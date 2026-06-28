use anyhow::{Context, Result};
use clap::Parser;
use dstore::chunk;
use dstore::cli::{Cli, Command};
use dstore::crypto::{decrypt_chunk, derive_encryption_key, encrypt_chunk, EncryptedChunk};
use dstore::erasure;
use dstore::ipc::{default_socket_path, IpcRequest, IpcResponse};
use dstore::net::dht::DhtNode;
use dstore::store::{ChunkStore, FileIndex, FileRecord};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Store {
            file,
            out,
            passphrase,
            addr,
            bootstrap,
            socket,
        } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            });

            if let Some(sock) = socket_path {
                let req = IpcRequest::Store {
                    file: file.to_string_lossy().to_string(),
                    passphrase,
                };
                let resp = dstore::ipc::send_request(&sock, &req).await?;
                match resp {
                    IpcResponse::StoreOk { root_hash } => println!("{}", root_hash),
                    IpcResponse::Error { message } => anyhow::bail!("{}", message),
                    _ => anyhow::bail!("Unexpected response from daemon"),
                }
            } else {
                let key = passphrase.as_deref().map(derive_encryption_key).transpose()?;
                store_file(&file, &out, key, addr, bootstrap).await?;
            }
        }
        Command::Get {
            root_hash,
            output,
            store,
            passphrase,
            addr,
            bootstrap,
            socket,
        } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            });

            if let Some(sock) = socket_path {
                let req = IpcRequest::Get {
                    root_hash,
                    output: output.to_string_lossy().to_string(),
                    passphrase,
                };
                let resp = dstore::ipc::send_request(&sock, &req).await?;
                match resp {
                    IpcResponse::GetOk => {
                        tracing::info!("File reassembled to {}", output.display());
                    }
                    IpcResponse::Error { message } => anyhow::bail!("{}", message),
                    _ => anyhow::bail!("Unexpected response from daemon"),
                }
            } else {
                let key = passphrase.as_deref().map(derive_encryption_key).transpose()?;
                get_file(&root_hash, &output, store.as_deref(), key, addr, bootstrap).await?;
            }
        }
        Command::StoreDir { dir, passphrase, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::StoreDir {
                dir: dir.to_string_lossy().to_string(),
                passphrase,
            };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::StoreDirOk { root_hash } => println!("{}", root_hash),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::GetDir { root_hash, output, passphrase, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::GetDir {
                root_hash,
                output: output.to_string_lossy().to_string(),
                passphrase,
            };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::GetDirOk => {
                    tracing::info!("Directory reconstructed to {}", output.display());
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Delete { root_hash, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::Delete { root_hash };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::DeleteOk => println!("Deleted"),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Gc { socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::Gc;
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::GcOk { removed_chunks } => println!("Removed {} orphaned chunks", removed_chunks),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Watch { dir, passphrase, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::Watch {
                dir: dir.to_string_lossy().to_string(),
                passphrase,
            };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::WatchOk => {
                    println!("Watching {} (daemon will auto-store new files)", dir.display());
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Verify { root_hash, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::Verify { root_hash };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::VerifyOk { total, ok, corrupted } => {
                    println!("Verified {} chunks: {} ok, {} corrupted", total, ok, corrupted);
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Repair { root_hash, passphrase, socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::Repair { root_hash, passphrase };
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::RepairOk { total, repaired, failed } => {
                    println!("Repair: {} chunks, {} repaired, {} failed", total, repaired, failed);
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::List { socket } => {
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            }).context("No daemon socket found (is the daemon running?)")?;
            let req = IpcRequest::ListFiles;
            let resp = dstore::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::ListFilesOk { files } => {
                    if files.is_empty() {
                        println!("No files stored");
                    } else {
                        println!("{:<70} {:>8}  Name", "Root Hash", "Size");
                        println!("{}", "-".repeat(100));
                        for f in &files {
                            let size_str = if f.size < 1024 {
                                format!("{} B", f.size)
                            } else if f.size < 1024 * 1024 {
                                format!("{:.1} KB", f.size as f64 / 1024.0)
                            } else {
                                format!("{:.1} MB", f.size as f64 / (1024.0 * 1024.0))
                            };
                            println!("{:<70} {:>8}  {}", f.root_hash, size_str, f.name);
                        }
                    }
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Serve {
            root_hash,
            bind,
            passphrase,
            addr,
            bootstrap,
            socket,
        } => {
            // If a daemon socket exists, just print the URL
            let socket_path = socket.or_else(|| {
                let def = default_socket_path();
                if def.exists() { Some(def) } else { None }
            });
            if let Some(sock) = socket_path {
                // Try to get daemon HTTP port from its status
                let req = IpcRequest::ListFiles;
                if dstore::ipc::send_request(&sock, &req).await.is_ok() {
                    println!("Daemon running. Download at:");
                    println!("  http://{}:8080/download/{}", if bind.contains("0.0.0.0") { "localhost" } else { &bind.split(':').next().unwrap_or("localhost") }, root_hash);
                    println!("Files list: http://{}:8080/", bind);
                    return Ok(());
                }
            }

            // Standalone HTTP file server
            let encryption_key = passphrase
                .as_deref()
                .map(derive_encryption_key)
                .transpose()?
                .map(Arc::new);

            let node = match addr {
                Some(listen) => {
                    let n = Arc::new(DhtNode::new(listen).await?);
                    if let Some(bootstrap_addr) = bootstrap {
                        n.bootstrap(bootstrap_addr).await?;
                    }
                    n.start_repair_task();
                    let run = n.clone();
                    tokio::spawn(async move { run.run().await.ok(); });
                    n
                }
                None => anyhow::bail!("--addr is required for standalone server (or connect to a running daemon)"),
            };

            let store_dir = PathBuf::from("./dstore_data");
            let http_state = Arc::new(dstore::http::HttpState {
                node,
                store_dir,
                encryption_key,
                start_time: std::time::Instant::now(),
            });
            tracing::info!("Serving file {} at http://{}", root_hash, bind);
            println!("Download: http://{}/download/{}", bind, root_hash);
            dstore::http::run_http_server(http_state, &bind).await;
        }
        Command::Daemon {
            addr,
            bootstrap,
            http_port,
            passphrase,
            socket,
        } => {
            let encryption_key = passphrase
                .as_deref()
                .map(derive_encryption_key)
                .transpose()?
                .map(Arc::new);

            let node = Arc::new(DhtNode::new(addr).await?);
            if let Some(bootstrap_addr) = bootstrap {
                node.bootstrap(bootstrap_addr).await?;
            }
            node.start_repair_task();

            // Spawn node.run() as background task
            let run_node = node.clone();
            tokio::spawn(async move {
                if let Err(e) = run_node.run().await {
                    tracing::error!("DHT node run loop exited: {}", e);
                }
            });

            let socket_path = socket.unwrap_or_else(default_socket_path);
            if socket_path.exists() {
                std::fs::remove_file(&socket_path).ok();
            }
            if let Some(parent) = socket_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let listener = UnixListener::bind(&socket_path)?;
            tracing::info!("IPC socket at {}", socket_path.display());

            let store_dir: PathBuf = socket_path.parent().unwrap().join("chunks");

            // Spawn HTTP dashboard
            let http_state = Arc::new(dstore::http::HttpState {
                node: node.clone(),
                store_dir: store_dir.clone(),
                encryption_key,
                start_time: std::time::Instant::now(),
            });
            let http_bind = http_port.clone();
            tokio::spawn(async move {
                dstore::http::run_http_server(http_state, &http_bind).await;
            });

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let node = node.clone();
                        let store = ChunkStore::new(store_dir.clone());
                        tokio::spawn(async move {
                            let (reader, mut writer) = stream.into_split();
                            let mut buf_reader = BufReader::new(reader);
                            let mut line = String::new();
                            if tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            let resp = match serde_json::from_str::<IpcRequest>(line.trim()) {
                                Ok(req) => handle_ipc_request(node, &store, req).await,
                                Err(e) => IpcResponse::Error { message: format!("invalid request: {}", e) },
                            };
                            if let Ok(resp_line) = serde_json::to_string(&resp) {
                                let _ = writer.write_all(resp_line.as_bytes()).await;
                                let _ = writer.write_all(b"\n").await;
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("IPC accept error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

fn hex_to_key(h: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(h)?;
    let mut id = [0u8; 32];
    if bytes.len() != 32 {
        anyhow::bail!("invalid 32-byte hex key");
    }
    id.copy_from_slice(&bytes);
    Ok(id)
}

async fn bootstrap_dht(
    addr: Option<SocketAddr>,
    bootstrap: Option<SocketAddr>,
) -> Result<Option<DhtNode>> {
    match addr {
        Some(listen) => {
            let node = DhtNode::new(listen).await?;
            if let Some(bootstrap_addr) = bootstrap {
                node.bootstrap(bootstrap_addr).await?;
            }
            Ok(Some(node))
        }
        None => Ok(None),
    }
}

fn encrypt_if_keyed(
    key: Option<&Zeroizing<[u8; 32]>>,
    plaintext: &[u8],
) -> (Vec<u8>, Option<[u8; 12]>) {
    match key {
        Some(k) => {
            let enc = encrypt_chunk(k, plaintext);
            let nonce = enc.nonce;
            let mut data = Vec::with_capacity(12 + enc.ciphertext.len());
            data.extend_from_slice(&nonce);
            data.extend_from_slice(&enc.ciphertext);
            (data, Some(nonce))
        }
        None => (plaintext.to_vec(), None),
    }
}

fn decrypt_if_keyed(
    key: Option<&Zeroizing<[u8; 32]>>,
    data: &[u8],
    nonce_opt: Option<[u8; 12]>,
) -> Result<Vec<u8>> {
    match (key, nonce_opt) {
        (Some(k), Some(nonce)) => {
            if data.len() < 12 {
                anyhow::bail!("truncated encrypted chunk");
            }
            let ciphertext = &data[12..];
            let enc = EncryptedChunk {
                nonce,
                ciphertext: ciphertext.to_vec(),
            };
            decrypt_chunk(k, &enc).context("decryption failed — wrong passphrase or corrupted data")
        }
        _ => Ok(data.to_vec()),
    }
}

fn compute_chunk_hash(data: &[u8], key: Option<&Zeroizing<[u8; 32]>>) -> String {
    match key {
        Some(_) => hex::encode(Sha256::digest(&data[12..])),
        None => hex::encode(Sha256::digest(data)),
    }
}

// --- IPC handlers ---

async fn handle_ipc_request(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    req: IpcRequest,
) -> IpcResponse {
    match req {
        IpcRequest::Store { file, passphrase } => {
            match handle_daemon_store(&node, chunk_store, &file, passphrase).await {
                Ok(root_hash) => IpcResponse::StoreOk { root_hash },
                Err(e) => IpcResponse::Error { message: format!("store failed: {}", e) },
            }
        }
        IpcRequest::Get { root_hash, output, passphrase } => {
            match handle_daemon_get(node, chunk_store, &root_hash, &output, passphrase).await {
                Ok(_) => IpcResponse::GetOk,
                Err(e) => IpcResponse::Error { message: format!("get failed: {}", e) },
            }
        }
        IpcRequest::StoreDir { dir, passphrase } => {
            match handle_daemon_store_dir(&node, chunk_store, &dir, passphrase).await {
                Ok(root_hash) => IpcResponse::StoreDirOk { root_hash },
                Err(e) => IpcResponse::Error { message: format!("store-dir failed: {}", e) },
            }
        }
        IpcRequest::GetDir { root_hash, output, passphrase } => {
            match handle_daemon_get_dir(node.clone(), chunk_store, &root_hash, &output, passphrase).await {
                Ok(_) => IpcResponse::GetDirOk,
                Err(e) => IpcResponse::Error { message: format!("get-dir failed: {}", e) },
            }
        }
        IpcRequest::Delete { root_hash } => {
            match handle_daemon_delete(node, chunk_store, &root_hash).await {
                Ok(_) => IpcResponse::DeleteOk,
                Err(e) => IpcResponse::Error { message: format!("delete failed: {}", e) },
            }
        }
        IpcRequest::Gc => {
            match handle_daemon_gc(&node, chunk_store).await {
                Ok(removed) => IpcResponse::GcOk { removed_chunks: removed },
                Err(e) => IpcResponse::Error { message: format!("gc failed: {}", e) },
            }
        }
        IpcRequest::ListFiles => {
            let mut index = FileIndex::load(chunk_store.dir());
            index.files.sort_by_key(|b| std::cmp::Reverse(b.stored_at));
            IpcResponse::ListFilesOk {
                files: index.files,
            }
        }
        IpcRequest::Watch { dir, passphrase } => {
            let store_dir = chunk_store.dir().clone();
            let w_node = node.clone();
            let chunk_dir = store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = run_watcher(w_node, &dir, &chunk_dir, passphrase).await {
                    tracing::error!("Watcher for {} failed: {}", dir, e);
                }
            });
            IpcResponse::WatchOk
        }
        IpcRequest::Verify { root_hash } => {
            match handle_daemon_verify(node, chunk_store, &root_hash).await {
                Ok((total, ok, corrupted)) => IpcResponse::VerifyOk { total, ok, corrupted },
                Err(e) => IpcResponse::Error { message: format!("verify failed: {}", e) },
            }
        }
        IpcRequest::Repair { root_hash, passphrase } => {
            match handle_daemon_repair(node, chunk_store, &root_hash, passphrase).await {
                Ok((total, repaired, failed)) => IpcResponse::RepairOk { total, repaired, failed },
                Err(e) => IpcResponse::Error { message: format!("repair failed: {}", e) },
            }
        }
        IpcRequest::Status => {
            let peer_count = node.routing.lock().await.all_nodes().len();
            IpcResponse::StatusOk {
                node_id: hex::encode(node.id),
                peer_count,
            }
        }
    }
}

async fn handle_daemon_store(
    node: &DhtNode,
    chunk_store: &ChunkStore,
    file_path: &str,
    passphrase: Option<String>,
) -> Result<String> {
    let key = passphrase.as_deref().map(derive_encryption_key).transpose()?;
    let path = Path::new(file_path);

    tracing::info!("Daemon storing file: {}", path.display());
    let (plaintext_chunks, mut manifest) = chunk::chunk_file(path)?;
    let total_data = plaintext_chunks.len();

    let (data_shards, parity_shards) = erasure::choose_config(total_data);
    manifest.data_shards = data_shards;
    manifest.parity_shards = parity_shards;

    let mut all_chunks: Vec<(chunk::ChunkInfo, Vec<u8>)> = Vec::new();

    if parity_shards > 0 {
        let stripes = plaintext_chunks.chunks(data_shards);
        for (stripe_idx, stripe_data) in stripes.enumerate() {
            let mut stripe_input = stripe_data.to_vec();
            while stripe_input.len() < data_shards {
                stripe_input.push(vec![0u8; 0]);
            }
            let encoded = erasure::encode_stripe(&stripe_input, parity_shards)
                .context("erasure encoding failed")?;
            for (shard_idx, plaintext) in encoded.iter().enumerate() {
                let is_parity = shard_idx >= data_shards;
                let (on_disk_data, nonce) = encrypt_if_keyed(key.as_ref(), plaintext);
                let hash = compute_chunk_hash(&on_disk_data, key.as_ref());
                let (chunk_index, orig_size) = if is_parity {
                    ((shard_idx - data_shards) as u32, 0u32)
                } else {
                    let file_idx = stripe_idx * data_shards + shard_idx;
                    let s = if file_idx < total_data { manifest.chunks[file_idx].size } else { 0 };
                    (shard_idx as u32, s)
                };
                let info = chunk::ChunkInfo {
                    hash: hash.clone(),
                    index: chunk_index,
                    size: orig_size,
                    nonce,
                    is_parity,
                    stripe_index: stripe_idx as u32,
                };
                chunk_store.store_chunk(&hash, &on_disk_data)?;
                all_chunks.push((info, on_disk_data));
            }
        }
        manifest.chunks = all_chunks.iter().map(|(info, _)| info.clone()).collect();
        manifest.total_chunks = all_chunks.len() as u32;
    } else {
        for (i, pt_chunk) in plaintext_chunks.iter().enumerate() {
            let (on_disk_data, nonce) = encrypt_if_keyed(key.as_ref(), pt_chunk);
            let hash = compute_chunk_hash(&on_disk_data, key.as_ref());
            chunk_store.store_chunk(&hash, &on_disk_data)?;
            manifest.chunks[i].hash = hash;
            manifest.chunks[i].nonce = nonce;
        }
    }

    let manifest_bytes = serde_json::to_string(&manifest)?;
    let root_hash = hex::encode(Sha256::digest(manifest_bytes.as_bytes()));
    chunk_store.store_root_hash(&root_hash)?;
    chunk_store.store_manifest(&manifest)?;

    tracing::info!("Daemon distributing {} chunks to DHT...", manifest.chunks.len());
    for info in &manifest.chunks {
        if let Some(data) = chunk_store.load_chunk(&info.hash)? {
            let key_bytes = hex_to_key(&info.hash)?;
            if let Err(e) = node.store_value(key_bytes, data).await {
                tracing::warn!("Failed to distribute chunk {}: {}", info.hash, e);
            }
        }
    }
    let manifest_key = hex_to_key(&root_hash)?;
    node.store_value(manifest_key, manifest_bytes.as_bytes().to_vec()).await?;

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let record = FileRecord {
        name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        root_hash: root_hash.clone(),
        size: file_size,
        stored_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
        chunk_count: manifest.chunks.len() as u32,
    };
    let mut index = FileIndex::load(chunk_store.dir());
    // Replace existing entry with same root_hash, or append
    if let Some(pos) = index.files.iter().position(|f| f.root_hash == record.root_hash) {
        index.files[pos] = record.clone();
    } else {
        index.files.push(record);
    }
    if let Err(e) = index.save(chunk_store.dir()) {
        tracing::warn!("Failed to save file index: {}", e);
    }

    tracing::info!("Daemon stored file: {}", root_hash);
    Ok(root_hash)
}

async fn handle_daemon_store_dir(
    node: &DhtNode,
    chunk_store: &ChunkStore,
    dir_path: &str,
    passphrase: Option<String>,
) -> Result<String> {
    let dir = Path::new(dir_path);
    if !dir.is_dir() {
        anyhow::bail!("not a directory: {}", dir_path);
    }
    let dir_name = dir.file_name().unwrap_or_default().to_string_lossy().to_string();

    let relative_files = chunk::walk_directory(dir)?;
    tracing::info!("Storing directory '{}' with {} files", dir_name, relative_files.len());

    let mut entries = Vec::new();
    for rel_path in &relative_files {
        let full_path = dir.join(rel_path);
        let root_hash = handle_daemon_store(node, chunk_store, &full_path.to_string_lossy(), passphrase.clone()).await?;
        let size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
        entries.push(chunk::DirEntry {
            path: rel_path.clone(),
            root_hash,
            size,
        });
    }

    let dir_manifest = chunk::DirManifest { dir_name, entries };
    let dir_bytes = serde_json::to_string(&dir_manifest)?;
    let root_hash = hex::encode(Sha256::digest(dir_bytes.as_bytes()));

    let manifest_key = hex_to_key(&root_hash)?;
    node.store_value(manifest_key, dir_bytes.as_bytes().to_vec()).await?;

    let record = FileRecord {
        name: format!("{}/", Path::new(dir_path).file_name().unwrap_or_default().to_string_lossy()),
        root_hash: root_hash.clone(),
        size: 0,
        stored_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
        chunk_count: 0,
    };
    let mut index = FileIndex::load(chunk_store.dir());
    if let Some(pos) = index.files.iter().position(|f| f.root_hash == record.root_hash) {
        index.files[pos] = record.clone();
    } else {
        index.files.push(record);
    }
    if let Err(e) = index.save(chunk_store.dir()) {
        tracing::warn!("Failed to save file index: {}", e);
    }

    tracing::info!("Daemon stored directory: {}", root_hash);
    Ok(root_hash)
}

async fn handle_daemon_get_dir(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
    output_path: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let manifest_key = hex_to_key(root_hash)?;
    let dir_bytes = node.find_value(&manifest_key).await?
        .context("directory manifest not found on DHT")?;
    let dir_manifest: chunk::DirManifest = serde_json::from_slice(&dir_bytes)?;

    let output_dir = Path::new(output_path);
    std::fs::create_dir_all(output_dir)?;

    for entry in &dir_manifest.entries {
        let file_output = output_dir.join(&entry.path);
        if let Some(parent) = file_output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        handle_daemon_get(
            node.clone(),
            chunk_store,
            &entry.root_hash,
            &file_output.to_string_lossy(),
            passphrase.clone(),
        ).await?;
    }

    tracing::info!("Reconstructed directory with {} files to {}", dir_manifest.entries.len(), output_path);
    Ok(())
}

async fn handle_daemon_delete(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
) -> Result<()> {
    let mut index = FileIndex::load(chunk_store.dir());
    let pos = index.files.iter().position(|f| f.root_hash == root_hash)
        .context("file not found in index")?;

    let hash_key = hex_to_key(root_hash)?;
    if let Ok(Some(manifest_bytes)) = node.find_value(&hash_key).await {
        if let Ok(manifest) = serde_json::from_slice::<chunk::Manifest>(&manifest_bytes) {
            for info in &manifest.chunks {
                let chunk_path = chunk_store.dir().join("chunks").join(format!("{}.chunk", info.hash));
                if chunk_path.exists() {
                    std::fs::remove_file(&chunk_path)?;
                    tracing::debug!("Deleted chunk: {}", info.hash);
                }
            }
        }
    }

    index.files.remove(pos);
    index.save(chunk_store.dir())?;
    tracing::info!("Deleted file: {}", root_hash);
    Ok(())
}

async fn handle_daemon_gc(node: &DhtNode, chunk_store: &ChunkStore) -> Result<usize> {
    let index = FileIndex::load(chunk_store.dir());

    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &index.files {
        if entry.name.ends_with('/') {
            continue; // dir manifests don't directly reference chunks
        }
        let hash_key = match hex_to_key(&entry.root_hash) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(Some(manifest_bytes)) = node.find_value(&hash_key).await {
            if let Ok(manifest) = serde_json::from_slice::<chunk::Manifest>(&manifest_bytes) {
                for info in &manifest.chunks {
                    referenced.insert(info.hash.clone());
                }
            }
        }
    }

    let chunks_dir = chunk_store.dir().join("chunks");
    if !chunks_dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    for entry in std::fs::read_dir(&chunks_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "chunk") {
            let hash = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            if !referenced.contains(&hash) {
                std::fs::remove_file(&path)?;
                removed += 1;
            }
        }
    }

    tracing::info!("GC removed {} orphaned chunks", removed);
    Ok(removed)
}

async fn handle_daemon_verify(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
) -> Result<(usize, usize, usize)> {
    let manifest_key = hex_to_key(root_hash)?;
    let manifest_bytes = node.find_value(&manifest_key).await?
        .context("manifest not found on DHT")?;
    let manifest: chunk::Manifest = serde_json::from_slice(&manifest_bytes)?;

    let total = manifest.chunks.len();
    let mut ok = 0usize;
    let mut corrupted = 0usize;

    for info in &manifest.chunks {
        match chunk_store.load_chunk(&info.hash) {
            Ok(Some(data)) => {
                let actual_hash = compute_chunk_hash(&data, None);
                if actual_hash == info.hash {
                    ok += 1;
                } else {
                    corrupted += 1;
                }
            }
            _ => {
                corrupted += 1;
            }
        }
    }

    tracing::info!("Verify {}: {}/{} ok, {} corrupted", root_hash, ok, total, corrupted);
    Ok((total, ok, corrupted))
}

async fn handle_daemon_repair(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
    passphrase: Option<String>,
) -> Result<(usize, usize, usize)> {
    let key = passphrase.as_deref().map(derive_encryption_key).transpose()?;

    let manifest_key = hex_to_key(root_hash)?;
    let manifest_bytes = node.find_value(&manifest_key).await?
        .context("manifest not found on DHT")?;
    let manifest: chunk::Manifest = serde_json::from_slice(&manifest_bytes)?;

    if manifest.parity_shards == 0 {
        anyhow::bail!("file has no EC parity, cannot repair");
    }

    let data_shards = manifest.data_shards;
    let parity_shards = manifest.parity_shards;
    let total_shards = data_shards + parity_shards;

    let mut stripe_map: HashMap<u32, Vec<&chunk::ChunkInfo>> = HashMap::new();
    for info in &manifest.chunks {
        stripe_map.entry(info.stripe_index).or_default().push(info);
    }
    let total_stripes = stripe_map.len();

    let mut total = 0usize;
    let mut repaired = 0usize;
    let mut failed = 0usize;

    for stripe_idx in 0..total_stripes as u32 {
        let infos = stripe_map.remove(&stripe_idx).unwrap_or_default();

        let mut available: Vec<Option<Vec<u8>>> = (0..total_shards).map(|_| None).collect();
        let mut is_corrupted = vec![false; total_shards];

        for info in &infos {
            let pos = if info.is_parity {
                data_shards + info.index as usize
            } else {
                info.index as usize
            };
            if pos >= total_shards {
                continue;
            }
            match chunk_store.load_chunk(&info.hash) {
                Ok(Some(data)) => {
                    let actual_hash = compute_chunk_hash(&data, None);
                    if actual_hash == info.hash {
                        if let Ok(plaintext) = decrypt_if_keyed(key.as_ref(), &data, info.nonce) {
                            available[pos] = Some(plaintext);
                        } else {
                            is_corrupted[pos] = true;
                        }
                    } else {
                        is_corrupted[pos] = true;
                    }
                }
                _ => {
                    is_corrupted[pos] = true;
                }
            }
        }

        let stripe_corrupted: usize = is_corrupted.iter().filter(|c| **c).count();
        if stripe_corrupted == 0 {
            continue;
        }

        total += stripe_corrupted;
        let present = available.iter().filter(|s| s.is_some()).count();
        if present < data_shards {
            tracing::warn!("Stripe {}: only {}/{} good shards, need {}", stripe_idx, present, present, data_shards);
            failed += stripe_corrupted;
            continue;
        }

        let mut original_sizes = vec![0usize; data_shards];
        for info in &infos {
            if !info.is_parity && (info.index as usize) < data_shards {
                original_sizes[info.index as usize] = info.size as usize;
            }
        }

        let reconstructed = match erasure::decode_stripe(&available, data_shards, parity_shards, &original_sizes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Stripe {}: RS decode failed: {}", stripe_idx, e);
                failed += stripe_corrupted;
                continue;
            }
        };

        for (pos, is_bad) in is_corrupted.iter().enumerate() {
            if !is_bad {
                continue;
            }
            let plaintext = &reconstructed[pos];
            let info = infos.iter().find(|i| {
                let ip = if i.is_parity { data_shards + i.index as usize } else { i.index as usize };
                ip == pos
            });

            let Some(info) = info else {
                failed += 1;
                continue;
            };

            let (encrypted, _) = encrypt_if_keyed(key.as_ref(), plaintext);
            let new_hash = compute_chunk_hash(&encrypted, key.as_ref());

            if new_hash != info.hash {
                tracing::warn!(
                    "Repaired chunk {} hash mismatch (expected {}, got {})",
                    info.hash, info.hash, new_hash
                );
                failed += 1;
                continue;
            }

            chunk_store.store_chunk(&info.hash, &encrypted)?;
            tracing::info!("Repaired chunk: {}", info.hash);
            repaired += 1;
        }
    }

    tracing::info!("Repair {}: {}/{} repaired, {} failed", root_hash, repaired, total, failed);
    Ok((total, repaired, failed))
}

async fn run_watcher(
    node: Arc<DhtNode>,
    dir_path: &str,
    chunk_dir: &Path,
    passphrase: Option<String>,
) -> Result<()> {
    use inotify::{Inotify, WatchMask};
    use std::time::Duration;

    let dir = Path::new(dir_path);
    if !dir.is_dir() {
        anyhow::bail!("not a directory: {}", dir_path);
    }

    let mut inotify = Inotify::init()?;
    inotify.watches().add(dir, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)?;
    tracing::info!("Watcher started for: {}", dir_path);

    let mut buffer = [0u8; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .map_err(|e| anyhow::anyhow!("inotify read error: {}", e))?;

        for event in events {
            let Some(name) = event.name else { continue };
            let full_path = dir.join(name);
            if !full_path.is_file() {
                continue;
            }
            // Skip hidden files and temp files
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str.ends_with('~') || name_str.ends_with(".tmp") {
                continue;
            }
            // Brief delay to let the write finish
            tokio::time::sleep(Duration::from_millis(500)).await;
            let store = ChunkStore::new(chunk_dir.to_path_buf());
            match handle_daemon_store(&node, &store, &full_path.to_string_lossy(), passphrase.clone()).await {
                Ok(root_hash) => {
                    tracing::info!("Auto-stored {} -> {}", full_path.display(), root_hash);
                }
                Err(e) => {
                    tracing::warn!("Failed to auto-store {}: {}", full_path.display(), e);
                }
            }
        }
    }
}

async fn handle_daemon_get(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
    output_path: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let key = passphrase.as_deref().map(derive_encryption_key).transpose()?;

    let manifest = if let Ok(local_root) = chunk_store.root_hash() {
        if local_root.as_deref() == Some(root_hash) {
            if let Ok(m) = chunk_store.load_manifest() {
                m
            } else {
                fetch_manifest_from_dht(&node, root_hash).await?
            }
        } else {
            fetch_manifest_from_dht(&node, root_hash).await?
        }
    } else {
        fetch_manifest_from_dht(&node, root_hash).await?
    };

    verify_manifest_integrity(&manifest, root_hash)?;

    fetch_chunks_parallel(&node, chunk_store, &manifest, key.as_ref()).await?;

    reassemble_from_store(chunk_store, &manifest, Path::new(output_path), key.as_ref()).await
}

async fn fetch_chunks_parallel(
    node: &Arc<DhtNode>,
    store: &ChunkStore,
    manifest: &chunk::Manifest,
    key: Option<&Zeroizing<[u8; 32]>>,
) -> Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let mut handles = Vec::new();

    for info in &manifest.chunks {
        if store.has_chunk(&info.hash) {
            continue;
        }
        let chunk_key = hex_to_key(&info.hash)?;
        let hash = info.hash.clone();
        let sem = sem.clone();
        let node = node.clone();
        let key = key.cloned();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await?;
            match node.find_value(&chunk_key).await {
                Ok(Some(data)) => {
                    let actual_hash = compute_chunk_hash(&data, key.as_ref());
                    if actual_hash != hash {
                        anyhow::bail!("Integrity check failed for chunk {}: hash mismatch", hash);
                    }
                    Ok::<_, anyhow::Error>(Some((hash, data)))
                }
                Ok(None) => {
                    tracing::warn!("Chunk {} not found on DHT (will try RS recovery)", hash);
                    Ok(None)
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch chunk {}: {} (will try RS recovery)", hash, e);
                    Ok(None)
                }
            }
        }));
    }

    for handle in handles {
        if let Some((hash, data)) = handle.await?? {
            store.store_chunk(&hash, &data)?;
        }
    }

    Ok(())
}

async fn fetch_manifest_from_dht(node: &DhtNode, root_hash: &str) -> Result<chunk::Manifest> {
    let manifest_key = hex_to_key(root_hash)?;
    tracing::info!("Fetching manifest from DHT...");
    let manifest_bytes = node
        .find_value(&manifest_key)
        .await?
        .context("manifest not found on DHT")?;
    Ok(serde_json::from_slice(&manifest_bytes)?)
}

// --- Standalone store/get (used without daemon) ---

async fn store_file(
    file: &Path,
    out: &Path,
    key: Option<Zeroizing<[u8; 32]>>,
    dht_addr: Option<SocketAddr>,
    dht_bootstrap: Option<SocketAddr>,
) -> Result<()> {
    tracing::info!("Reading file: {}", file.display());
    let (plaintext_chunks, mut manifest) = chunk::chunk_file(file)?;
    let total_data = plaintext_chunks.len();
    tracing::info!("Split into {} chunks ({} KB each)", total_data, chunk::CHUNK_SIZE / 1024);

    let (data_shards, parity_shards) = erasure::choose_config(total_data);
    manifest.data_shards = data_shards;
    manifest.parity_shards = parity_shards;

    let store = ChunkStore::new(out.to_path_buf());
    let mut all_chunks: Vec<(chunk::ChunkInfo, Vec<u8>)> = Vec::new();

    if parity_shards > 0 {
        let stripes = plaintext_chunks.chunks(data_shards);
        for (stripe_idx, stripe_data) in stripes.enumerate() {
            let mut stripe_input = stripe_data.to_vec();
            while stripe_input.len() < data_shards {
                stripe_input.push(vec![0u8; 0]);
            }
            let encoded = erasure::encode_stripe(&stripe_input, parity_shards)
                .context("erasure encoding failed")?;
            for (shard_idx, plaintext) in encoded.iter().enumerate() {
                let is_parity = shard_idx >= data_shards;
                let (on_disk_data, nonce) = encrypt_if_keyed(key.as_ref(), plaintext);
                let hash = compute_chunk_hash(&on_disk_data, key.as_ref());
                let (chunk_index, orig_size) = if is_parity {
                    ((shard_idx - data_shards) as u32, 0u32)
                } else {
                    let file_idx = stripe_idx * data_shards + shard_idx;
                    let s = if file_idx < total_data { manifest.chunks[file_idx].size } else { 0 };
                    (shard_idx as u32, s)
                };
                let info = chunk::ChunkInfo {
                    hash: hash.clone(),
                    index: chunk_index,
                    size: orig_size,
                    nonce,
                    is_parity,
                    stripe_index: stripe_idx as u32,
                };
                store.store_chunk(&hash, &on_disk_data)?;
                all_chunks.push((info, on_disk_data));
            }
        }
        manifest.chunks = all_chunks.iter().map(|(info, _)| info.clone()).collect();
        manifest.total_chunks = all_chunks.len() as u32;
        tracing::info!(
            "EC: {} data + {} parity shards per stripe ({} stripes, {} total shards)",
            data_shards, parity_shards, total_data.div_ceil(data_shards),
            manifest.total_chunks
        );
    } else {
        for (i, pt_chunk) in plaintext_chunks.iter().enumerate() {
            let (on_disk_data, nonce) = encrypt_if_keyed(key.as_ref(), pt_chunk);
            let hash = compute_chunk_hash(&on_disk_data, key.as_ref());
            store.store_chunk(&hash, &on_disk_data)?;
            manifest.chunks[i].hash = hash;
            manifest.chunks[i].nonce = nonce;
        }
    }

    tracing::info!("Stored {} chunks to {}", manifest.total_chunks, out.display());
    store.store_manifest(&manifest)?;
    let manifest_bytes = serde_json::to_string(&manifest)?;
    let root_hash = hex::encode(Sha256::digest(manifest_bytes.as_bytes()));
    store.store_root_hash(&root_hash)?;
    tracing::info!("Root hash: {}", root_hash);

    if let Some(node) = bootstrap_dht(dht_addr, dht_bootstrap).await? {
        tracing::info!("Publishing {} chunks to DHT...", manifest.chunks.len());
        for info in &manifest.chunks {
            if let Some(data) = store.load_chunk(&info.hash)? {
                let key_bytes = hex_to_key(&info.hash)?;
                node.store_value(key_bytes, data).await?;
            }
        }
        let manifest_key = hex_to_key(&root_hash)?;
        node.store_value(manifest_key, manifest_bytes.as_bytes().to_vec())
            .await?;
        tracing::info!("Published to DHT successfully");
    }

    println!("{}", root_hash);
    Ok(())
}

async fn get_file(
    root_hash: &str,
    output: &Path,
    store_path: Option<&Path>,
    key: Option<Zeroizing<[u8; 32]>>,
    dht_addr: Option<SocketAddr>,
    dht_bootstrap: Option<SocketAddr>,
) -> Result<()> {
    let manifest: chunk::Manifest;

    if let Some(local_dir) = store_path {
        let store = ChunkStore::new(local_dir.to_path_buf());
        if let Ok(local_root) = store.root_hash() {
            if local_root.as_deref() == Some(root_hash) {
                if let Ok(local_manifest) = store.load_manifest() {
                    verify_manifest_integrity(&local_manifest, root_hash)?;
                    manifest = local_manifest;
                    tracing::info!("Found manifest locally");
                    return reassemble_from_store(&store, &manifest, output, key.as_ref()).await;
                }
            }
        }
        tracing::info!("File not found locally, trying DHT...");
    }

    let node = match dht_addr {
        Some(addr) => bootstrap_dht(Some(addr), dht_bootstrap).await?.unwrap(),
        None => anyhow::bail!(
            "File not found locally and no DHT address provided.\n\
             Use --addr to specify a DHT listen address and --bootstrap to join the network."
        ),
    };

    let manifest_key = hex_to_key(root_hash)?;
    tracing::info!("Fetching manifest from DHT...");
    let manifest_bytes = node
        .find_value(&manifest_key)
        .await?
        .context("manifest not found on DHT")?;
    manifest = serde_json::from_slice(&manifest_bytes)?;
    verify_manifest_integrity(&manifest, root_hash)?;

    tracing::info!(
        "Fetching {} chunks for {} from DHT...",
        manifest.total_chunks,
        manifest.file_name
    );

    let tmp_dir = std::env::temp_dir().join(format!("dstore_{}", root_hash));
    std::fs::create_dir_all(&tmp_dir)?;
    let tmp_store = ChunkStore::new(tmp_dir.clone());

    let node = Arc::new(node);
    fetch_chunks_parallel(&node, &tmp_store, &manifest, key.as_ref()).await?;

    let result = reassemble_from_store(&tmp_store, &manifest, output, key.as_ref()).await;
    std::fs::remove_dir_all(&tmp_dir).ok();
    result
}

fn verify_manifest_integrity(manifest: &chunk::Manifest, expected_root_hash: &str) -> Result<()> {
    let manifest_bytes = serde_json::to_string(manifest)?;
    let computed = hex::encode(Sha256::digest(manifest_bytes.as_bytes()));
    if computed != expected_root_hash {
        anyhow::bail!(
            "Manifest hash mismatch: expected {}, got {}",
            expected_root_hash,
            computed
        );
    }
    Ok(())
}

async fn reassemble_from_store(
    store: &ChunkStore,
    manifest: &chunk::Manifest,
    output: &Path,
    key: Option<&Zeroizing<[u8; 32]>>,
) -> Result<()> {
    if manifest.parity_shards == 0 {
        return simple_reassemble(store, manifest, output, key).await;
    }
    ec_reassemble(store, manifest, output, key).await
}

async fn simple_reassemble(
    store: &ChunkStore,
    manifest: &chunk::Manifest,
    output: &Path,
    key: Option<&Zeroizing<[u8; 32]>>,
) -> Result<()> {
    let mut out_file = std::fs::File::create(output)?;
    for info in &manifest.chunks {
        let data = store
            .load_chunk(&info.hash)?
            .with_context(|| format!("Missing chunk: {}", info.hash))?;
        let plaintext = decrypt_if_keyed(key, &data, info.nonce)?;
        use std::io::Write;
        out_file.write_all(&plaintext)?;
    }
    tracing::info!("Reassembled to {}", output.display());
    Ok(())
}

async fn ec_reassemble(
    store: &ChunkStore,
    manifest: &chunk::Manifest,
    output: &Path,
    key: Option<&Zeroizing<[u8; 32]>>,
) -> Result<()> {
    let data_shards = manifest.data_shards;
    let parity_shards = manifest.parity_shards;
    let total_shards = data_shards + parity_shards;

    let mut stripe_map: HashMap<u32, Vec<&chunk::ChunkInfo>> = HashMap::new();
    for info in &manifest.chunks {
        stripe_map.entry(info.stripe_index).or_default().push(info);
    }
    let total_stripes = stripe_map.len();

    let mut out_file = std::fs::File::create(output)?;

    for stripe_idx in 0..total_stripes as u32 {
        let infos = stripe_map.remove(&stripe_idx).unwrap_or_default();

        let mut available: Vec<Option<Vec<u8>>> = (0..total_shards).map(|_| None).collect();
        let mut original_sizes = vec![0usize; data_shards];

        // First pass: record original sizes for ALL data shards from the manifest
        for info in &infos {
            if !info.is_parity && (info.index as usize) < data_shards {
                original_sizes[info.index as usize] = info.size as usize;
            }
        }

        // Second pass: load available chunk data
        for info in &infos {
            let pos = if info.is_parity {
                data_shards + info.index as usize
            } else {
                info.index as usize
            };
            if pos >= total_shards {
                continue;
            }
            if let Some(data) = store.load_chunk(&info.hash)? {
                let plaintext = decrypt_if_keyed(key, &data, info.nonce)?;
                available[pos] = Some(plaintext);
            }
        }

        let present = available.iter().filter(|s| s.is_some()).count();
        if present < data_shards && present < total_shards {
            anyhow::bail!(
                "Stripe {}: only {}/{} shards available, need at least {}",
                stripe_idx, present, total_shards, data_shards
            );
        }

        let reconstructed = erasure::decode_stripe(&available, data_shards, parity_shards, &original_sizes)
            .with_context(|| format!("RS reconstruction failed for stripe {}", stripe_idx))?;

        use std::io::Write;
        for chunk_data in &reconstructed {
            if !chunk_data.is_empty() {
                out_file.write_all(chunk_data)?;
            }
        }
    }

    tracing::info!("Reassembled (EC) to {}", output.display());
    Ok(())
}
