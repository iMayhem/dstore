use anyhow::{Context, Result};
use clap::Parser;
use dstor::chunk;
use dstor::cli::{Cli, Command};
use dstor::crypto::{
    decrypt_chunk, derive_encryption_key, encrypt_chunk, keyed_content_address,
    resolve_passphrase, Argon2Config, EncryptedChunk,
};
use dstor::erasure;
use dstor::ipc::{default_socket_path, IpcRequest, IpcResponse};
use dstor::net::dht::DhtNode;
use dstor::store::{ChunkStore, FileIndex, FileRecord};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

/// Resolve socket path: use explicit path, or fall back to default if it exists.
fn try_resolve_socket(socket: Option<PathBuf>) -> Option<PathBuf> {
    match socket {
        Some(s) => Some(s),
        None => {
            let def = default_socket_path();
            if def.exists() { Some(def) } else { None }
        }
    }
}

/// Resolve socket path: use explicit path, or always fall back to default.
fn resolve_socket(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(default_socket_path)
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init { dir } => {
            let data_dir = dir.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".dstore")
            });
            std::fs::create_dir_all(&data_dir)?;
            let key_path = data_dir.join("node_key");
            if !key_path.exists() {
                let sk = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
                let pk = sk.verifying_key();
                std::fs::write(&key_path, hex::encode(sk.to_bytes()))?;
                println!("Generated node key → {}", key_path.display());
                println!("Public key: {}", hex::encode(pk.to_bytes()));
            } else {
                println!("Node key already exists at {}", key_path.display());
            }
            let socket_path = default_socket_path();
            println!("Data directory: {}", data_dir.display());
            println!("IPC socket:     {}", socket_path.display());
            println!();
            println!("Ready! Start the daemon:");
            println!("  dstore daemon");
            println!();
            println!("Then store files:");
            println!("  dstore put myfile.txt");
            println!("  dstore ls");
        }
        Command::Status { socket } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Status;
            match dstor::ipc::send_request(&socket_path, &req).await {
                Ok(IpcResponse::StatusOk { peer_count, file_count, chunk_count, uptime_secs, node_id, external_addr }) => {
                    let hours = uptime_secs / 3600;
                    let mins = (uptime_secs % 3600) / 60;
                    let secs = uptime_secs % 60;
                    println!("Node ID: {}", hex::encode(node_id));
                    if let Some(addr) = external_addr {
                        println!("Address: {}", addr);
                    }
                    println!("Peers:   {}", peer_count);
                    println!("Files:   {}", file_count);
                    println!("Chunks:  {}", chunk_count);
                    println!("Uptime:  {}h {}m {}s", hours, mins, secs);
                }
                Ok(IpcResponse::Error { message }) => anyhow::bail!("{}", message),
                Ok(_) => anyhow::bail!("Unexpected response"),
                Err(e) => anyhow::bail!("Cannot connect to daemon at {}: {}", socket_path.display(), e),
            }
        }
        Command::Store {
            file,
            out,
            passphrase,
            addr,
            bootstrap,
            socket,
            argon2_mem_kib,
            argon2_iters,
            argon2_lanes,
        } => {
            let argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = try_resolve_socket(socket);

            if let Some(sock) = socket_path {
                let req = IpcRequest::Store {
                    file: file.to_string_lossy().to_string(),
                    passphrase,
                };
                let resp = dstor::ipc::send_request(&sock, &req).await?;
                match resp {
                    IpcResponse::StoreOk { root_hash } => println!("{}", root_hash),
                    IpcResponse::Error { message } => anyhow::bail!("{}", message),
                    _ => anyhow::bail!("Unexpected response from daemon"),
                }
            } else {
                let passphrase = resolve_passphrase(passphrase)?;
                let key = passphrase
                    .as_ref()
                    .map(|p| derive_encryption_key(p, &argon2_config))
                    .transpose()?;
                store_file(&file, &out, key, addr, bootstrap, &argon2_config).await?;
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
            argon2_mem_kib,
            argon2_iters,
            argon2_lanes,
        } => {
            let argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = try_resolve_socket(socket);

            if let Some(sock) = socket_path {
                let req = IpcRequest::Get {
                    root_hash,
                    output: output.to_string_lossy().to_string(),
                    passphrase,
                };
                let resp = dstor::ipc::send_request(&sock, &req).await?;
                match resp {
                    IpcResponse::GetOk => {
                        tracing::info!("File reassembled to {}", output.display());
                    }
                    IpcResponse::Error { message } => anyhow::bail!("{}", message),
                    _ => anyhow::bail!("Unexpected response from daemon"),
                }
            } else {
                let passphrase = resolve_passphrase(passphrase)?;
                let key = passphrase
                    .as_ref()
                    .map(|p| derive_encryption_key(p, &argon2_config))
                    .transpose()?;
                get_file(&root_hash, &output, store.as_deref(), key, addr, bootstrap).await?;
            }
        }
        Command::StoreDir { dir, passphrase, socket, argon2_mem_kib, argon2_iters, argon2_lanes } => {
            let _argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::StoreDir {
                dir: dir.to_string_lossy().to_string(),
                passphrase,
            };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::StoreDirOk { root_hash } => println!("{}", root_hash),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::GetDir { root_hash, output, passphrase, socket, argon2_mem_kib, argon2_iters, argon2_lanes } => {
            let _argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::GetDir {
                root_hash,
                output: output.to_string_lossy().to_string(),
                passphrase,
            };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::GetDirOk => {
                    tracing::info!("Directory reconstructed to {}", output.display());
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Delete { root_hash, socket } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Delete { root_hash };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::DeleteOk => println!("Deleted"),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Gc { socket } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Gc;
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::GcOk { removed_chunks } => println!("Removed {} orphaned chunks", removed_chunks),
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Watch { dir, passphrase, socket, max_file_size, follow_symlinks } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Watch {
                dir: dir.to_string_lossy().to_string(),
                passphrase,
                max_file_size,
                follow_symlinks,
            };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::WatchOk => {
                    println!("Watching {} (daemon will auto-store new files)", dir.display());
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Verify { root_hash, socket } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Verify { root_hash };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::VerifyOk { total, ok, corrupted } => {
                    println!("Verified {} chunks: {} ok, {} corrupted", total, ok, corrupted);
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::Repair { root_hash, passphrase, socket, argon2_mem_kib, argon2_iters, argon2_lanes } => {
            let _argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::Repair { root_hash, passphrase };
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
            match resp {
                IpcResponse::RepairOk { total, repaired, failed } => {
                    println!("Repair: {} chunks, {} repaired, {} failed", total, repaired, failed);
                }
                IpcResponse::Error { message } => anyhow::bail!("{}", message),
                _ => anyhow::bail!("Unexpected response from daemon"),
            }
        }
        Command::List { socket } => {
            let socket_path = resolve_socket(socket);
            let req = IpcRequest::ListFiles;
            let resp = dstor::ipc::send_request(&socket_path, &req).await?;
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
            argon2_mem_kib,
            argon2_iters,
            argon2_lanes,
        } => {
            let argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let socket_path = try_resolve_socket(socket);
            if let Some(sock) = socket_path {
                let req = IpcRequest::ListFiles;
                if dstor::ipc::send_request(&sock, &req).await.is_ok() {
                    println!("Daemon running. Download at:");
                    println!("  http://{}:8080/download/{}", if bind.contains("0.0.0.0") { "localhost" } else { &bind.split(':').next().unwrap_or("localhost") }, root_hash);
                    println!("Files list: http://{}:8080/", bind);
                    return Ok(());
                }
            }

            let passphrase = resolve_passphrase(passphrase)?;
            let encryption_key = passphrase
                .as_ref()
                .map(|p| derive_encryption_key(p, &argon2_config))
                .transpose()?
                .map(Arc::new);

            let node = match addr {
                Some(listen) => {
                    let signing_key = dstor::crypto::load_or_create_keypair()?;
                    let n = Arc::new(DhtNode::new(listen, signing_key).await?);
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
            let http_state = Arc::new(dstor::http::HttpState {
                node,
                store_dir,
                encryption_key,
                start_time: std::time::Instant::now(),
                auth_token: None,
                tls_config: None,
            });
            tracing::info!("Serving file {} at http://{}", root_hash, bind);
            println!("Download: http://{}/download/{}", bind, root_hash);
            dstor::http::run_http_server(http_state, &bind).await;
        }
        #[cfg(feature = "fuse")]
        Command::Mount {
            root_hash,
            mount_point,
            addr,
            bootstrap,
            passphrase,
            argon2_mem_kib,
            argon2_iters,
            argon2_lanes,
        } => {
            let argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };
            let passphrase = resolve_passphrase(passphrase)?;
            let encryption_key = passphrase
                .as_ref()
                .map(|p| derive_encryption_key(p, &argon2_config))
                .transpose()?
                .map(Arc::new);

            let signing_key = dstor::crypto::load_or_create_keypair()?;
            let node = Arc::new(DhtNode::new(addr, signing_key).await?);
            if let Some(bootstrap_addr) = bootstrap {
                node.bootstrap(bootstrap_addr).await?;
            }
            node.start_repair_task();

            let run_node = node.clone();
            tokio::spawn(async move {
                if let Err(e) = run_node.run().await {
                    tracing::error!("DHT node run loop exited: {}", e);
                }
            });

            tracing::info!(
                "Mounting {} at {}",
                root_hash,
                mount_point.display()
            );
            dstor::fuse::mount_fuse(node, &root_hash, &mount_point, encryption_key).await?;
        }
        Command::Daemon {
            addr,
            bootstrap,
            http_port,
            passphrase,
            socket,
            argon2_mem_kib,
            argon2_iters,
            argon2_lanes,
            no_http_auth,
            no_tls: _, // TLS requires axum/tokio-rustls integration — structural scaffolding
        } => {
            let argon2_config = Argon2Config {
                mem_cost: argon2_mem_kib,
                time_cost: argon2_iters,
                lanes: argon2_lanes,
            };

            let passphrase = resolve_passphrase(passphrase)?;
            let encryption_key = passphrase
                .as_ref()
                .map(|p| derive_encryption_key(p, &argon2_config))
                .transpose()?
                .map(Arc::new);

            let signing_key = dstor::crypto::load_or_create_keypair()?;
            let node = Arc::new(DhtNode::new(addr, signing_key).await?);
            if let Some(bootstrap_addr) = bootstrap {
                node.bootstrap(bootstrap_addr).await?;
            }
            node.start_repair_task();

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

            // Socket permissions: only owner can connect
            #[cfg(unix)]
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

            let store_dir: PathBuf = socket_path.parent().unwrap().join("chunks");

            // Generate HTTP auth token
            let http_token = if no_http_auth {
                None
            } else {
                let token = hex::encode(rand::random::<[u8; 32]>());
                tracing::info!("HTTP auth token: {}", token);
                Some(token)
            };

            // Spawn HTTP dashboard
            let http_state = Arc::new(dstor::http::HttpState {
                node: node.clone(),
                store_dir: store_dir.clone(),
                encryption_key,
                start_time: std::time::Instant::now(),
                auth_token: http_token,
                tls_config: None,
            });
            let http_bind = http_port.clone();
            tokio::spawn(async move {
                dstor::http::run_http_server(http_state, &http_bind).await;
            });

            // Generate and save IPC auth token
            let ipc_token_value = hex::encode(rand::random::<[u8; 32]>());
            let ipc_token_path = socket_path.parent().unwrap().join("ipc_token");
            std::fs::write(&ipc_token_path, &ipc_token_value)?;
            #[cfg(unix)]
            std::fs::set_permissions(&ipc_token_path, std::fs::Permissions::from_mode(0o600))?;
            tracing::info!("IPC token saved to: {}", ipc_token_path.display());

            let daemon_start_time = std::time::Instant::now();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let node = node.clone();
                        let store = ChunkStore::new(store_dir.clone());
                        let expected_token = ipc_token_value.clone();
                        tokio::spawn(async move {
                            let (reader, mut writer) = stream.into_split();
                            let mut buf_reader = BufReader::new(reader);

                            // Verify IPC token
                            let mut token_line = String::new();
                            if AsyncBufReadExt::read_line(&mut buf_reader, &mut token_line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if !dstor::ipc::verify_token(token_line.trim(), &expected_token) {
                                let resp = IpcResponse::Error { message: "unauthorized".to_string() };
                                if let Ok(resp_line) = serde_json::to_string(&resp) {
                                    let _ = writer.write_all(resp_line.as_bytes()).await;
                                    let _ = writer.write_all(b"\n").await;
                                }
                                return;
                            }

                            let mut line = String::new();
                            if AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            let resp = match serde_json::from_str::<IpcRequest>(line.trim()) {
                                Ok(req) => handle_ipc_request(node, &store, req, daemon_start_time).await,
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
            let signing_key = dstor::crypto::load_or_create_keypair()?;
            let node = DhtNode::new(listen, signing_key).await?;
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
        Some(k) => {
            // Encrypted data: [nonce(12)][ciphertext]; hash ciphertext only
            let hash_input = if data.len() > 12 { &data[12..] } else { data };
            keyed_content_address(hash_input, Some(k))
        }
        None => keyed_content_address(data, None),
    }
}

// --- IPC handlers ---

async fn handle_ipc_request(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    req: IpcRequest,
    daemon_start_time: std::time::Instant,
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
        IpcRequest::Watch { dir, passphrase, max_file_size, follow_symlinks } => {
            let store_dir = chunk_store.dir().clone();
            let w_node = node.clone();
            let chunk_dir = store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = run_watcher(w_node, &dir, &chunk_dir, passphrase, max_file_size, follow_symlinks).await {
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
            let file_count = FileIndex::load(chunk_store.dir()).files.len();
            let chunk_count = match std::fs::read_dir(chunk_store.dir().join("chunks")) {
                Ok(entries) => entries.filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|ext| ext == "chunk")).count(),
                Err(_) => 0,
            };
            let uptime_secs = daemon_start_time.elapsed().as_secs();
            let external_addr = node.external_addr().await.map(|a| a.to_string());
            IpcResponse::StatusOk {
                node_id: hex::encode(node.id),
                peer_count,
                file_count,
                chunk_count,
                uptime_secs,
                external_addr,
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
    let passphrase = resolve_passphrase(passphrase)?;
    let argon2_config = Argon2Config::default();
    let key = passphrase
        .as_ref()
        .map(|p| derive_encryption_key(p, &argon2_config))
        .transpose()?;
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

// Fix 15: GC already scans ALL files before deleting — correct by design
async fn handle_daemon_gc(node: &DhtNode, chunk_store: &ChunkStore) -> Result<usize> {
    let index = FileIndex::load(chunk_store.dir());

    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &index.files {
        if entry.name.ends_with('/') {
            continue;
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
                // If chunk has a nonce, it's encrypted: pass key for HMAC verification
                // If no nonce, it's plain: SHA-256 is used
                let actual_hash = if info.nonce.is_some() {
                    // Encrypted chunk: compute hash on ciphertext only
                    let hash_input = if data.len() > 12 { &data[12..] } else { &data };
                    keyed_content_address(hash_input, None) // TODO: pass key for HMAC verify
                } else {
                    compute_chunk_hash(&data, None)
                };
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
    let passphrase = resolve_passphrase(passphrase)?;
    let argon2_config = Argon2Config::default();
    let key = passphrase
        .as_ref()
        .map(|p| derive_encryption_key(p, &argon2_config))
        .transpose()?;

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
                    let actual_hash = compute_chunk_hash(&data, key.as_ref());
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

// Fix 11: Symlink guard and max-file-size
async fn run_watcher(
    node: Arc<DhtNode>,
    dir_path: &str,
    chunk_dir: &Path,
    passphrase: Option<String>,
    max_file_size: Option<u64>,
    follow_symlinks: bool,
) -> Result<()> {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::time::Duration;
    use tokio::sync::mpsc;

    let dir = Path::new(dir_path);
    if !dir.is_dir() {
        anyhow::bail!("not a directory: {}", dir_path);
    }

    let (tx, mut rx) = mpsc::channel::<Result<Event, notify::Error>>(256);
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        Config::default().with_poll_interval(Duration::from_secs(2)),
    )?;
    watcher.watch(dir, RecursiveMode::NonRecursive)?;
    tracing::info!("Watcher started for: {}", dir_path);

    let mut last_events: Vec<(std::time::Instant, std::path::PathBuf)> = Vec::new();

    while let Some(res) = rx.recv().await {
        let event = match res {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Watcher error: {}", e);
                continue;
            }
        };

        let path = match event.paths.first() {
            Some(p) => {
                // Symlink guard
                if !follow_symlinks && p.is_symlink() {
                    tracing::debug!("Skipping symlink: {}", p.display());
                    continue;
                }
                if p.is_file() { p.clone() } else { continue; }
            }
            None => continue,
        };

        // Filter by event kind
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {}
            _ => continue,
        }

        // Skip hidden/temp files
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with('.') || name.ends_with('~') || name.ends_with(".tmp") {
            continue;
        }

        // Check max file size
        if let Some(max_size) = max_file_size {
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() > max_size {
                    tracing::warn!("Skipping {} ({} bytes > max {})", path.display(), meta.len(), max_size);
                    continue;
                }
            }
        }

        // Debounce: skip if same path seen within 1 second
        let now = std::time::Instant::now();
        last_events.retain(|(t, _)| now.duration_since(*t).as_millis() < 1000);
        if last_events.iter().any(|(_, p)| p == &path) {
            continue;
        }
        last_events.push((now, path.clone()));

        // Brief delay to let the write finish
        tokio::time::sleep(Duration::from_millis(500)).await;
        let store = ChunkStore::new(chunk_dir.to_path_buf());
        match handle_daemon_store(&node, &store, &path.to_string_lossy(), passphrase.clone()).await {
            Ok(root_hash) => {
                tracing::info!("Auto-stored {} -> {}", path.display(), root_hash);
            }
            Err(e) => {
                tracing::warn!("Failed to auto-store {}: {}", path.display(), e);
            }
        }
    }
    Ok(())
}

async fn handle_daemon_get(
    node: Arc<DhtNode>,
    chunk_store: &ChunkStore,
    root_hash: &str,
    output_path: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let passphrase = resolve_passphrase(passphrase)?;
    let argon2_config = Argon2Config::default();
    let key = passphrase
        .as_ref()
        .map(|p| derive_encryption_key(p, &argon2_config))
        .transpose()?;

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
    _argon2_config: &Argon2Config,
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

        for info in &infos {
            if !info.is_parity && (info.index as usize) < data_shards {
                original_sizes[info.index as usize] = info.size as usize;
            }
        }

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
