use crate::chunk;
use crate::crypto::{decrypt_chunk, encrypt_chunk, keyed_content_address, EncryptedChunk};
use crate::net::dht::DhtNode;
use crate::store::{ChunkStore, FileIndex, FileRecord};

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub struct TlsConfig {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct HttpState {
    pub node: Arc<DhtNode>,
    pub store_dir: PathBuf,
    pub encryption_key: Option<Arc<Zeroizing<[u8; 32]>>>,
    pub start_time: Instant,
    pub auth_token: Option<String>,
    pub tls_config: Option<TlsConfig>,
}

pub async fn run_http_server(state: Arc<HttpState>, bind_addr: &str) {
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => {
            tracing::info!("HTTP server listening on http://{}", bind_addr);
            l
        }
        Err(e) => {
            tracing::error!("Failed to bind HTTP server on {}: {}", bind_addr, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&mut stream, state).await {
                        tracing::debug!("HTTP error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("HTTP accept error: {}", e);
            }
        }
    }
}

fn extract_bearer_token(request: &str) -> Option<&str> {
    for line in request.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization: bearer ") {
            return Some(line.trim_start_matches(|c: char| !c.is_whitespace()).trim());
        }
    }
    None
}

pub async fn handle_connection(stream: &mut tokio::net::TcpStream, state: Arc<HttpState>) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16384];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    buf.truncate(n);

    let request = String::from_utf8_lossy(&buf);

    if let Some(ref expected_token) = state.auth_token {
        let provided = extract_bearer_token(&request).unwrap_or("");
        if expected_token.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1 {
            let body = "401 Unauthorized";
            let header = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
            return Ok(());
        }
    }

    if request.starts_with("GET /status") {
        let body = status_json(&state);
        write_response(stream, "application/json", body.as_bytes()).await
    } else if request.starts_with("GET /download/") {
        let hash = request
            .strip_prefix("GET /download/")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("");
        serve_file(stream, state, hash).await
    } else if request.starts_with("DELETE /files/") {
        let hash = request
            .strip_prefix("DELETE /files/")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("");
        handle_delete(stream, state, hash).await
    } else if request.starts_with("POST /upload") {
        handle_upload(stream, state, &buf).await
    } else if request.starts_with("GET / ") || request.starts_with("GET / HTTP") || request.starts_with("GET /\r\n") {
        let body = status_html(&state);
        write_response(stream, "text/html; charset=utf-8", body.as_bytes()).await
    } else {
        write_response(stream, "text/plain", b"Not Found").await
    }
}

async fn handle_upload(stream: &mut tokio::net::TcpStream, state: Arc<HttpState>, initial_data: &[u8]) -> std::io::Result<()> {
    let request = String::from_utf8_lossy(initial_data);

    let content_length = request
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let boundary = request
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .and_then(|l| l.split("boundary=").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if boundary.is_empty() || content_length == 0 {
        return write_error(stream, 400, "Missing boundary or content-length").await;
    }

    let headers_end = initial_data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(initial_data.len());

    let total_needed = headers_end + content_length;
    let mut full_data = initial_data.to_vec();
    while full_data.len() < total_needed {
        let mut tmp = vec![0u8; 65536];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        full_data.extend_from_slice(&tmp[..n]);
    }

    if full_data.len() < total_needed {
        return write_error(stream, 400, "Incomplete request body").await;
    }

    let file = match parse_multipart_upload(&full_data[headers_end..], &boundary) {
        Some(f) => f,
        None => return write_json_error(stream, 400, "Failed to parse upload").await,
    };

    match store_uploaded_file(&state, &file).await {
        Ok(root_hash) => {
            let resp = serde_json::json!({
                "url": format!("/download/{}", root_hash),
                "root_hash": root_hash,
                "name": file.filename,
                "size": file.data.len(),
            });
            write_json_response(stream, &resp).await
        }
        Err(e) => {
            let msg = format!("Storage error: {}", e);
            write_json_error(stream, 500, &msg).await
        }
    }
}

struct UploadedFile {
    filename: String,
    _content_type: String,
    data: Vec<u8>,
}

fn parse_multipart_upload(body: &[u8], boundary: &str) -> Option<UploadedFile> {
    let boundary_start = format!("--{}", boundary);
    let crlf_boundary = format!("\r\n--{}", boundary);
    let b_start = boundary_start.as_bytes();
    let b_crlf = crlf_boundary.as_bytes();

    let bpos = find_subsequence(body, b_start, 0)?;
    let after_b = bpos + b_start.len();

    let pos = if body[after_b..].starts_with(b"\r\n") {
        after_b + 2
    } else {
        return None;
    };

    let hdr_end = find_subsequence(body, b"\r\n\r\n", pos)?;
    let header_str = std::str::from_utf8(&body[pos..hdr_end]).ok()?;

    let mut filename = "uploaded.bin".to_string();
    let mut content_type = "application/octet-stream".to_string();

    for line in header_str.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-disposition:") {
            if let Some(start) = line.find("filename=\"") {
                let s = start + 10;
                if let Some(end) = line[s..].find('"') {
                    let name = &line[s..s + end];
                    if !name.is_empty() {
                        filename = name.to_string();
                    }
                }
            }
        }
        if lower.starts_with("content-type:") {
            if let Some(val) = line.split(':').nth(1) {
                content_type = val.trim().to_string();
            }
        }
    }

    let body_start = hdr_end + 4;
    let body_end = find_subsequence(body, b_crlf, body_start)?;

    Some(UploadedFile {
        filename,
        _content_type: content_type,
        data: body[body_start..body_end].to_vec(),
    })
}

fn find_subsequence(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() || needle.is_empty() {
        return None;
    }
    data[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

async fn store_uploaded_file(state: &HttpState, file: &UploadedFile) -> anyhow::Result<String> {
    if file.data.is_empty() {
        anyhow::bail!("empty file");
    }

    let temp_dir = std::env::temp_dir();
    let temp_name = format!("dstore_upload_{}", file.filename);
    let temp_path = temp_dir.join(&temp_name);
    {
        let mut f = std::fs::File::create(&temp_path)?;
        f.write_all(&file.data)?;
    }

    let (plaintext_chunks, mut manifest) = chunk::chunk_file(&temp_path)?;
    let total_data = plaintext_chunks.len();

    let (data_shards, parity_shards) = crate::erasure::choose_config(total_data);
    manifest.data_shards = data_shards;
    manifest.parity_shards = parity_shards;

    let chunk_dir = state.store_dir.join("chunks");
    let store = ChunkStore::new(chunk_dir);
    let mut all_chunks: Vec<(chunk::ChunkInfo, Vec<u8>)> = Vec::new();

    let key = state.encryption_key.as_deref();

    if parity_shards > 0 {
        let stripes = plaintext_chunks.chunks(data_shards);
        for (stripe_idx, stripe_data) in stripes.enumerate() {
            let mut stripe_input = stripe_data.to_vec();
            while stripe_input.len() < data_shards {
                stripe_input.push(vec![0u8; 0]);
            }
            let encoded = crate::erasure::encode_stripe(&stripe_input, parity_shards)?;
            for (shard_idx, plaintext) in encoded.iter().enumerate() {
                let is_parity = shard_idx >= data_shards;
                let (on_disk_data, nonce) = encrypt_chunk_data(key, plaintext);
                let hash = keyed_content_address(&on_disk_data, key);
                let (chunk_index, orig_size) = if is_parity {
                    ((shard_idx - data_shards) as u32, 0u32)
                } else {
                    let file_idx = stripe_idx * data_shards + shard_idx;
                    let s = if file_idx < total_data {
                        manifest.chunks[file_idx].size
                    } else {
                        0
                    };
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
    } else {
        for (i, pt_chunk) in plaintext_chunks.iter().enumerate() {
            let (on_disk_data, nonce) = encrypt_chunk_data(key, pt_chunk);
            let hash = keyed_content_address(&on_disk_data, key);
            store.store_chunk(&hash, &on_disk_data)?;
            manifest.chunks[i].hash = hash;
            manifest.chunks[i].nonce = nonce;
        }
    }

    let manifest_bytes = serde_json::to_string(&manifest)?;
    let root_hash = hex::encode(Sha256::digest(&manifest_bytes));
    store.store_root_hash(&root_hash)?;
    store.store_manifest(&manifest)?;

    tracing::info!("Publishing {} chunks to DHT...", manifest.chunks.len());
    for info in &manifest.chunks {
        if let Some(data) = store.load_chunk(&info.hash)? {
            let key_bytes = hex_decode_32(&info.hash)?;
            if let Err(e) = state.node.store_value(key_bytes, data).await {
                tracing::warn!("Failed to distribute chunk {}: {}", info.hash, e);
            }
        }
    }
    let manifest_key = hex_decode_32(&root_hash)?;
    state
        .node
        .store_value(manifest_key, manifest_bytes.as_bytes().to_vec())
        .await?;

    let record = FileRecord {
        name: file.filename.clone(),
        root_hash: root_hash.clone(),
        size: file.data.len() as u64,
        stored_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        chunk_count: manifest.chunks.len() as u32,
    };
    let mut index = FileIndex::load(&state.store_dir);
    if let Some(pos) = index.files.iter().position(|f| f.root_hash == record.root_hash) {
        index.files[pos] = record.clone();
    } else {
        index.files.push(record);
    }
    index.save(&state.store_dir)?;

    let _ = std::fs::remove_file(&temp_path);

    Ok(root_hash)
}

fn encrypt_chunk_data(key: Option<&Zeroizing<[u8; 32]>>, data: &[u8]) -> (Vec<u8>, Option<[u8; 12]>) {
    match key {
        Some(k) => {
            let enc = encrypt_chunk(k, data);
            let mut buf = Vec::with_capacity(12 + enc.ciphertext.len());
            buf.extend_from_slice(&enc.nonce);
            buf.extend_from_slice(&enc.ciphertext);
            (buf, Some(enc.nonce))
        }
        None => (data.to_vec(), None),
    }
}

fn hex_decode_32(hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid hash length");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn handle_delete(stream: &mut tokio::net::TcpStream, state: Arc<HttpState>, root_hash: &str) -> std::io::Result<()> {
    if root_hash.len() != 64 {
        return write_error(stream, 400, "Invalid root hash (expected 64 hex chars)").await;
    }

    let mut file_index = FileIndex::load(&state.store_dir);
    let before = file_index.files.len();
    file_index.files.retain(|f| f.root_hash != root_hash);
    if file_index.files.len() == before {
        return write_error(stream, 404, "File not found in index").await;
    }
    file_index
        .save(&state.store_dir)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    if let Ok(entries) = std::fs::read_dir(state.store_dir.join("chunks")) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.starts_with(root_hash) || fname.contains(root_hash) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    write_json_response(stream, &serde_json::json!({"ok": true, "action": "deleted", "root_hash": root_hash})).await
}

async fn write_json_response(stream: &mut tokio::net::TcpStream, value: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_string(value).unwrap_or_default();
    write_response(stream, "application/json", body.as_bytes()).await
}

async fn write_json_error(stream: &mut tokio::net::TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = serde_json::to_string(&serde_json::json!({"error": msg})).unwrap_or_default();
    let reason = if status == 400 {
        "Bad Request"
    } else if status == 404 {
        "Not Found"
    } else if status == 401 {
        "Unauthorized"
    } else {
        "Error"
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn write_response(stream: &mut tokio::net::TcpStream, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type,
        body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn write_error(stream: &mut tokio::net::TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!("<h1>{} {}</h1><p>{}</p>", status, if status == 404 { "Not Found" } else { "Error" }, msg);
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        if status == 404 { "Not Found" } else { "Error" },
        body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn serve_file(stream: &mut tokio::net::TcpStream, state: Arc<HttpState>, root_hash: &str) -> std::io::Result<()> {
    if root_hash.is_empty() || root_hash.len() != 64 {
        return write_error(stream, 400, "Invalid root hash").await;
    }

    let manifest_key = match hex::decode(root_hash) {
        Ok(k) if k.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&k);
            arr
        }
        _ => return write_error(stream, 400, "Invalid root hash").await,
    };

    let manifest_bytes = match state.node.find_value(&manifest_key).await {
        Ok(Some(b)) => b,
        Ok(None) => return write_error(stream, 404, "File not found").await,
        Err(e) => return write_error(stream, 500, &format!("DHT error: {}", e)).await,
    };

    let manifest: crate::chunk::Manifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(_) => return write_error(stream, 500, "Invalid manifest").await,
    };

    let needs_key = manifest.chunks.iter().any(|c| c.nonce.is_some());
    if needs_key && state.encryption_key.is_none() {
        return write_error(stream, 401, "File is encrypted. Restart daemon with --passphrase.").await;
    }

    let store = ChunkStore::new(state.store_dir.join("chunks"));
    let mut missing = Vec::new();
    for info in &manifest.chunks {
        if !store.has_chunk(&info.hash) {
            missing.push(info.hash.clone());
        }
    }
    if !missing.is_empty() {
        for hash in &missing {
            let chunk_key = match hex::decode(hash) {
                Ok(k) if k.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&k);
                    arr
                }
                _ => continue,
            };
            if let Ok(Some(data)) = state.node.find_value(&chunk_key).await {
                let actual_hash = keyed_content_address(&data, state.encryption_key.as_deref());
                if actual_hash == *hash {
                    store.store_chunk(hash, &data).ok();
                }
            }
        }
    }

    let mut file_data = Vec::new();
    for info in &manifest.chunks {
        match store.load_chunk(&info.hash) {
            Ok(Some(data)) => {
                let plaintext = match (&state.encryption_key, info.nonce) {
                    (Some(k), Some(nonce)) => {
                        if data.len() < 12 {
                            return write_error(stream, 500, "Truncated chunk").await;
                        }
                        let enc = EncryptedChunk {
                            nonce,
                            ciphertext: data[12..].to_vec(),
                        };
                        match decrypt_chunk(k, &enc) {
                            Some(p) => p,
                            None => return write_error(stream, 500, "Decryption failed").await,
                        }
                    }
                    _ => data,
                };
                file_data.extend_from_slice(&plaintext);
            }
            Err(_) | Ok(None) => {
                return write_error(stream, 500, &format!("Missing chunk: {}", info.hash)).await;
            }
        }
    }

    file_data.truncate(manifest.file_size as usize);

    let content_type = guess_mime(&manifest.file_name);
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Disposition: inline; filename=\"{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type,
        manifest.file_name,
        file_data.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&file_data).await?;
    Ok(())
}

fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        "text/html"
    } else if lower.ends_with(".txt") || lower.ends_with(".md") {
        "text/plain"
    } else if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".pdf") {
        "application/pdf"
    } else if lower.ends_with(".zip") {
        "application/zip"
    } else if lower.ends_with(".tar") || lower.ends_with(".gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

fn status_json(state: &HttpState) -> String {
    let node_id = hex::encode(state.node.id);
    let peers = state
        .node
        .routing
        .try_lock()
        .map(|rt| rt.all_nodes())
        .unwrap_or_default();
    let num_chunks = std::fs::read_dir(state.store_dir.join("chunks"))
        .map(|e| {
            e.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "chunk"))
                .count()
        })
        .unwrap_or(0);
    let files = FileIndex::load(&state.store_dir).files;
    let uptime = state.start_time.elapsed().as_secs();

    #[derive(serde::Serialize)]
    struct PeerInfo {
        id: String,
        addr: String,
        tcp_port: u16,
    }
    #[derive(serde::Serialize)]
    struct FileInfo {
        name: String,
        root_hash: String,
        size: u64,
        stored_at: u64,
    }
    #[derive(serde::Serialize)]
    struct Status {
        node_id: String,
        peer_count: usize,
        peers: Vec<PeerInfo>,
        files: Vec<FileInfo>,
        chunk_count: usize,
        tcp_port: u16,
        uptime_secs: u64,
    }

    let s = Status {
        node_id,
        peer_count: peers.len(),
        peers: peers
            .into_iter()
            .map(|p| PeerInfo {
                id: hex::encode(p.id),
                addr: p.addr.to_string(),
                tcp_port: p.tcp_port,
            })
            .collect(),
        files: files
            .into_iter()
            .map(|f| FileInfo {
                name: f.name,
                root_hash: f.root_hash,
                size: f.size,
                stored_at: f.stored_at,
            })
            .collect(),
        chunk_count: num_chunks,
        tcp_port: state.node.tcp_port,
        uptime_secs: uptime,
    };
    serde_json::to_string(&s).unwrap_or_default()
}

fn status_html(state: &HttpState) -> String {
    let node_id = hex::encode(state.node.id);
    let uptime = state.start_time.elapsed();
    let uptime_str = format!(
        "{:02}h {:02}m {:02}s",
        uptime.as_secs() / 3600,
        (uptime.as_secs() % 3600) / 60,
        uptime.as_secs() % 60
    );

    let peers = state
        .node
        .routing
        .try_lock()
        .map(|rt| rt.all_nodes())
        .unwrap_or_default();
    let peer_rows: String = peers
        .iter()
        .map(|p| {
            format!(
                "<div class=\"peer\"><code data-copy=\"{id}\">{short}</code><span class=\"addr\">{addr}:{port}</span></div>",
                id = hex::encode(p.id),
                short = &hex::encode(p.id)[..16],
                addr = p.addr,
                port = p.tcp_port,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let num_chunks = std::fs::read_dir(state.store_dir.join("chunks"))
        .map(|e| {
            e.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "chunk"))
                .count()
        })
        .unwrap_or(0);
    let files = FileIndex::load(&state.store_dir).files;
    let file_items: String = files
        .iter()
        .map(|f| {
            let size_str = if f.size < 1024 {
                format!("{} B", f.size)
            } else if f.size < 1024 * 1024 {
                format!("{:.1} KB", f.size as f64 / 1024.0)
            } else {
                format!("{:.1} MB", f.size as f64 / (1024.0 * 1024.0))
            };
            format!(
                r#"<div class="item" data-hash="{hash}">
  <div class="top">
    <a class="fname" href="/download/{hash}">{name}</a>
    <span class="fsize">{size}</span>
  </div>
  <div class="hrow">
    <code class="chip" data-copy="{hash}">{short}</code>
    <button class="delbtn" data-hash="{hash}" title="Delete">&#10005;</button>
  </div>
</div>"#,
                hash = f.root_hash,
                name = html_escape(&f.name),
                size = size_str,
                short = &f.root_hash[..16],
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let peer_count = peers.len();
    let file_count = files.len();
    let node_short = &node_id[..16];
    let tcp_port = state.node.tcp_port;
    let empty_msg = if files.is_empty() {
        "No files stored yet"
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
<script>document.documentElement.className='js';</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dstore</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:#f6f8fc; --card:#ffffff; --ink:#333f5c; --muted:#8a93a8;
  --accent:#e25c5c; --teal:#1fae99; --tint:#fdf2f0;
  --line:#dee4ef; --shadow:#333f5c;
  --sans:'Nunito',-apple-system,'Segoe UI',Roboto,sans-serif;
  --mono:ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;
}}
[data-theme="dark"]{{
  --bg:#1d2331; --card:#262e42; --ink:#e9edf6; --muted:#939db4;
  --accent:#f0837c; --teal:#3cc9b3; --tint:#332b36;
  --line:#3a4460; --shadow:#10141f;
}}
*{{box-sizing:border-box}}
html{{-webkit-text-size-adjust:100%}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15.5px;line-height:1.6;font-weight:500}}
::selection{{background:var(--accent);color:#fff}}
a{{color:var(--accent)}}
a:hover{{text-decoration-style:wavy;text-decoration-thickness:2px;text-underline-offset:3px}}
:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
.shell{{max-width:640px;margin:0 auto;padding:0 1.1rem 3.2rem;position:relative;z-index:1}}
header{{padding:1rem 0 0;text-align:right}}
.tt{{border:0;background:none;color:var(--muted);font:inherit;font-size:.85em;font-weight:700;cursor:pointer;padding:.2rem .4rem}}
.tt:hover{{color:var(--accent)}}
.hero{{text-align:center;margin-top:clamp(1.4rem,6vh,3rem)}}
.hero h1{{margin:0;font-size:clamp(1.8rem,6.2vw,2.6rem);font-weight:900;letter-spacing:-.015em;line-height:1.15}}
.squig{{display:block;width:clamp(130px,30vw,180px);height:13px;margin:.45rem auto 0;color:var(--accent)}}
.hero p{{margin:.8rem auto 0;color:var(--muted);font-weight:600;max-width:44ch}}

.box.drop{{margin:1.5rem auto 0;background:var(--card);border:2px solid var(--ink);border-radius:16px;box-shadow:5px 5px 0 var(--shadow);padding:2.2rem 1rem 1.8rem;text-align:center;cursor:pointer;display:block;width:100%;transition:transform .12s ease,box-shadow .12s ease,background .12s ease}}
.box.drop:hover{{transform:translate(-2px,-2px);box-shadow:7px 7px 0 var(--shadow)}}
.box.drop.dragging{{background:var(--tint);transform:translate(-2px,-2px);box-shadow:7px 7px 0 var(--shadow)}}
.drop-line{{font-size:1.2em;font-weight:800}}
.drop-or{{display:inline;color:var(--muted);font-weight:600}}
.select{{color:var(--accent);font-weight:800;text-decoration:underline;text-underline-offset:3px}}
.box.drop:hover .select{{text-decoration-style:wavy;text-decoration-thickness:2px}}
.drop-max{{color:var(--muted);font-size:.85em;font-weight:600;margin-top:.9rem}}

.box{{background:var(--card);border:2px solid var(--ink);border-radius:16px;box-shadow:5px 5px 0 var(--shadow);padding:1.2rem 1.4rem;margin-top:1.5rem}}
.statrow{{display:flex;gap:.6rem 1.4rem;flex-wrap:wrap}}
.stat{{flex:1;min-width:120px}}
.stat dt{{color:var(--muted);font-weight:700;font-size:.82em;text-transform:uppercase;letter-spacing:.02em}}
.stat dd{{margin:.15rem 0 0;font-weight:800;font-size:1.05em}}
.chip{{font-family:var(--mono);font-size:.88em;word-break:break-all;background:var(--bg);padding:.15em .5em;border-radius:8px}}
.act{{border:0;background:none;color:var(--accent);font:inherit;font-size:.85em;font-weight:700;cursor:pointer;padding:0}}
.act:hover{{text-decoration:underline wavy;text-decoration-thickness:2px;text-underline-offset:3px}}
.act.copied{{color:var(--teal)}}
.act.copied::after{{content:" \\2713"}}
h2{{font-size:1.12em;font-weight:900;margin:2rem 0 .5rem}}
.peer{{display:flex;align-items:center;gap:.6rem;padding:.35rem 0;border-bottom:1px solid var(--line)}}
.peer:last-child{{border:0}}
.peer .addr{{color:var(--muted);font-size:.9em;font-weight:600;margin-left:auto}}
.items{{display:flex;flex-direction:column;gap:.7rem;margin-top:.7rem}}
.item{{background:var(--card);border:2px solid var(--ink);border-radius:14px;box-shadow:4px 4px 0 var(--shadow);padding:.7rem .95rem}}
.item .top{{display:flex;justify-content:space-between;gap:.8rem;align-items:baseline}}
.item .fname{{font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-decoration:none}}
.item .fname:hover{{text-decoration:underline wavy;text-decoration-thickness:2px;text-underline-offset:3px}}
.item .fsize{{color:var(--muted);font-size:.82em;font-weight:700;flex:0 0 auto}}
.item .hrow{{margin-top:.3rem}}
.item .chip{{font-size:.82em;cursor:pointer;transition:color .12s}}
.item .chip:hover{{color:var(--accent)}}
.item.loading{{opacity:.6;pointer-events:none}}
.empty{{color:var(--muted);font-weight:600;text-align:center;padding:1.5rem 0}}
.delbtn{{border:0;background:none;color:var(--muted);font:inherit;font-size:.82em;font-weight:700;cursor:pointer;padding:0;margin-left:.5rem}}
.delbtn:hover{{color:var(--accent)}}
.delbtn:disabled{{opacity:.5;cursor:default}}

.results{{display:flex;flex-direction:column;gap:.7rem;margin-top:1.2rem}}
.ritem{{background:var(--card);border:2px solid var(--ink);border-radius:14px;box-shadow:4px 4px 0 var(--shadow);padding:.7rem .95rem}}
.ritem .top{{display:flex;justify-content:space-between;gap:.8rem;align-items:baseline}}
.ritem .fname{{font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.ritem .fsize{{color:var(--muted);font-size:.82em;font-weight:700;flex:0 0 auto}}
.prog{{margin-top:.5rem;display:flex;align-items:center;gap:.6rem}}
.pbar{{flex:1;height:10px;background:var(--bg);border:2px solid var(--ink);border-radius:99px;overflow:hidden}}
.pfill{{height:100%;width:0;background:var(--teal);transition:width .18s ease}}
.ppct{{font-size:.8em;font-weight:700;color:var(--muted);min-width:34px;text-align:right}}
.urlrow{{display:flex;gap:.75rem;align-items:baseline;margin-top:.4rem;flex-wrap:wrap}}
.url{{flex:1;min-width:0;font-family:var(--mono);font-size:.86em;color:var(--teal);font-weight:600;text-decoration:underline;text-underline-offset:3px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.ritem.error{{border-color:var(--accent)}}
.sub{{margin-top:.4rem;font-size:.82em;font-weight:600;color:var(--muted)}}

.foot{{margin-top:2.5rem;text-align:center;color:var(--muted);font-size:.8em;font-weight:600}}
.dropveil{{position:fixed;inset:0;z-index:50;background:rgba(40,49,72,.6);display:flex;align-items:center;justify-content:center;pointer-events:none}}
.dropveil[hidden]{{display:none}}
.dropveil-inner{{border:3px dashed #fff;color:#fff;font-weight:900;font-size:clamp(1.2rem,3.5vw,1.7rem);padding:1.8rem 2.8rem;border-radius:20px;background:rgba(20,25,38,.35)}}
@media (prefers-reduced-motion:reduce){{*{{transition:none!important}}}}
</style>
</head>
<body>

<div class="shell">
<header>
  <button class="tt" id="themeBtn" onclick="var r=document.documentElement;var n=r.getAttribute('data-theme')==='dark'?'light':'dark';r.setAttribute('data-theme',n);try{{localStorage.setItem('dstore-theme',n);}}catch(e){{}}">&#9681;</button>
</header>
<div class="hero">
  <h1>dstore</h1>
  <svg class="squig" viewBox="0 0 165 13" fill="none"><path d="M2 10.5c16-8 28-8 44 0s28 8 44 0 28-8 44 0 28 8 44 0" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>
  <p>decentralized file storage</p>
</div>

<section class="box drop" id="drop" tabindex="0" role="button" aria-label="Upload a file">
  <div class="drop-line">Drag a file here</div>
  <div><span class="drop-or">or</span> <span class="select">Choose file</span></div>
  <div class="drop-max">powered by Kademlia DHT</div>
</section>
<input type="file" id="file" hidden>
<div id="results"></div>

<div class="box">
  <div class="statrow">
    <div class="stat"><dt>Node</dt><dd><code class="chip" data-copy="{node_id}">{node_short}</code></dd></div>
    <div class="stat"><dt>Uptime</dt><dd id="uptime-display">{uptime_str}</dd></div>
    <div class="stat"><dt>TCP Port</dt><dd>{tcp_port}</dd></div>
    <div class="stat"><dt>Chunks</dt><dd id="chunk-count">{num_chunks}</dd></div>
  </div>
</div>

<h2>Peers (<span id="peer-count">{peer_count}</span>)</h2>
<div class="box" id="peer-list">{peer_rows}</div>

<h2>Files (<span id="file-count">{file_count}</span>)</h2>
<div class="items" id="file-list">{file_items}</div>
<div class="empty">{empty_msg}</div>

<div class="foot">dstore &middot; decentralized file storage</div>
</div>

<div class="dropveil" id="dropveil" hidden aria-hidden="true"><div class="dropveil-inner">Drop file here</div></div>
<script>
(function(){{
  function g(id){{return document.getElementById(id)}}
  var drop=g('drop'),input=g('file'),results=g('results'),veil=g('dropveil'),dragDepth=0;

  if(!drop||!input)return;

  drop.addEventListener('click',function(){{input.click()}});
  drop.addEventListener('keydown',function(e){{if(e.key==='Enter'||e.key===' '){{e.preventDefault();input.click()}}}});
  input.addEventListener('change',function(){{handleFiles(input.files);input.value=''}});

  ['dragenter','dragover'].forEach(function(ev){{drop.addEventListener(ev,function(e){{e.preventDefault();e.stopPropagation();drop.classList.add('dragging')}})}});
  ['dragleave','drop'].forEach(function(ev){{drop.addEventListener(ev,function(e){{e.preventDefault();e.stopPropagation();drop.classList.remove('dragging')}})}});
  drop.addEventListener('drop',function(e){{hideVeil();if(e.dataTransfer&&e.dataTransfer.files)handleFiles(e.dataTransfer.files)}});

  function hideVeil(){{dragDepth=0;if(veil)veil.hidden=true}}
  window.addEventListener('dragenter',function(e){{
    e.preventDefault();if(!veil)return;
    var types=(e.dataTransfer&&e.dataTransfer.types)||[];
    if(Array.prototype.indexOf.call(types,'Files')===-1)return;
    dragDepth++;veil.hidden=false;
  }});
  window.addEventListener('dragleave',function(e){{
    e.preventDefault();dragDepth=Math.max(0,dragDepth-1);if(dragDepth===0&&veil)veil.hidden=true;
  }});
  window.addEventListener('dragover',function(e){{e.preventDefault()}});
  window.addEventListener('drop',function(e){{e.preventDefault();hideVeil();if(e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files.length)handleFiles(e.dataTransfer.files)}});
  window.addEventListener('dragend',hideVeil);

  function fmt(n){{var u=['B','KB','MB','GB'],i=0;while(n>=1024&&i<u.length-1){{n/=1024;i++}}return Math.round(n*10)/10+' '+u[i]}}
  function setProg(el,pct){{var f=el.querySelector('.pfill');if(f)f.style.width=pct+'%';var t=el.querySelector('.ppct');if(t)t.textContent=pct+'%'}}

  function makeItem(file){{
    var el=document.createElement('div');el.className='ritem';
    el.innerHTML='<div class="top"><span class="fname"></span><span class="fsize"></span></div><div class="prog"><div class="pbar"><div class="pfill"></div></div><span class="ppct">0%</span></div>';
    el.querySelector('.fname').textContent=file.name;
    el.querySelector('.fsize').textContent=fmt(file.size);
    results.prepend(el);return el;
  }}

  function succeed(el,data){{
    var p=el.querySelector('.prog');if(p)p.remove();
    var row=document.createElement('div');row.className='urlrow';
    var url=document.createElement('div');url.className='url';url.textContent=data.url;url.title=data.url;
    var copy=document.createElement('button');copy.className='act';copy.type='button';copy.textContent='copy';
    copy.addEventListener('click',function(){{
      navigator.clipboard.writeText(window.location.origin+data.url).then(function(){{
        copy.textContent='ok';copy.classList.add('copied');
        setTimeout(function(){{copy.textContent='copy';copy.classList.remove('copied')}},1400);
      }});
    }});
    url.style.cursor='pointer';
    url.addEventListener('click',function(){{window.open(data.url,'_blank','noopener')}});
    row.appendChild(url);row.appendChild(copy);
    el.appendChild(row);
  }}

  function fail(el,msg){{
    el.classList.add('error');
    var p=el.querySelector('.prog');if(p)p.remove();
    var sub=document.createElement('div');sub.className='sub';sub.textContent='! '+msg;el.appendChild(sub);
  }}

  function handleFiles(files){{for(var i=0;i<files.length;i++)upload(files[i])}}

  function upload(file){{
    var el=makeItem(file);
    if(file.size===0){{fail(el,'empty file');return}}
    var prog=el.querySelector('.prog');
    var form=new FormData();form.append('file',file);
    var xhr=new XMLHttpRequest();xhr.open('POST','/upload');
    xhr.upload.addEventListener('progress',function(e){{if(e.lengthComputable&&prog)setProg(prog,Math.round((e.loaded/e.total)*100))}});
    xhr.addEventListener('load',function(){{
      var data={{}};try{{data=JSON.parse(xhr.responseText)}}catch(_){{}}
      if(xhr.status>=200&&xhr.status<300&&data.url)succeed(el,data);
      else fail(el,data.error||'upload failed');
    }});
    xhr.addEventListener('error',function(){{fail(el,'connection error')}});
    xhr.send(form);
  }}

  document.addEventListener('click',function(e){{
    var b=e.target.closest('[data-copy]');
    if(!b)return;
    var t=b.getAttribute('data-copy');
    navigator.clipboard.writeText(t).then(function(){{
      var o=b.textContent;b.textContent='copied';b.classList.add('copied');
      setTimeout(function(){{b.textContent=o;b.classList.remove('copied')}},1200);
    }});
  }});

  document.addEventListener('click',function(e){{
    var b=e.target.closest('.delbtn');
    if(!b||!confirm('Delete this file?'))return;
    var hash=b.getAttribute('data-hash');
    var item=b.closest('.item');item.classList.add('loading');
    fetch('/files/'+hash,{{method:'DELETE'}})
      .then(function(r){{return r.json()}})
      .then(function(d){{if(d.ok)item.remove();else alert('Delete failed: '+JSON.stringify(d))}})
      .catch(function(e){{alert('Error: '+e);item.classList.remove('loading')}});
  }});

  setInterval(function(){{
    fetch('/status').then(function(r){{return r.json()}}).then(function(d){{
      var pc=g('peer-count');if(pc)pc.textContent=d.peer_count;
      var fc=g('file-count');if(fc)fc.textContent=d.files.length;
      var cc=g('chunk-count');if(cc)cc.textContent=d.chunk_count;
      var up=g('uptime-display');
      if(up){{var s=d.uptime_secs;var h=Math.floor(s/3600);s%=3600;var m=Math.floor(s/60);s%=60;up.textContent=(h<10?'0':'')+h+'h '+(m<10?'0':'')+m+'m '+(s<10?'0':'')+s+'s'}}
    }}).catch(function(){{}});
  }},5000);
}})();
</script>
</body>
</html>"#,
        node_id = node_id,
        node_short = node_short,
        uptime_str = uptime_str,
        tcp_port = tcp_port,
        num_chunks = num_chunks,
        peer_count = peer_count,
        peer_rows = peer_rows,
        file_count = file_count,
        file_items = if files.is_empty() {
            String::new()
        } else {
            file_items
        },
        empty_msg = empty_msg,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
