use crate::store::FileRecord;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(home).join(".dstore");
    std::fs::create_dir_all(&dir).ok();
    dir.join("daemon.sock")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum IpcRequest {
    Store {
        file: String,
        passphrase: Option<String>,
    },
    Get {
        root_hash: String,
        output: String,
        passphrase: Option<String>,
    },
    StoreDir {
        dir: String,
        passphrase: Option<String>,
    },
    GetDir {
        root_hash: String,
        output: String,
        passphrase: Option<String>,
    },
    Delete {
        root_hash: String,
    },
    Gc,
    Watch {
        dir: String,
        passphrase: Option<String>,
    },
    Verify {
        root_hash: String,
    },
    Repair {
        root_hash: String,
        passphrase: Option<String>,
    },
    ListFiles,
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcResponse {
    StoreOk {
        root_hash: String,
    },
    GetOk,
    ListFilesOk {
        files: Vec<FileRecord>,
    },
    StoreDirOk {
        root_hash: String,
    },
    GetDirOk,
    DeleteOk,
    GcOk {
        removed_chunks: usize,
    },
    WatchOk,
    VerifyOk {
        total: usize,
        ok: usize,
        corrupted: usize,
    },
    RepairOk {
        total: usize,
        repaired: usize,
        failed: usize,
    },
    StatusOk {
        node_id: String,
        peer_count: usize,
    },
    Error {
        message: String,
    },
}

pub async fn send_request(socket_path: &PathBuf, req: &IpcRequest) -> anyhow::Result<IpcResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let line = serde_json::to_string(req)? + "\n";
    writer.write_all(line.as_bytes()).await?;
    writer.shutdown().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    if response_line.is_empty() {
        anyhow::bail!("Daemon closed connection without response");
    }

    let resp: IpcResponse = serde_json::from_str(response_line.trim())?;
    Ok(resp)
}
