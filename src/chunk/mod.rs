use sha2::{Sha256, Digest};
use anyhow::{Result, Context};
use std::path::Path;
use std::io::{Read, Write};

pub const CHUNK_SIZE: usize = 256 * 1024; // 256 KB

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkInfo {
    pub hash: String,
    pub index: u32,
    pub size: u32,
    pub nonce: Option<[u8; 12]>,
    #[serde(default)]
    pub is_parity: bool,
    #[serde(default)]
    pub stripe_index: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub file_name: String,
    pub file_size: u64,
    pub total_chunks: u32,
    pub chunks: Vec<ChunkInfo>,
    #[serde(default = "default_data_shards")]
    pub data_shards: usize,
    #[serde(default = "default_parity_shards")]
    pub parity_shards: usize,
}

fn default_data_shards() -> usize { 1 }
fn default_parity_shards() -> usize { 0 }

pub fn chunk_file(path: &Path) -> Result<(Vec<Vec<u8>>, Manifest)> {
    let file_name = path
        .file_name()
        .context("invalid file path")?
        .to_string_lossy()
        .to_string();
    let file_size = std::fs::metadata(path)?.len();

    let mut file = std::fs::File::open(path)?;
    let mut chunks = Vec::new();
    let mut chunk_infos = Vec::new();
    let mut index = 0u32;

    loop {
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        buf.truncate(n);

        let hash = hex::encode(Sha256::digest(&buf));
        let info = ChunkInfo {
            hash,
            index,
            size: n as u32,
            nonce: None,
            is_parity: false,
            stripe_index: 0,
        };
        chunk_infos.push(info);
        chunks.push(buf);
        index += 1;
    }

    let manifest = Manifest {
        file_name,
        file_size,
        total_chunks: index,
        chunks: chunk_infos,
        data_shards: 1,
        parity_shards: 0,
    };

    Ok((chunks, manifest))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirEntry {
    pub path: String,
    pub root_hash: String,
    pub size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirManifest {
    pub dir_name: String,
    pub entries: Vec<DirEntry>,
}

pub fn walk_directory(dir: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    walk_dir_recursive(dir, dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_dir_recursive(root: &Path, current: &Path, files: &mut Vec<String>) -> Result<()> {
    if current.is_dir() {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk_dir_recursive(root, &path, files)?;
            } else if path.is_file() {
                let relative = path.strip_prefix(root)
                    .context("path prefix error")?
                    .to_string_lossy()
                    .to_string();
                files.push(relative);
            }
        }
    }
    Ok(())
}

pub fn reassemble_file(manifest: &Manifest, chunk_dir: &Path, output: &Path) -> Result<()> {
    let mut file = std::fs::File::create(output)?;

    for info in &manifest.chunks {
        let chunk_path = chunk_dir.join(format!("{}.chunk", info.hash));
        let mut buf = vec![0u8; info.size as usize];
        if chunk_path.exists() {
            let mut cf = std::fs::File::open(&chunk_path)?;
            cf.read_exact(&mut buf)?;
        } else {
            anyhow::bail!("missing chunk: {}", info.hash);
        }
        file.write_all(&buf)?;
    }

    Ok(())
}
