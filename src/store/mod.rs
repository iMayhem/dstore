use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub name: String,
    pub root_hash: String,
    pub size: u64,
    pub stored_at: u64,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    pub files: Vec<FileRecord>,
}

impl FileIndex {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("files.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(FileIndex { files: Vec::new() })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join("files.json");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, data)?;
        Ok(())
    }
}

pub struct ChunkStore {
    dir: PathBuf,
}

impl ChunkStore {
    pub fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).ok();
        ChunkStore { dir }
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    pub fn store_chunk(&self, hash: &str, data: &[u8]) -> Result<()> {
        let path = self.dir.join(format!("{}.chunk", hash));
        let mut file = std::fs::File::create(&path)?;
        file.write_all(data)?;
        Ok(())
    }

    pub fn load_chunk(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        let path = self.dir.join(format!("{}.chunk", hash));
        if path.exists() {
            Ok(Some(std::fs::read(&path)?))
        } else {
            Ok(None)
        }
    }

    pub fn has_chunk(&self, hash: &str) -> bool {
        self.dir.join(format!("{}.chunk", hash)).exists()
    }

    pub fn store_manifest(&self, manifest: &crate::chunk::Manifest) -> Result<()> {
        let path = self.dir.join("manifest.json");
        let data = serde_json::to_string_pretty(manifest)?;
        std::fs::write(&path, data)?;
        Ok(())
    }

    pub fn load_manifest(&self) -> Result<crate::chunk::Manifest> {
        let path = self.dir.join("manifest.json");
        let data = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn root_hash(&self) -> Result<Option<String>> {
        let path = self.dir.join("root_hash");
        if path.exists() {
            Ok(Some(std::fs::read_to_string(&path)?.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    pub fn store_root_hash(&self, hash: &str) -> Result<()> {
        std::fs::write(self.dir.join("root_hash"), hash)?;
        Ok(())
    }
}
