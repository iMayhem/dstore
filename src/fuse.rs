use crate::chunk::Manifest;
use crate::crypto::{decrypt_chunk, EncryptedChunk};
use crate::erasure;
use crate::net::dht::DhtNode;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};

const TTL: Duration = Duration::from_secs(60);
const BLOCK_SIZE: u64 = 4096;
const ROOT_ID: u64 = fuser::FUSE_ROOT_ID;

struct InodeData {
    attr: FileAttr,
    parent: u64,
    name: String,
}

pub struct DstoreFS {
    manifest: Manifest,
    inodes: Vec<InodeData>,
    file_content: Vec<u8>,
}

impl DstoreFS {
    pub async fn new(
        node: Arc<DhtNode>,
        root_hash: &str,
        encryption_key: Option<Arc<Zeroizing<[u8; 32]>>>,
    ) -> anyhow::Result<Self> {
        let hash_key = hex_to_key(root_hash)?;
        let manifest_bytes = node
            .find_value(&hash_key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("manifest not found on DHT"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

        let file_content = reconstruct_file(
            &node,
            &manifest,
            encryption_key.as_deref(),
        )
        .await?;

        let now_dur = UNIX_EPOCH.elapsed().unwrap_or_default();
        let now = SystemTime::UNIX_EPOCH + now_dur;
        let file_size = file_content.len() as u64;
        let file_name = manifest.file_name.clone();

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let root_attr = FileAttr {
            ino: ROOT_ID,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        };

        let file_attr = FileAttr {
            ino: 2,
            size: file_size,
            blocks: (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        };

        let inodes = vec![
            InodeData {
                attr: root_attr,
                parent: ROOT_ID,
                name: String::new(),
            },
            InodeData {
                attr: file_attr,
                parent: ROOT_ID,
                name: file_name,
            },
        ];

        Ok(DstoreFS {
            manifest,
            inodes,
            file_content,
        })
    }

    fn get_inode(&self, ino: u64) -> Option<&InodeData> {
        self.inodes.get((ino - 1) as usize)
    }
}

async fn fetch_chunk_data(
    node: &DhtNode,
    hash: &str,
    nonce: Option<[u8; 12]>,
    encryption_key: Option<&Zeroizing<[u8; 32]>>,
) -> Option<Vec<u8>> {
    let chunk_key = hex_to_key(hash).ok()?;
    let data = node.find_value(&chunk_key).await.ok().flatten()?;

    let actual_hash = hex::encode(Sha256::digest(&data));
    if actual_hash != hash {
        return None;
    }

    match (encryption_key, nonce) {
        (Some(key), Some(nonce)) => {
            let enc = EncryptedChunk {
                nonce,
                ciphertext: if data.len() > 12 {
                    data[12..].to_vec()
                } else {
                    return None;
                },
            };
            decrypt_chunk(key, &enc)
        }
        _ => Some(data),
    }
}

async fn reconstruct_file(
    node: &DhtNode,
    manifest: &Manifest,
    encryption_key: Option<&Zeroizing<[u8; 32]>>,
) -> anyhow::Result<Vec<u8>> {
    if manifest.parity_shards == 0 {
        let mut content = Vec::with_capacity(manifest.file_size as usize);
        for info in &manifest.chunks {
            let chunk = fetch_chunk_data(node, &info.hash, info.nonce, encryption_key)
                .await
                .ok_or_else(|| anyhow::anyhow!("missing chunk: {}", info.hash))?;
            content.extend_from_slice(&chunk);
        }
        content.truncate(manifest.file_size as usize);
        return Ok(content);
    }

    // EC reconstruction: group by stripe
    let data_shards = manifest.data_shards;
    let parity_shards = manifest.parity_shards;
    let total_shards = data_shards + parity_shards;

    let mut stripe_map: HashMap<u32, Vec<&crate::chunk::ChunkInfo>> = HashMap::new();
    for info in &manifest.chunks {
        stripe_map.entry(info.stripe_index).or_default().push(info);
    }
    let total_stripes = stripe_map.len();

    let mut content = Vec::with_capacity(manifest.file_size as usize);

    for stripe_idx in 0..total_stripes as u32 {
        let infos = stripe_map.remove(&stripe_idx).unwrap_or_default();

        let mut available: Vec<Option<Vec<u8>>> = (0..total_shards).map(|_| None).collect();
        let mut original_sizes = vec![0usize; data_shards];

        for info in &infos {
            let pos = if info.is_parity {
                data_shards + info.index as usize
            } else {
                info.index as usize
            };
            if pos >= total_shards {
                continue;
            }
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
            if let Some(data) =
                fetch_chunk_data(node, &info.hash, info.nonce, encryption_key).await
            {
                available[pos] = Some(data);
            }
        }

        let present = available.iter().filter(|s| s.is_some()).count();
        if present < data_shards {
            anyhow::bail!(
                "stripe {}: only {}/{} shards available, need {}",
                stripe_idx,
                present,
                total_shards,
                data_shards
            );
        }

        let reconstructed = erasure::decode_stripe(&available, data_shards, parity_shards, &original_sizes)
            .map_err(|e| anyhow::anyhow!("stripe {} decode failed: {}", stripe_idx, e))?;

        for chunk_data in &reconstructed {
            if !chunk_data.is_empty() {
                content.extend_from_slice(chunk_data);
            }
        }
    }

    content.truncate(manifest.file_size as usize);
    Ok(content)
}

impl Filesystem for DstoreFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        for inode in &self.inodes {
            if inode.parent == parent && inode.name == name {
                reply.entry(&TTL, &inode.attr, 0);
                return;
            }
        }
        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.get_inode(ino) {
            Some(inode) => reply.attr(&TTL, &inode.attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino != 2 {
            reply.error(libc::ENOENT);
            return;
        }
        if offset < 0 || size == 0 {
            reply.data(&[]);
            return;
        }

        let file_size = self.file_content.len() as i64;
        if offset >= file_size {
            reply.data(&[]);
            return;
        }

        let start = offset as usize;
        let end = (offset as usize + size as usize).min(self.file_content.len());
        reply.data(&self.file_content[start..end]);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        entries.push((ROOT_ID, FileType::Directory, ".".to_string()));
        entries.push((ROOT_ID, FileType::Directory, "..".to_string()));
        for inode in &self.inodes {
            if inode.attr.ino != ROOT_ID && inode.parent == ino {
                entries.push((inode.attr.ino, inode.attr.kind, inode.name.clone()));
            }
        }

        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*entry_ino, (i + 1) as i64, *kind, OsStr::new(name)) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request, _ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(0, 0);
    }
}

fn hex_to_key(h: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(h)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid 32-byte hex key");
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

pub async fn mount_fuse(
    node: Arc<DhtNode>,
    root_hash: &str,
    mount_point: &Path,
    encryption_key: Option<Arc<Zeroizing<[u8; 32]>>>,
) -> anyhow::Result<()> {
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)
            .map_err(|e| anyhow::anyhow!("failed to create mount point: {}", e))?;
    }

    let fs = DstoreFS::new(node, root_hash, encryption_key).await?;

    tracing::info!("Mounting FUSE filesystem at {}", mount_point.display());
    fuser::mount2(fs, mount_point, &[MountOption::AutoUnmount])
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {}", e))
}
