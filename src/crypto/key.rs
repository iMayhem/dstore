use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub struct Argon2Config {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Argon2Config {
            mem_cost: 192,    // 192 KiB (Argon2 default)
            time_cost: 2,
            lanes: 1,
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .context("cannot find home directory")?
        .join(".dstore");
    std::fs::create_dir_all(&dir).ok();
    Ok(dir)
}

pub fn load_or_create_salt() -> Result<[u8; 32]> {
    let path = config_dir()?.join("salt");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        let mut salt = [0u8; 32];
        if bytes.len() == 32 {
            salt.copy_from_slice(&bytes);
            return Ok(salt);
        }
    }
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    std::fs::write(&path, salt)?;
    Ok(salt)
}

pub fn derive_encryption_key(
    passphrase: &str,
    config: &Argon2Config,
) -> Result<Zeroizing<[u8; 32]>> {
    let salt = load_or_create_salt()?;
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(config.mem_cost, config.time_cost, config.lanes, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

pub fn resolve_passphrase(cli_passphrase: Option<String>) -> Result<Option<Zeroizing<String>>> {
    if let Some(p) = cli_passphrase {
        if !p.is_empty() {
            return Ok(Some(Zeroizing::new(p)));
        }
    }
    if let Ok(val) = std::env::var("DSTORE_PASSPHRASE") {
        if !val.is_empty() {
            return Ok(Some(Zeroizing::new(val)));
        }
    }
    if let Ok(path) = std::env::var("DSTORE_PASSPHRASE_FILE") {
        let val = std::fs::read_to_string(&path)
            .context("DSTORE_PASSPHRASE_FILE: cannot read")?;
        let trimmed = val.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Some(Zeroizing::new(trimmed)));
        }
    }
    // Interactive prompt is available via the rpassword crate
    // Enable with `rpassword::read_password_from_tty(...)` if desired
    Ok(None)
}

pub fn load_or_create_keypair() -> Result<ed25519_dalek::SigningKey> {
    let path = config_dir()?.join("node_key");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            anyhow::bail!("invalid node key file (expected 32 bytes)");
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Ok(ed25519_dalek::SigningKey::from_bytes(&secret))
    } else {
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let kp = ed25519_dalek::SigningKey::from_bytes(&secret);
        save_key_secure(&path, &secret)?;
        Ok(kp)
    }
}

#[cfg(unix)]
fn save_key_secure(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn save_key_secure(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}
