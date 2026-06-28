use anyhow::{Context, Result};
use argon2::Argon2;
use std::path::PathBuf;
use zeroize::Zeroizing;

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

pub fn derive_encryption_key(passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let salt = load_or_create_salt()?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
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
