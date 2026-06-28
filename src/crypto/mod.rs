mod key;
mod encrypt;

pub use key::{
    derive_encryption_key, load_or_create_keypair, config_dir, resolve_passphrase, Argon2Config,
};
pub use encrypt::{
    encrypt_chunk, decrypt_chunk, EncryptedChunk, keyed_content_address, zeroize_buf,
};
