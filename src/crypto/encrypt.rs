use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

pub struct EncryptedChunk {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_chunk(key: &Zeroizing<[u8; 32]>, plaintext: &[u8]) -> EncryptedChunk {
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failed");
    EncryptedChunk {
        nonce: nonce_bytes,
        ciphertext,
    }
}

pub fn decrypt_chunk(key: &Zeroizing<[u8; 32]>, enc: &EncryptedChunk) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let nonce = Nonce::from(enc.nonce);
    cipher.decrypt(&nonce, enc.ciphertext.as_ref()).ok()
}
