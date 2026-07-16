use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub fn encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), data).unwrap_or_default()
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).unwrap_or_default()
}
