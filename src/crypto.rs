use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use sha2::{Digest, Sha256};
use aes::cipher::generic_array::GenericArray;

type AesCtr = ctr::Ctr128BE<Aes256>;

/// Derives a 256-bit AES key from vault password, file password, and creation time.
/// All inputs are strings.
pub fn derive_key(vault_pw: &str, file_pw: &str, creation_time: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(vault_pw.as_bytes());
    hasher.update(file_pw.as_bytes());
    hasher.update(creation_time.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypts data with AES-CTR using derived key.
/// Returns a tuple of (nonce, ciphertext).
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(&nonce);

    let mut cipher = AesCtr::new(key, nonce_ga);
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);

    (nonce.to_vec(), buffer)
}

/// Decrypts data with AES-CTR using key and nonce.
/// Returns the plaintext.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let mut cipher = AesCtr::new(key.into(), nonce.into());
    let mut buffer = ciphertext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}
