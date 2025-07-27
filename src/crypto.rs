// src/crypto.rs
use aes_gcm::{
    aead::{Aead, KeyInit},
    AeadCore, Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256};

/// Hashes the master password with Argon2.
pub fn hash_master_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hashing failed")
        .to_string()
}

/// Verifies the master password against the stored Argon2 hash.
pub fn verify_master_password(password: &str, full_hash: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(full_hash) {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        false
    }
}

/// Derives a deterministic 256-bit file key.
pub fn derive_file_key(vault_pw: &str, file_pw: &str, creation_time: &str) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(vault_pw.as_bytes());
    hasher.update(file_pw.as_bytes());
    hasher.update(creation_time.as_bytes());
    hasher.finalize().into()
}

/// Encrypts plaintext with AES-256-GCM.
pub fn encrypt(
    plaintext: &[u8],
    key_bytes: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypts ciphertext with AES-256-GCM.
pub fn decrypt(
    ciphertext: &[u8],
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}