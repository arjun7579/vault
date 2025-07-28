use aes_gcm::{
    aead::{Aead, KeyInit},
    AeadCore, // FIX 2: Import the trait that provides `generate_nonce`
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256};

/// Hash the vault’s master password with Argon2id.
pub fn hash_master_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hashing failed")
        .to_string()
}

/// Verify the vault’s master password against the stored Argon2 hash.
pub fn verify_master_password(password: &str, full_hash: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(full_hash) {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        false
    }
}

/// Deterministically derive a 256‑bit file key.
pub fn derive_file_key(vault_pw: &str, file_pw: &str, creation_time: &str) -> [u8; 32] {
    // FIX 1: Use `default()` instead of `new()`
    let mut hasher = Sha256::default();
    hasher.update(vault_pw.as_bytes());
    hasher.update(file_pw.as_bytes());
    hasher.update(creation_time.as_bytes());
    hasher.finalize().into()
}

/// Encrypt `plaintext` with AES‑256‑GCM.
pub fn encrypt(
    plaintext: &[u8],
    key_bytes: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
    // FIX 3: Use the concrete type `Aes256Gcm` instead of the generic `Key`
    let cipher = Aes256Gcm::new(key_bytes.into());

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt AES‑256‑GCM `(nonce, ciphertext)` back to plaintext.
pub fn decrypt(
    ciphertext: &[u8],
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}