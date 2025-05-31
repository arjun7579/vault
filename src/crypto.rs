use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a random 16-byte salt
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive 32-byte master key from password and salt using Argon2id
pub fn derive_key_from_password(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let argon2 = Argon2::default();

    let password_bytes = password.as_bytes();
    let mut key = [0u8; 32];

    // Argon2 password hash output as raw bytes (not encoded)
    // Use password hash as key material by hashing the password with salt
    // We can do this by password hashing and then extracting bytes, but argon2 crate returns PasswordHash struct

    // Instead, we use low-level function to fill key directly (recommended for key derivation)

    use argon2::password_hash::{PasswordHasher as _, SaltString};
    let salt_str = SaltString::b64_encode(salt).expect("Failed to encode salt");

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password_bytes, salt_str.as_ref(), &mut output)
        .expect("Key derivation failed");

    key.copy_from_slice(&output);
    key
}

/// Derive per-file key from master key + filename (SHA256(master_key || filename))
pub fn derive_file_key(master_key: &[u8; 32], filename: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key);
    hasher.update(filename.as_bytes());
    let result = hasher.finalize();
    let mut file_key = [0u8; 32];
    file_key.copy_from_slice(&result);
    file_key
}

/// Encrypt plaintext with key using AES-256-GCM
/// Returns nonce + ciphertext concatenated
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key.into());

    // 12-byte random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    // Return nonce || ciphertext
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt ciphertext with key using AES-256-GCM
/// Expects nonce (12 bytes) prepended to ciphertext
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    if ciphertext.len() < 12 {
        return Err(aes_gcm::Error);
    }
    let cipher = Aes256Gcm::new(key.into());

    let (nonce_bytes, ciphertext) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
}
