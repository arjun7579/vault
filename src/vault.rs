// src/vault.rs

use crate::{compress, crypto};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use chrono::Utc;
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
// REFACTOR: Use tracing for structured logging. We will add this in the next step.
// For now, we will use standard print macros.

const VAULT_EXT: &str = "vlt";
const TEMP_EXT: &str = "tmp"; // For atomic writes

#[derive(Serialize, Deserialize, Clone)]
struct Vault {
    password_hash: String,
    files: HashMap<String, VaultEntry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            files: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct VaultEntry {
    // REFACTOR: Store the compression algorithm for this file.
    compression_algo: compress::Algorithm,
    data: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
    hash: Vec<u8>,
}

fn load_vault(path: &Path) -> io::Result<Vault> {
    if path.exists() {
        let data = fs::read(path)?;
        let vault = bincode::deserialize(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to deserialize vault: {}", e)))?;
        Ok(vault)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "Vault file not found."))
    }
}

// REFACTOR: `save_vault` implements atomic writes.
fn save_vault(path: &Path, vault: &Vault) -> io::Result<()> {
    let temp_path = path.with_extension(TEMP_EXT);

    let data = bincode::serialize(vault)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize vault: {}", e)))?;

    fs::write(&temp_path, &data)?;
    fs::rename(&temp_path, path)?;

    // Using println for now, will be replaced by tracing::info!
    // println!("Vault saved successfully to: {}", path.display());
    Ok(())
}

fn get_and_verify_vault_password(vault: &Vault) -> Option<Zeroizing<String>> {
    if vault.password_hash.is_empty() {
        println!("Error: Vault has no password hash. It may be new or corrupted.");
        return None;
    }
    for _ in 0..3 {
        let mut password = Zeroizing::new(prompt_password("Vault password: ").ok()?);
        if crypto::verify_master_password(&password, &vault.password_hash) {
            return Some(password);
        } else {
            println!("Incorrect password.");
            password.zeroize();
        }
    }
    println!("Error: Too many incorrect password attempts.");
    None
}

fn file_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// REFACTOR: `create_vault` is updated for the portable model.
pub fn create_vault(dir: &Path, name: &str) -> io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));

    if vault_path.exists() {
        println!("Error: A vault with this name already exists in this directory.");
        return Ok(());
    }

    let mut pw = Zeroizing::new(prompt_password("Create vault password: ").unwrap());
    let hash = crypto::hash_master_password(&pw);
    pw.zeroize();

    let vault = Vault {
        password_hash: hash,
        files: HashMap::new(),
    };

    save_vault(&vault_path, &vault)?;
    println!("Vault created: {}", vault_path.display());
    Ok(())
}

// REFACTOR: `add_file` is updated for streaming and error handling.
pub fn add_file(
    file_path: &Path,
    vault_path: &Path,
    algorithm: compress::Algorithm,
) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let mut vault = load_vault(vault_path)?;

    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());
    let created_at = Utc::now().to_rfc3339();

    // --- FIX: Separate the reading and finalizing stages completely ---
    let mut hasher = Sha256::default();
    let compressed_data;

    // -- Stage 1: Read the stream and update the hasher --
    { // This scope ensures the readers (and the borrow on hasher) are dropped.
        let source_file = File::open(file_path)?;
        let mut tee_reader = TeeReader::new(source_file, &mut hasher);
        let mut compressed_reader = compress::compress_stream(&mut tee_reader, algorithm);
        
        let mut data_buf = Vec::new();
        compressed_reader.read_to_end(&mut data_buf)?;
        compressed_data = data_buf;
    } // `tee_reader` and `compressed_reader` are dropped here. The borrow on `hasher` ends.

    // -- Stage 2: Finalize the hash --
    // Now that `hasher` is no longer borrowed, we can safely take ownership of it.
    let hash = hasher.finalize().to_vec();

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &created_at));
    
    let (nonce, encrypted) = crypto::encrypt(&compressed_data, &key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;

    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let status = if vault.files.contains_key(&file_name) { "MODIFIED" } else { "ADDED" };

    vault.files.insert(
        file_name.clone(),
        VaultEntry {
            compression_algo: algorithm,
            data: encrypted,
            nonce,
            created_at,
            hash,
        },
    );

    save_vault(vault_path, &vault)?;
    println!("File {}: {}", status.to_lowercase(), file_name);
    Ok(())
}
// REFACTOR: `extract_file` is updated for streaming and error handling.
pub fn extract_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());

    let entry = match vault.files.get(file_name) {
        Some(e) => e,
        None => {
            println!("Error: File not found in vault.");
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));
    
    // FIX: Manually map the crypto error to io::Error.
    let decrypted_data = crypto::decrypt(&entry.data, &key, &entry.nonce)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed (tampering or wrong password?): {}", e)))?;

    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decrypted_reader = io::Cursor::new(decrypted_data);
    let mut decompressed_reader = compress::decompress_stream(decrypted_reader, entry.compression_algo);

    let mut dest_file = File::create(file_name)?;
    io::copy(&mut decompressed_reader, &mut dest_file)?;

    println!("File extracted: {}", file_name);
    Ok(())
}

// REFACTOR: `remove_file` is updated.
pub fn remove_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    if get_and_verify_vault_password(&vault).is_none() {
        return Ok(());
    }

    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        println!("File removed: {}", file_name);
    } else {
        println!("Error: File not found for removal.");
    }
    Ok(())
}

// REFACTOR: The final, complete `remex_file` function.
pub fn remex_file(file_name: &str, vault_path: &Path, out_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());

    let entry = match vault.files.get(file_name).cloned() {
        Some(e) => e,
        None => {
            println!("Error: File not found for remex.");
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));
    
    let decrypted_data = match crypto::decrypt(&entry.data, &key, &entry.nonce) {
        Ok(pt) => pt,
        Err(e) => {
            println!("Error: Decryption failed (tampering or wrong password?): {}", e);
            return Ok(());
        }
    };
    
    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decrypted_reader = io::Cursor::new(decrypted_data);
    let mut decompressed_reader = compress::decompress_stream(decrypted_reader, entry.compression_algo);

    let mut dest_file = File::create(out_path)?;
    io::copy(&mut decompressed_reader, &mut dest_file)?;

    // Now that extraction was successful, commit the removal.
    vault.files.remove(file_name);
    save_vault(vault_path, &vault)?;

    println!("File extracted to {} and removed from vault.", out_path.display());
    Ok(())
}


// Helper struct for on-the-fly hashing of a stream.
struct TeeReader<'a, R: Read> {
    reader: R,
    hasher: &'a mut Sha256,
}

impl<'a, R: Read> TeeReader<'a, R> {
    fn new(reader: R, hasher: &'a mut Sha256) -> Self {
        Self { reader, hasher }
    }
}

impl<'a, R: Read> Read for TeeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.reader.read(buf)?;
        if bytes_read > 0 {
            self.hasher.update(&buf[..bytes_read]);
        }
        Ok(bytes_read)
    }
}