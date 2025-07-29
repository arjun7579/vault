use crate::{compress, crypto};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    path::{Path},
};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument, warn};
use zeroize::{Zeroize, Zeroizing};

const VAULT_EXT: &str = "vlt";
const TEMP_EXT: &str = "tmp";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LogEntry {
    timestamp: String,
    action: String,
    filename: String,
    status: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct Vault {
    password_hash: String,
    files: HashMap<String, VaultEntry>,
    log: Vec<LogEntry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            files: HashMap::new(),
            log: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct VaultEntry {
    compression_algo: compress::Algorithm,
    data: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
    hash: Vec<u8>,
}

fn load_vault(path: &Path) -> io::Result<Vault> {
    if path.exists() {
        let data = fs::read(path)?;
        bincode::deserialize(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to deserialize vault: {}", e)))
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "Vault file not found."))
    }
}

#[instrument(skip(vault), fields(path = %path.display()))]
fn save_vault(path: &Path, vault: &Vault) -> io::Result<()> {
    let temp_path = path.with_extension(TEMP_EXT);
    let data = bincode::serialize(vault)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize vault: {}", e)))?;
    fs::write(&temp_path, &data)?;
    fs::rename(&temp_path, path)?;
    info!("Vault saved successfully.");
    Ok(())
}

#[instrument(skip_all)]
fn get_and_verify_vault_password(vault: &Vault) -> Option<Zeroizing<String>> {
    if vault.password_hash.is_empty() {
        error!("Vault appears to be new or corrupted (no password hash found).");
        return None;
    }
    for i in 0..3 {
        let mut password = Zeroizing::new(prompt_password("Vault password: ").ok()?);
        if crypto::verify_master_password(&password, &vault.password_hash) {
            info!("Vault password verified.");
            return Some(password);
        } else {
            warn!(attempt = i + 1, "Incorrect password attempt.");
            password.zeroize();
        }
    }
    error!("Too many incorrect password attempts.");
    None
}

#[instrument(skip(dir, name))]
pub fn create_vault(dir: &Path, name: &str) -> io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));
    if vault_path.exists() {
        error!(path = %vault_path.display(), "A vault with this name already exists.");
        return Ok(());
    }
    let mut pw = Zeroizing::new(prompt_password("Create vault password: ").unwrap());
    let hash = crypto::hash_master_password(&pw);
    pw.zeroize();

    let mut vault = Vault::default();
    vault.password_hash = hash;
    vault.log.push(LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: "CREATE".to_string(),
        filename: name.to_string(),
        status: "Success".to_string(),
    });
    
    save_vault(&vault_path, &vault)?;
    info!(path = %vault_path.display(), "Vault created successfully.");
    Ok(())
}

#[instrument(skip(file_path, vault_path, algorithm))]
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

    let mut hasher = Sha256::default();
    let compressed_data;
    {
        let source_file = File::open(file_path)?;
        let file_size = source_file.metadata()?.len();
        info!(source_file = %file_path.display(), size = file_size, "Starting file processing stream.");
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("=>-"),
        );
        let progress_reader = pb.wrap_read(source_file);
        let mut tee_reader = TeeReader::new(progress_reader, &mut hasher);
        let mut compressed_reader = compress::compress_stream(&mut tee_reader, algorithm);
        let mut data_buf = Vec::new();
        compressed_reader.read_to_end(&mut data_buf)?;
        compressed_data = data_buf;
        pb.finish_with_message("Read and compressed.");
    }
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
    vault.log.push(LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: "EXTRACT".to_string(),
        filename: file_name.to_string(),
        status: "Success".to_string(),
    });
    save_vault(vault_path, &vault)?;
    info!(file_name, status, "File operation successful.");
    Ok(())
}

#[instrument(skip(file_name, vault_path))]
pub fn extract_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());
    let entry = match vault.files.get(file_name) {
        Some(e) => e,
        None => {
            error!(file_name, "File not found in vault.");
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));
    let decrypted_data = crypto::decrypt(&entry.data, &key, &entry.nonce)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {}", e)))?;
    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decrypted_size = decrypted_data.len() as u64;
    let decrypted_reader = Cursor::new(decrypted_data);
    info!(file_name, size = decrypted_size, "Extracting file.");
    let pb = ProgressBar::new(decrypted_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("=>-"),
    );
    let progress_reader = pb.wrap_read(decrypted_reader);
    let mut decompressed_reader = compress::decompress_stream(progress_reader, entry.compression_algo);
    let mut dest_file = File::create(file_name)?;
    io::copy(&mut decompressed_reader, &mut dest_file)?;
    pb.finish_with_message("Decompressed and written to disk.");

    vault.log.push(LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: "EXTRACT".to_string(),
        filename: file_name.to_string(),
        status: "Success".to_string(),
    });
    save_vault(vault_path, &vault)?;
    
    info!(file_name, "File extracted successfully.");
    Ok(())
}

#[instrument(skip(file_name, vault_path))]
pub fn remove_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };

    let entry = match vault.files.get(file_name) {
        Some(e) => e.clone(),
        None => {
            error!(file_name, "File not found for removal.");
            return Ok(());
        }
    };

    info!(file_name, "Verifying file password before deletion.");
    let mut file_pw = Zeroizing::new(prompt_password("Enter password for file to be deleted: ").unwrap());

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));

    if crypto::decrypt(&entry.data, &key, &entry.nonce).is_err() {
        error!(file_name, "Incorrect file password. Deletion aborted.");
        key.zeroize();
        vault_pw.zeroize();
        file_pw.zeroize();
        return Ok(());
    }

    info!(file_name, "File password verified. Proceeding with deletion.");
    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        info!(file_name, "File removed successfully.");
    } else {
        error!(file_name, "File was present but could not be removed.");
    }
    vault.log.push(LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: "REMOVE".to_string(),
        filename: file_name.to_string(),
        status: "Success".to_string(),
    });
    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();
    Ok(())
}

#[instrument(skip(file_name, vault_path, out_path))]
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
            error!(file_name, "File not found for remex.");
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));
    let decrypted_data = match crypto::decrypt(&entry.data, &key, &entry.nonce) {
        Ok(pt) => pt,
        Err(e) => {
            error!("Decryption failed: {}. Aborting remex.", e);
            return Ok(());
        }
    };
    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decrypted_reader = Cursor::new(decrypted_data);
    let mut decompressed_reader = compress::decompress_stream(decrypted_reader, entry.compression_algo);
    let mut dest_file = File::create(out_path)?;
    io::copy(&mut decompressed_reader, &mut dest_file)?;

    vault.files.remove(file_name);
    vault.log.push(LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: "REMEX".to_string(),
        filename: file_name.to_string(),
        status: "Success".to_string(),
    });
    save_vault(vault_path, &vault)?;
    info!(file_name, output_path = %out_path.display(), "File extracted and removed successfully.");
    Ok(())
}

#[instrument(skip(vault_path))]
pub fn check_vault(vault_path: &Path) -> io::Result<()> {
    let vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };

    println!("Vault master password OK.");
    let mut tampered_files = 0;

    let mut dummy_file_pw = Zeroizing::new(String::from("dummy_check_password"));

    for (file_name, entry) in &vault.files {
        let mut key = Zeroizing::new(crypto::derive_file_key(
            &vault_pw,
            &dummy_file_pw,
            &entry.created_at,
        ));

        if crypto::decrypt(&entry.data, &key, &entry.nonce).is_err() {
            println!("[FAIL] File '{}' appears to be tampered with or corrupt.", file_name);
            tampered_files += 1;
        } else {
            println!("[OK]   File '{}' integrity check passed.", file_name);
        }
        key.zeroize();
    }
    dummy_file_pw.zeroize();
    vault_pw.zeroize();

    if tampered_files == 0 {
        println!("\nVault integrity check completed. All {} files are OK.", vault.files.len());
    } else {
        println!("\nVault integrity check completed. Found {} corrupted file(s).", tampered_files);
    }

    Ok(())
}

#[instrument(skip(vault_path))]
pub fn list_files(vault_path: &Path) -> io::Result<()> {
    let vault = load_vault(vault_path)?;
    if get_and_verify_vault_password(&vault).is_none() {
        return Ok(());
    }
    info!("Listing files in vault.");
    let mut files: Vec<_> = vault.files.keys().collect();
    files.sort();

    println!("\nFiles in vault '{}':", vault_path.display());
    if files.is_empty() {
        println!("  (No files)");
    } else {
        for file_name in files {
            println!("  - {}", file_name);
        }
    }
    Ok(())
}

#[instrument(skip(vault_path))]
pub fn delete_vault(vault_path: &Path) -> io::Result<()> {
    let vault = match load_vault(vault_path) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to load vault for deletion: {}", e);
            return Ok(());
        }
    };

    if get_and_verify_vault_password(&vault).is_none() {
        error!("Password verification failed. Vault deletion aborted.");
        return Ok(());
    }

    let vault_name = vault_path.file_stem().unwrap_or_default().to_string_lossy();
    warn!(
        path = %vault_path.display(),
        "You are about to permanently delete this vault and all its contents."
    );
    print!("This action is irreversible. To confirm, type the vault's name ('{}'): ", vault_name);
    io::stdout().flush()?;

    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;

    if confirmation.trim() == vault_name {
        fs::remove_file(vault_path)?;
        let log_path = vault_path.with_extension("log");
        if log_path.exists() {
            let _ = fs::remove_file(log_path);
        }
        info!(path = %vault_path.display(), "Vault has been permanently deleted.");
    } else {
        info!("Confirmation failed. Vault deletion aborted.");
    }

    Ok(())
}


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

#[instrument(skip(vault_path))]
pub fn log_vault(vault_path: &Path) -> io::Result<()> {
    let vault = load_vault(vault_path)?;
    if get_and_verify_vault_password(&vault).is_none() {
        return Ok(());
    }
    info!("Displaying vault activity log.");
    println!("\n--- Activity Log for '{}' ---", vault_path.display());
    if vault.log.is_empty() {
        println!("(No activities logged)");
    } else {
        for entry in &vault.log {
            let label = if entry.action == "CREATE" { "Vault" } else { "File" };
            println!("[{}] - {:<10} | {}: {:<20} | Status: {}",
                entry.timestamp,
                entry.action,
                label,
                entry.filename,
                entry.status
            );
        }
    }
    Ok(())
}