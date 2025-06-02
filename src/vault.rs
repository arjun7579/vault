use crate::{compress, crypto, log::log_op};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use chrono::Utc;
use colored::*;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const VAULT_EXT: &str = "vlt";
const MAX_ATTEMPTS: usize = 3;

#[derive(Serialize, Deserialize)]
struct VaultEntry {
    data: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
    hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    files: HashMap<String, VaultEntry>,
    password_hash: Option<Vec<u8>>,
}

fn log_path(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.to_path_buf();
    path.set_extension("log");
    path
}

fn load_vault(path: &Path) -> io::Result<Vault> {
    if path.exists() {
        let data = fs::read(path)?;
        Ok(bincode::deserialize(&data).unwrap_or_default())
    } else {
        Ok(Vault::default())
    }
}

fn save_vault(path: &Path, vault: &Vault) -> io::Result<()> {
    let data = bincode::serialize(vault).unwrap();
    fs::write(path, data)
}

fn hash_password(password: &str) -> Vec<u8> {
    Sha256::digest(password.as_bytes()).to_vec()
}

fn file_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn prompt_password_retry(prompt: &str) -> Option<String> {
    for _ in 0..MAX_ATTEMPTS {
        if let Ok(pw) = prompt_password(prompt) {
            if !pw.is_empty() {
                return Some(pw);
            }
            eprintln!("{}", "Password cannot be empty.".red());
        }
    }
    eprintln!("{}", "Too many failed attempts.".red());
    None
}

fn verify_password(stored: &[u8]) -> bool {
    for _ in 0..MAX_ATTEMPTS {
        if let Ok(pw) = prompt_password("Vault password: ") {
            if hash_password(&pw) == stored {
                return true;
            }
            eprintln!("{}", "Incorrect password.".red());
        }
    }
    false
}

pub fn create_vault(dir: &Path, name: &str) -> io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));
    let target_name = format!("{}.{}", name, VAULT_EXT);

    // Check all files on disk for existing vault name
    let duplicate_exists = WalkDir::new("/")
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry.file_name()
                .to_str()
                .map_or(false, |s| s == target_name)
        });

    if duplicate_exists {
        eprintln!("{}", "A vault with this name already exists.".red());
        return Ok(());
    }

    let pw = match prompt_password_retry("Create vault password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut vault = Vault::default();
    vault.password_hash = Some(hash_password(&pw));
    save_vault(&vault_path, &vault)?;
    fs::write(log_path(&vault_path), b"Vault created\n")?;
    println!("{}", format!("Vault created: {}", vault_path.display()).green());
    Ok(())
}

pub fn add_file(file_path: &Path, vault_path: &Path) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let file_pw = match prompt_password_retry("File password: ") {
        Some(p) => p,
        None => return Ok(()),
    };
    let created_at = Utc::now().to_rfc3339();

    let mut file_data = Vec::new();
    File::open(file_path)?.read_to_end(&mut file_data)?;
    let hash = file_hash(&file_data);

    let mut vault = load_vault(vault_path)?;
    if let Some(ref pw_hash) = vault.password_hash {
        if !verify_password(pw_hash) {
            return Ok(());
        }
    }

    let vault_pw = match prompt_password_retry("Vault password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &created_at);
    let compressed = compress::compress_f(&file_data)?;
    let (nonce, encrypted) = crypto::encrypt(&compressed, &key);

    let status = if let Some(entry) = vault.files.get(&file_name) {
        if entry.hash != hash {
            "MODIFIED"
        } else {
            "UNCHANGED"
        }
    } else {
        "ADDED"
    };

    vault.files.insert(
        file_name.clone(),
        VaultEntry {
            data: encrypted,
            nonce,
            created_at: created_at.clone(),
            hash,
        },
    );
    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("{}: {} @ {}", status, file_name, created_at))?;
    println!("{}", format!("File {}.", status.to_lowercase()).cyan());
    Ok(())
}

pub fn extract_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let file_pw = match prompt_password_retry("File password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let vault = load_vault(vault_path)?;
    if let Some(ref pw_hash) = vault.password_hash {
        if !verify_password(pw_hash) {
            return Ok(());
        }
    }

    let entry = match vault.files.get(file_name) {
        Some(e) => e,
        None => {
            eprintln!("{}", "File not found in vault.".red());
            return Ok(());
        }
    };

    let vault_pw = match prompt_password_retry("Vault password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
    let decompressed = compress::decompress_f(&decrypted)?;
    fs::write(file_name, decompressed)?;
    log_op(&log_path(vault_path), &format!("EXTRACT: {}", file_name))?;
    println!("{}", format!("File extracted: {}", file_name).green());
    Ok(())
}

pub fn remove_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    if let Some(ref pw_hash) = vault.password_hash {
        if !verify_password(pw_hash) {
            return Ok(());
        }
    }

    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        log_op(&log_path(vault_path), &format!("REMOVE: {}", file_name))?;
        println!("{}", "File removed.".yellow());
    } else {
        eprintln!("{}", "File not found.".red());
    }
    Ok(())
}

pub fn remex_file(file_name: &str, vault_path: &Path, out_path: &Path) -> io::Result<()> {
    let file_pw = match prompt_password_retry("File password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut vault = load_vault(vault_path)?;
    if let Some(ref pw_hash) = vault.password_hash {
        if !verify_password(pw_hash) {
            return Ok(());
        }
    }

    let entry = match vault.files.remove(file_name) {
        Some(e) => e,
        None => {
            eprintln!("{}", "File not found in vault.".red());
            return Ok(());
        }
    };

    let vault_pw = match prompt_password_retry("Vault password: ") {
        Some(p) => p,
        None => return Ok(()),
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(out_path, decompressed)?;
    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("REMEX: {} -> {}", file_name, out_path.display()))?;
    println!("{}", "File extracted and removed.".green());
    Ok(())
}
