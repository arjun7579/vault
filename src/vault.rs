use crate::{compress, crypto, log::log_op};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use chrono::Utc;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};

const VAULT_EXT: &str = "vlt";

#[derive(Serialize, Deserialize)]
struct VaultEntry {
    data: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    files: HashMap<String, VaultEntry>,
}

fn log_path(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.to_path_buf();
    path.set_extension("log");
    path
}

fn load_vault(path: &Path) -> std::io::Result<Vault> {
    if path.exists() {
        let data = fs::read(path)?;
        Ok(bincode::deserialize(&data).unwrap_or_default())
    } else {
        Ok(Vault::default())
    }
}

fn save_vault(path: &Path, vault: &Vault) -> std::io::Result<()> {
    let data = bincode::serialize(vault).unwrap();
    fs::write(path, data)?;
    Ok(())
}

pub fn create_vault(dir: &Path, name: &str) -> std::io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));
    if vault_path.exists() {
        eprintln!("Vault already exists.");
        return Ok(());
    }

    save_vault(&vault_path, &Vault::default())?;
    fs::write(log_path(&vault_path), b"Vault created\n")?;
    println!("Vault created: {}", vault_path.display());
    Ok(())
}

pub fn add_file(file_path: &Path, vault_path: &Path) -> std::io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let vault_pw = prompt_password("Vault password: ").unwrap();
    let file_pw = prompt_password("File password: ").unwrap();
    let created_at = Utc::now().to_rfc3339();

    let mut file_data = Vec::new();
    File::open(file_path)?.read_to_end(&mut file_data)?;
    let compressed = compress::compress_f(&file_data)?;
    let key = crypto::derive_key(&vault_pw, &file_pw, &created_at);
    let (nonce, encrypted) = crypto::encrypt(&compressed, &key);

    let mut vault = load_vault(vault_path)?;
    vault.files.insert(file_name.clone(), VaultEntry { data: encrypted, nonce, created_at: created_at.clone() });
    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("ADD: {} @ {}", file_name, created_at))?;
    println!("File added.");
    Ok(())
}

pub fn extract_file(file_name: &str, vault_path: &Path) -> std::io::Result<()> {
    let vault_pw = prompt_password("Vault password: ").unwrap();
    let file_pw = prompt_password("File password: ").unwrap();

    let vault = load_vault(vault_path)?;
    let entry = match vault.files.get(file_name) {
        Some(e) => e,
        None => {
            eprintln!("File not found in vault.");
            return Ok(());
        }
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(file_name, decompressed)?;
    log_op(&log_path(vault_path), &format!("EXTRACT: {}", file_name))?;
    println!("File extracted: {}", file_name);
    Ok(())
}

pub fn remove_file(file_name: &str, vault_path: &Path) -> std::io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        log_op(&log_path(vault_path), &format!("REMOVE: {}", file_name))?;
        println!("File removed.");
    } else {
        eprintln!("File not found.");
    }
    Ok(())
}

pub fn remex_file(file_name: &str, vault_path: &Path, out_path: &Path) -> std::io::Result<()> {
    let vault_pw = prompt_password("Vault password: ").unwrap();
    let file_pw = prompt_password("File password: ").unwrap();

    let mut vault = load_vault(vault_path)?;
    let entry = match vault.files.remove(file_name) {
        Some(e) => e,
        None => {
            eprintln!("File not found in vault.");
            return Ok(());
        }
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(out_path, decompressed)?;
    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("REMEX: {} -> {}", file_name, out_path.display()))?;
    println!("File extracted and removed.");
    Ok(())
}