use crate::{compress, crypto, log::log_op};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use chrono::Utc;
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const VAULT_EXT: &str = "vlt";

// NEW: Vault struct now stores the master password hash directly.
#[derive(Serialize, Deserialize)]
struct Vault {
    password_hash: String, // Stores the full Argon2 hash string
    files: HashMap<String, VaultEntry>,
}

// NEW: The default vault is now one with an empty hash and no files.
impl Default for Vault {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            files: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct VaultEntry {
    data: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
    hash: Vec<u8>,
}

fn log_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("log")
}

fn load_vault(path: &Path) -> io::Result<Vault> {
    if path.exists() {
        let data = fs::read(path)?;
        // Use unwrap_or_default for robustness against empty/corrupt files
        Ok(bincode::deserialize(&data).unwrap_or_default())
    } else {
        // If the file doesn't exist, it's an error, not a new vault.
        // `create_vault` is the explicit way to make a new one.
        Err(io::Error::new(io::ErrorKind::NotFound, "Vault file not found."))
    }
}

fn save_vault(path: &Path, vault: &Vault) -> io::Result<()> {
    let data = bincode::serialize(vault)?;
    fs::write(path, data)
}

// REMOVED: All functions related to /etc are no longer needed.

// NEW: A single function to prompt for and verify the master password.
fn get_and_verify_vault_password(vault: &Vault) -> Option<Zeroizing<String>> {
    if vault.password_hash.is_empty() {
        // This case handles a newly created but not yet saved vault, or a corrupt one.
        return None;
    }
    for _ in 0..3 {
        // Use Zeroizing to securely handle the password in memory.
        let mut password = Zeroizing::new(prompt_password("Vault password: ").ok()?);
        if crypto::verify_master_password(&password, &vault.password_hash) {
            return Some(password);
        } else {
            print_color("Incorrect password.\n", Color::Red);
            password.zeroize(); // Securely wipe incorrect password attempt.
        }
    }
    None
}

fn file_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// NEW: `create_vault` is heavily modified for the portable model.
pub fn create_vault(dir: &Path, name: &str) -> io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));

    if vault_path.exists() {
        print_color("A vault with this name already exists in this directory.\n", Color::Red);
        return Ok(());
    }

    let mut pw = Zeroizing::new(prompt_password("Create vault password: ").unwrap());
    let hash = crypto::hash_master_password(&pw);
    pw.zeroize(); // Wipe password from memory immediately.

    let vault = Vault {
        password_hash: hash,
        files: HashMap::new(),
    };

    save_vault(&vault_path, &vault)?;
    fs::write(log_path(&vault_path), b"Vault created\n")?;
    print_color(&format!("Vault created: {}\n", vault_path.display()), Color::Green);
    Ok(())
}

// NEW: `add_file` is updated for the new password flow and error handling.
pub fn add_file(file_path: &Path, vault_path: &Path) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let mut vault = load_vault(vault_path)?;

    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());
    let created_at = Utc::now().to_rfc3339();

    let file_data = fs::read(file_path)?;
    let compressed = compress::compress_f(&file_data)?;

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &created_at));
    
    // Handle potential encryption error
    let (nonce, encrypted) = match crypto::encrypt(&compressed, &key) {
        Ok(result) => result,
        Err(_) => {
            print_color("Fatal: File encryption failed.\n", Color::Red);
            return Ok(());
        }
    };
    let hash = file_hash(&file_data);

    // Wipe sensitive data as soon as it's no longer needed.
    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let status = if let Some(entry) = vault.files.get(&file_name) {
        if entry.hash != hash { "MODIFIED" } else { "UNCHANGED" }
    } else {
        "ADDED"
    };

    vault.files.insert(file_name.clone(), VaultEntry {
        data: encrypted,
        nonce,
        created_at: created_at.clone(),
        hash,
    });

    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("{}: {} @ {}", status, file_name, created_at))?;
    print_color(&format!("File {}.\n", status.to_lowercase()), Color::Green);
    Ok(())
}

// NEW: `extract_file` is updated for the new password flow and error handling.
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
            print_color("File not found.\n", Color::Red);
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));

    let decrypted = match crypto::decrypt(&entry.data, &key, &entry.nonce) {
        Ok(pt) => pt,
        Err(_) => {
            print_color("Decryption failed! The password may be wrong or the data has been tampered with.\n", Color::Red);
            return Ok(());
        }
    };

    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(file_name, decompressed)?;
    log_op(&log_path(vault_path), &format!("EXTRACT: {}", file_name))?;
    print_color(&format!("File extracted: {}\n", file_name), Color::Green);
    Ok(())
}

// NEW: `remove_file` is updated.
pub fn remove_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    // We need the password to authorize the removal.
    if get_and_verify_vault_password(&vault).is_none() {
        return Ok(());
    }

    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        log_op(&log_path(vault_path), &format!("REMOVE: {}", file_name))?;
        print_color("File removed.\n", Color::Yellow);
    } else {
        print_color("File not found.\n", Color::Red);
    }
    Ok(())
}

// NEW: `remex_file` is updated.
pub fn remex_file(file_name: &str, vault_path: &Path, out_path: &Path) -> io::Result<()> {
    let mut vault = load_vault(vault_path)?;
    let mut vault_pw = match get_and_verify_vault_password(&vault) {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut file_pw = Zeroizing::new(prompt_password("File password: ").unwrap());

    let entry = match vault.files.remove(file_name) {
        Some(e) => e,
        None => {
            print_color("File not found.\n", Color::Red);
            return Ok(());
        }
    };

    let mut key = Zeroizing::new(crypto::derive_file_key(&vault_pw, &file_pw, &entry.created_at));
    
    let decrypted = match crypto::decrypt(&entry.data, &key, &entry.nonce) {
        Ok(pt) => pt,
        Err(_) => {
            print_color("Decryption failed! The password may be wrong or the data has been tampered with. Re-adding file to vault.\n", Color::Red);
            // Since we already removed the entry, put it back on failure.
            vault.files.insert(file_name.to_string(), entry);
            save_vault(vault_path, &vault)?;
            return Ok(());
        }
    };

    key.zeroize();
    vault_pw.zeroize();
    file_pw.zeroize();

    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(out_path, decompressed)?;
    save_vault(vault_path, &vault)?;
    log_op(&log_path(vault_path), &format!("REMEX: {} -> {}", file_name, out_path.display()))?;
    print_color("File extracted and removed.\n", Color::Yellow);
    Ok(())
}

fn print_color(msg: &str, color: Color) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(color))).unwrap();
    write!(&mut stdout, "{}", msg).unwrap();
    stdout.reset().unwrap();
}