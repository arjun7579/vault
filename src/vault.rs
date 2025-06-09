use crate::{compress, crypto, log::log_op};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use chrono::Utc;
use rpassword::prompt_password;
use rand::{thread_rng, RngCore};
use sha2::{Sha256, Digest};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use std::os::unix::fs::PermissionsExt;

const VAULT_EXT: &str = "vlt";

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
    fs::write(path, data)?;
    Ok(())
}

fn hash_with_salt(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}

fn save_password_hash(vault_name: &str, password: &str) -> io::Result<()> {
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    let hash = hash_with_salt(password, &salt);

    let mut file_path = PathBuf::from("/etc");
    file_path.push(format!(".vault_pw_{}.hash", vault_name));

    let mut file = OpenOptions::new().write(true).create_new(true).open(&file_path)?;
    file.write_all(&salt)?;
    file.write_all(&hash)?;

    // Make root-only
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&file_path, perms)?;

    Ok(())
}

fn verify_password_hash(vault_name: &str, input: &str) -> io::Result<bool> {
    let mut file_path = PathBuf::from("/etc");
    file_path.push(format!(".vault_pw_{}.hash", vault_name));
    let mut data = Vec::new();
    File::open(&file_path)?.read_to_end(&mut data)?;
    let salt = &data[..16];
    let stored_hash = &data[16..];

    Ok(hash_with_salt(input, salt) == stored_hash)
}

fn retry_password(prompt: &str, vault_name: &str) -> Option<String> {
    for _ in 0..3 {
        if let Ok(pw) = prompt_password(prompt) {
            if verify_password_hash(vault_name, &pw).unwrap_or(false) {
                return Some(pw);
            } else {
                print_color("Incorrect password.\n", Color::Red);
            }
        }
    }
    None
}

fn file_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn create_vault(dir: &Path, name: &str) -> io::Result<()> {
    let vault_path = dir.join(format!("{}.{}", name, VAULT_EXT));
    let duplicate_exists = WalkDir::new("/")
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry.file_name().to_string_lossy() == format!("{}.{}", name, VAULT_EXT)
        });

    if duplicate_exists {
        print_color("A vault with this name already exists.\n", Color::Red);
        return Ok(());
    }

    let pw = prompt_password("Create vault password: ").unwrap();
    save_password_hash(name, &pw)?;

    save_vault(&vault_path, &Vault::default())?;
    fs::write(log_path(&vault_path), b"Vault created\n")?;
    print_color(&format!("Vault created: {}\n", vault_path.display()), Color::Green);
    Ok(())
}

pub fn add_file(file_path: &Path, vault_path: &Path) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let vault_name = vault_path.file_stem().unwrap().to_string_lossy();

    let vault_pw = match retry_password("Vault password: ", &vault_name) {
        Some(p) => p,
        None => return Ok(()),
    };

    let file_pw = prompt_password("File password: ").unwrap();
    let created_at = Utc::now().to_rfc3339();

    let mut file_data = Vec::new();
    File::open(file_path)?.read_to_end(&mut file_data)?;
    let compressed = compress::compress_f(&file_data)?;
    let key = crypto::derive_key(&vault_pw, &file_pw, &created_at);
    let (nonce, encrypted) = crypto::encrypt(&compressed, &key);
    let hash = file_hash(&file_data);

    let mut vault = load_vault(vault_path)?;
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

pub fn extract_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let vault_name = vault_path.file_stem().unwrap().to_string_lossy();
    let vault_pw = match retry_password("Vault password: ", &vault_name) {
        Some(p) => p,
        None => return Ok(()),
    };
    let file_pw = prompt_password("File password: ").unwrap();

    let vault = load_vault(vault_path)?;
    let entry = match vault.files.get(file_name) {
        Some(e) => e,
        None => {
            print_color("File not found.\n", Color::Red);
            return Ok(());
        }
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
    let decompressed = compress::decompress_f(&decrypted)?;

    fs::write(file_name, decompressed)?;
    log_op(&log_path(vault_path), &format!("EXTRACT: {}", file_name))?;
    print_color(&format!("File extracted: {}\n", file_name), Color::Green);
    Ok(())
}

pub fn remove_file(file_name: &str, vault_path: &Path) -> io::Result<()> {
    let vault_name = vault_path.file_stem().unwrap().to_string_lossy();
    if retry_password("Vault password: ", &vault_name).is_none() {
        return Ok(());
    }

    let mut vault = load_vault(vault_path)?;
    if vault.files.remove(file_name).is_some() {
        save_vault(vault_path, &vault)?;
        log_op(&log_path(vault_path), &format!("REMOVE: {}", file_name))?;
        print_color("File removed.\n", Color::Yellow);
    } else {
        print_color("File not found.\n", Color::Red);
    }
    Ok(())
}

pub fn remex_file(file_name: &str, vault_path: &Path, out_path: &Path) -> io::Result<()> {
    let vault_name = vault_path.file_stem().unwrap().to_string_lossy();
    let vault_pw = match retry_password("Vault password: ", &vault_name) {
        Some(p) => p,
        None => return Ok(()),
    };
    let file_pw = prompt_password("File password: ").unwrap();

    let mut vault = load_vault(vault_path)?;
    let entry = match vault.files.remove(file_name) {
        Some(e) => e,
        None => {
            print_color("File not found.\n", Color::Red);
            return Ok(());
        }
    };

    let key = crypto::derive_key(&vault_pw, &file_pw, &entry.created_at);
    let decrypted = crypto::decrypt(&entry.data, &key, &entry.nonce);
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
