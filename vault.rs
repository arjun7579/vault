use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{compress, crypto, utils};

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultFile {
    pub salt: [u8; 16],
    pub files: HashMap<String, Vec<u8>>, // filename -> encrypted+compressed bytes
    pub logs: Vec<String>,
}

pub struct Vault {
    vault_path: PathBuf,
    master_key: [u8; 32],
    vault_file: VaultFile,
}

impl Vault {
    /// Create new vault file at path/vault_name.vlt with password
    pub fn create_new(path: &Path, vault_name: &str, password: &str) -> io::Result<()> {
        let mut full_path = PathBuf::from(path);
        full_path.push(format!("{}.vlt", vault_name));

        if full_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Vault file already exists",
            ));
        }

        // Generate random salt
        let salt = crypto::generate_salt();

        // Derive master key from password and salt
        let master_key = crypto::derive_key_from_password(password, &salt);

        // Create empty VaultFile struct
        let vault_file = VaultFile {
            salt,
            files: HashMap::new(),
            logs: Vec::new(),
        };

        // Serialize vault_file
        let serialized = bincode::serialize(&vault_file).unwrap();

        // Encrypt serialized vault_file with master_key
        let encrypted = crypto::encrypt(&master_key, &serialized).unwrap();

        // Write salt (plaintext) + encrypted data to file
        let mut data = Vec::with_capacity(16 + encrypted.len());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&encrypted);

        fs::write(&full_path, data)?;

        println!("Created vault at {:?}", full_path);
        Ok(())
    }

    /// Load vault from file with password
    pub fn load(vault_path: &Path, password: &str) -> io::Result<Self> {
        let data = fs::read(vault_path)?;

        if data.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vault file corrupted or incomplete",
            ));
        }

        let salt = &data[0..16];
        let encrypted = &data[16..];

        let mut salt_arr = [0u8; 16];
        salt_arr.copy_from_slice(salt);

        let master_key = crypto::derive_key_from_password(password, &salt_arr);

        let decrypted = crypto::decrypt(&master_key, encrypted).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Invalid password or corrupted vault")
        })?;

        let vault_file: VaultFile = bincode::deserialize(&decrypted).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Vault file corrupted")
        })?;

        Ok(Vault {
            vault_path: vault_path.to_path_buf(),
            master_key,
            vault_file,
        })
    }

    /// Save current vault_file to disk encrypted
    pub fn save(&self) -> io::Result<()> {
        let serialized = bincode::serialize(&self.vault_file).unwrap();
        let encrypted = crypto::encrypt(&self.master_key, &serialized).unwrap();

        let mut data = Vec::with_capacity(16 + encrypted.len());
        data.extend_from_slice(&self.vault_file.salt);
        data.extend_from_slice(&encrypted);

        fs::write(&self.vault_path, data)?;

        Ok(())
    }

    /// Add a file to the vault
    pub fn add_file(&mut self, file_path: &Path) -> io::Result<()> {
        let filename = file_path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?
            .to_string_lossy()
            .to_string();

        let data = utils::read_file_bytes(file_path)?;

        // Compress data
        let compressed = compress::compress(&data);

        // Derive per-file key from master key + filename
        let file_key = crypto::derive_file_key(&self.master_key, &filename);

        // Encrypt compressed data
        let encrypted = crypto::encrypt(&file_key, &compressed).unwrap();

        // Insert or overwrite
        self.vault_file.files.insert(filename.clone(), encrypted);

        // Log
        self.log(&format!("Added file: {}", filename));

        Ok(())
    }

    /// Extract a file from vault to output_path
    pub fn extract_file(&self, filename: &str, output_path: &Path) -> io::Result<()> {
        let encrypted = self
            .vault_file
            .files
            .get(filename)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found in vault"))?;

        let file_key = crypto::derive_file_key(&self.master_key, filename);

        let compressed = crypto::decrypt(&file_key, encrypted).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Decryption failed (bad key or corrupted)")
        })?;

        let decompressed = compress::decompress(&compressed).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Decompression failed (corrupted data)")
        })?;

        utils::write_file_bytes(output_path, &decompressed)?;

        Ok(())
    }

    /// Remove a file from vault (no trash)
    pub fn remove_file(&mut self, filename: &str) -> io::Result<()> {
        if self.vault_file.files.remove(filename).is_some() {
            self.log(&format!("Removed file: {}", filename));
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "File not found in vault"))
        }
    }

    /// Extract and then remove a file from vault
    pub fn remex_file(&mut self, filename: &str, output_path: &Path) -> io::Result<()> {
        self.extract_file(filename, output_path)?;
        self.remove_file(filename)?;
        Ok(())
    }

    /// Print vault logs
    pub fn print_log(&self) {
        println!("Vault logs:");
        for log in &self.vault_file.logs {
            println!("{}", log);
        }
    }

    /// Add entry to vault logs with timestamp
    fn log(&mut self, message: &str) {
        let now = SystemTime::now();
        let datetime: chrono::DateTime<chrono::Utc> = now.into();
        let timestamp = datetime.format("%Y-%m-%d %H:%M:%S UTC");

        let log_entry = format!("{} - {}", timestamp, message);
        self.vault_file.logs.push(log_entry);
    }
}
