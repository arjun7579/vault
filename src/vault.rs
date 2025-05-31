use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};




use crate::compress;
use crate::crypto;
use crate::utils;

use chrono::Local;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub path: PathBuf,
    pub files: HashMap<String, Vec<u8>>,
    pub password: String,
}

impl Vault {
    pub fn new(vault_dir: &Path, name: &str, password: &str) -> io::Result<Self> {
        let vault_path = vault_dir.join(format!("{}.vlt", name));
        let vault = Vault {
            path: vault_path.clone(),
            files: HashMap::new(),
            password: password.to_string(),
        };
        vault.save()?;
        utils::write_log(&vault_path, "Vault created")?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> io::Result<Self> {
        Self::load(path, password)
    }

    pub fn load(vault_path: &Path, password: &str) -> io::Result<Self> {
        let mut file = File::open(vault_path)?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        let decrypted_data = crypto::decrypt(&encrypted_data, &format!("{}{}", vault_path.display(), password))?;
        let files: HashMap<String, Vec<u8>> = bincode::deserialize(&decrypted_data).unwrap_or_default();

        Ok(Vault {
            path: vault_path.to_path_buf(),
            files,
            password: password.to_string(),
        })
    }

    pub fn save(&self) -> io::Result<()> {
        let data = bincode::serialize(&self.files)?;
        let encrypted_data = crypto::encrypt(&data, &format!("{}{}", self.path.display(), self.password))?;
        fs::write(&self.path, encrypted_data)?;
        Ok(())
    }

    pub fn add_file(&mut self, file_path: &Path) -> io::Result<()> {
        let mut file = File::open(file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let compressed = compress::compress(&contents);
        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
        self.files.insert(file_name.clone(), compressed);
        self.save()?;
        utils::write_log(&self.path, &format!("Added file: {}", file_name))?;
        Ok(())
    }

    pub fn extract_file(&self, file_name: &str, output_path: &Path) -> io::Result<()> {
        if let Some(data) = self.files.get(file_name) {
            let decompressed = compress::decompress(data)?;
            fs::write(output_path, decompressed)?;
            utils::write_log(&self.path, &format!("Extracted file: {}", file_name))?;
        }
        Ok(())
    }

    pub fn remove_file(&mut self, file_name: &str) -> io::Result<()> {
        if self.files.remove(file_name).is_some() {
            self.save()?;
            utils::write_log(&self.path, &format!("Removed file: {}", file_name))?;
        }
        Ok(())
    }

    pub fn remove_and_extract(&mut self, file_name: &str, output_path: &Path) -> io::Result<()> {
        if let Some(data) = self.files.remove(file_name) {
            let decompressed = compress::decompress(&data)?;
            fs::write(output_path, decompressed)?;
            self.save()?;
            utils::write_log(&self.path, &format!("Extracted and removed file: {}", file_name))?;
        }
        Ok(())
    }

    pub fn show_log(&self) -> io::Result<()> {
        let log_path = self.path.with_extension("log");
        if log_path.exists() {
            let contents = fs::read_to_string(log_path)?;
            println!("Vault Log:\n{}", contents);
        } else {
            println!("No log found.");
        }
        Ok(())
    }
}
