use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use rpassword::read_password;
use chrono::{Local, DateTime};

/// Read a password securely from the terminal without echo
pub fn read_password_prompt(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    read_password()
}

/// Read entire file into a Vec<u8>
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Write bytes to a file (overwrite)
pub fn write_file(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}

/// Generate a random 16-byte salt
pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Get current timestamp string for logging, e.g. "2025-05-31 12:45:30"
pub fn current_timestamp() -> String {
    let now: DateTime<Local> = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Format bytes into human-readable string (e.g. 1024 -> "1.00 KB")
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", size, UNITS[unit])
}
