use std::fs::{OpenOptions, read_to_string};
use std::io::{self, Write};
use std::path::Path;
use chrono::Utc;

/// Appends a log entry with timestamp
pub fn log_op(log_path: &Path, message: &str) -> io::Result<()> {
    let now = Utc::now().to_rfc3339();
    let entry = format!("[{}] {}\n", now, message);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    file.write_all(entry.as_bytes())
}

/// Prints the contents of the vault log
pub fn print_log(log_path: &Path) -> io::Result<()> {
    if log_path.exists() {
        let contents = read_to_string(log_path)?;
        println!("--- Vault Log ---\n{}", contents);
    } else {
        println!("No log file found.");
    }
    Ok(())
}
