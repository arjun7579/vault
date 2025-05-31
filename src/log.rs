use chrono::Utc;
use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub action: String,
    pub file: String,
    pub vault_file: Option<String>,
}

pub fn log_action(action: &str, file: &str, vault_file: Option<&str>) {
    let entry = LogEntry {
        timestamp: Utc::now().to_rfc3339(),
        action: action.to_string(),
        file: file.to_string(),
        vault_file: vault_file.map(|s| s.to_string()),
    };

    let json = serde_json::to_string(&entry).unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("vault/vault.log")
        .unwrap();

    writeln!(file, "{}", json).unwrap();
}
