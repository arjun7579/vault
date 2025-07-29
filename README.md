# 🔐 Vault: A Secure, Production-Grade File Vault

Vault is a secure, high-performance command-line application written in Rust for encrypted and compressed file storage. It allows you to safely manage sensitive files inside self-contained `.vlt` archives using modern, authenticated cryptography and robust engineering practices designed to prevent data loss.

---

## ✨ Features

### Security
- **Authenticated Encryption**  
  Uses AES‑256‑GCM for confidentiality and integrity, preventing unauthorized access or silent data tampering.  
- **Modern Password Hashing**  
  Master password is secured with Argon2 (winner of the Password Hashing Competition), making brute‑force attacks impractical.  
- **Granular Access Control**  
  Supports both a master vault password and per-file passwords for layered security, even on deletion.  
- **Secure Memory Handling**  
  Utilizes the `zeroize` crate to wipe passwords and keys from memory immediately after use.  
- **Secure Audit Trail**  
  Maintains a persistent, **encrypted** log of all vault operations (add, remove, extract) inside the `.vlt` file itself.  
- **Portable Vaults**  
  Self‑contained `.vlt` files include salt and hash internally—no extra setup or permissions needed.

### Reliability & Performance
- **Atomic File Writes**  
  Uses a safe “write‑and‑rename” strategy to never leave a half‑written vault on disk.  
- **Streaming I/O**  
  Handles arbitrarily large files with constant memory overhead via a streaming pipeline.  
- **Selectable Compression**  
  Choose **Zstandard (zstd)** for speed or **DEFLATE (zip)** for maximum compatibility per‐file.  
- **Data Integrity Checks**  
  A `check` command verifies vault integrity and authenticity of every file entry.

### User Experience
- **Rich CLI**  
  Intuitive commands: `new`, `add`, `extract`, `remove`, `remex`, `list`, `check`, `delete`, `log`.  
- **Progress Bars**  
  Visual feedback for long operations via the `indicatif` crate.  
- **Human‑Readable Logging**  
  Clean, structured output powered by `tracing`.

---

## 🚀 Quickstart

### Installation

```bash
git clone https://github.com/arjun7579/vault.git
cd vault
cargo build --release
# Binary will be at ./target/release/vault
```
After building the project, you can install the `vault` binary to your system's `PATH`. This allows you to run the `vault` command from any directory in your terminal.

```bash
# Run this command from the root of the project directory
cargo install --path .
```

To verify this, run the following command:
```bash
vault --version
```
### Commands

| Command  | Description                                                         |
|----------|---------------------------------------------------------------------|
| `new`    | Create a new, empty vault in a specified directory                  |
| `add`    | Add a file to the vault (choose zstd or deflate compression)        |
| `extract`| Extract a file from the vault into the current directory            |
| `remove` | Permanently remove a file from the vault (requires file password)   |
| `remex`  | Extract then immediately remove a file from the vault               |
| `list`   | List all files currently stored in the vault                        |
| `check`  | Verify vault integrity and authenticate every file entry            |
| `delete` | Permanently delete the entire vault (with confirmation prompt)      |
| `log`    | Display the secure, internal activity log for the vault             |


#### Example Usage

```bash
# Create a new vault
vault new . my_secrets

# Add a file with default zstd compression
vault add --file important.docx --vault my_secrets.vlt

# Add a file with DEFLATE compression
vault add --file photo.jpg --vault my_secrets.vlt --compression deflate

# List the files inside
vault list --vault my_secrets.vlt

# Check vault health
vault check --vault my_secrets.vlt

# View operation log
vault log --vault my_secrets.vlt
```
use ```-h``` parameter for help

## 🛡️ Security Architecture

### Master Password
- **Never stored in plaintext.**  
- On vault creation, a random salt is generated and an Argon2 hash is derived.  
- The hash (including salt and parameters) is embedded in the `.vlt` file, making the vault portable.

### Per‑File Key Derivation
For each file, derive a unique 256‑bit key using SHA‑256 over:
1. Master password  
2. Per‑file password  
3. File creation timestamp  

This prevents key reuse—compromise of one file’s key does not expose others.

### Authenticated Encryption
- Compress file contents, then encrypt with AES‑256‑GCM.  
- Store `(ciphertext, nonce, auth_tag)` together as the vault entry.  
- Any tampering will cause GCM’s integrity check to fail, preventing corrupted data from decrypting.

---

## 💡 Standalone Huffman Coder

A demonstration of lossless compression lives at `src/custom_compressor.rs`. It illustrates:
- Building a min‑heap of `(byte, frequency)` nodes  
- Merging nodes into a binary Huffman tree  
- Generating prefix codes  
- Bit‑level encoding and decoding  

> **Note:** This module is not included in the production binary—it’s kept purely for educational purposes.

---

## 🦀 Key Dependencies

- **clap** — CLI argument parsing  
- **serde** & **bincode** — Vault metadata serialization  
- **argon2**, **aes‑gcm**, **sha2** — Cryptographic primitives  
- **zstd** & **flate2** — Compression engines  
- **indicatif** — Progress bars  
- **tracing** — Structured, human‑readable logging  
- **zeroize** — Securely wipe secrets from memory  
---

## 🔭 Future Work

While **Vault** is fully functional, here are some features planned for future releases to enhance its capabilities further:

### 🔹 Interactive Shell Mode
An interactive session (`vault shell <path>`) where a user can unlock a vault once with the master password and then perform multiple operations (add, list, extract, etc.) without re-entering credentials.

### 🔹 Keyfile Authentication
Support for using a file (e.g., from a USB drive) as an additional factor for authentication, or as the primary key instead of a password — enhancing security through two-factor or password-less access.

### 🔹 Cloud Storage Sync
Integration with cloud storage providers (like AWS S3 or Google Cloud Storage) to allow for secure, encrypted backups and synchronization of vaults across multiple devices.

### 🔹 Role-Based Access Control (RBAC)
A major architectural enhancement to support multiple users with different roles (e.g., **Admin**, **Contributor**, **Reader**), using public-key cryptography to manage access without sharing the master password.

### 🔹 In-place File Editing
A seamless `edit` command that:
- Securely extracts a file to a temporary location
- Opens it in the user's default text editor
- Automatically re-encrypts and saves the changes back into the vault upon closing
---
## 📄 License

### This project is licensed under the MIT License.
---
###### _Made with ❤️ and rust by arjun7579_  
---