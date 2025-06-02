# 🔐 Vault

**Vault** is a secure, lightweight, and extensible command-line application written in Rust for encrypted and compressed file storage. It lets you manage your private data safely inside `.vlt` archive files using modern cryptographic techniques and file-level metadata.

---

## 📦 Features

- ✅ **Secure AES-CTR encryption**
- ✅ **File-level password protection**
- ✅ **Compression using `flate2` (DEFLATE)**
- ✅ **Metadata-based key derivation (vault password + file password + timestamp)**
- ✅ **Add, extract, remove, and extract+remove (remex) commands**
- ✅ **Plaintext `.log` file tracks all operations**
- ✅ **Fast binary serialization with `bincode`**

---

## 🧱 Vault Format

Vaults are binary `.vlt` files storing a serialized map of files:

HashMap<String, VaultEntry>


Each `VaultEntry` contains:

- `data`: Encrypted and compressed file contents (`Vec<u8>`)
- `nonce`: Unique nonce used in AES encryption
- `created_at`: RFC3339 timestamp used during key derivation

Vaults are paired with `.log` files to track all actions performed on them.

---

## 📂 Project Structure



## 🚀 Quickstart

### 🔧 Build

git clone https://github.com/arjun7579/vault.git

cd vault

cargo build --release

---

### 📌 Commands

| Command  | Description                        |
|----------|------------------------------------|
| create   | Create a new vault                 |
| add      | Add a file to an existing vault    |
| extract  | Extract a file from the vault      |
| remove   | Remove a file from the vault       |
| remex    | Extract and then remove a file     |

All commands involving files prompt for both the vault password and file password.

---

## 🔐 Encryption Details

- **Encryption Algorithm:** AES-256 in CTR mode
- **Key Derivation:** SHA-256 of (vault password + file password + RFC3339 timestamp)
- **Nonce:** Randomly generated per file and stored with the entry

---

## 📚 Logging

Every vault operation is logged to a plaintext file:

Vault created

[2025-06-01T13:19:28.343876253+00:00] ADD: f1.txt @ 2025-06-01T13:19:28.342844292+00:00

[2025-06-01T13:19:45.159780936+00:00] ADD: f2.txt @ 2025-06-01T13:19:45.158930221+00:00

[2025-06-01T13:20:58.312826976+00:00] EXTRACT: f1.txt

---

## 🛠 Dependencies

- [`aes`](https://crates.io/crates/aes) – AES encryption
- [`ctr`](https://crates.io/crates/ctr) – Counter (CTR) mode for stream encryption
- [`sha2`](https://crates.io/crates/sha2) – Secure hash (SHA-256)
- [`flate2`](https://crates.io/crates/flate2) – Compression (DEFLATE)
- [`rpassword`](https://crates.io/crates/rpassword) – Secure password prompt
- [`chrono`](https://crates.io/crates/chrono) – Timestamps
- [`serde`](https://crates.io/crates/serde)
- [`bincode`](https://crates.io/crates/bincode) – Efficient serialization


---

## 🔭 Future Work

- 🧠 Replace flate2 with a custom Huffman coding implementation
- 🔁 Vault versioning and file update tracking
- 🖼 GUI front-end using egui
- 🧪 Comprehensive unit and integration tests
- 🗂 Support for directories and file metadata (size, type, etc.)

---

_Made with 🦀 by arjun7579_

---
Output Screenshots (on command line):

![image](https://github.com/user-attachments/assets/625910f1-a3b2-4792-bbe8-7a73920b7eed)

![image](https://github.com/user-attachments/assets/0e9db14f-7247-4298-b2d6-e27b7e428ef3)
