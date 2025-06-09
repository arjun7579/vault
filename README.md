# 🔐 Vault

**Vault** is a secure, lightweight, and extensible command-line application written in Rust for encrypted and compressed file storage. It lets you manage your private data safely inside `.vlt` archive files using modern cryptographic techniques and file-level metadata.

---

## 📦 Features

- 🔒 **AES-256 in CTR mode** for confidentiality  
- 🔑 **File-level password protection**  
- 🗝️ **Salted vault password** stored as a root-only hash at `/etc/.vault_pw_<vault>.hash`  
- 🎨 **Colored CLI output** & **3-attempt retry** on password prompts  
- 📚 **Custom Huffman compression** implemented from scratch  
- 📂 **Add**, **extract**, **remove**, and **extract+remove (remex)** commands  
- 📝 **Plaintext `.log`** file tracks every operation with timestamps  
- ⚡ **Binary serialization** via `bincode`  

---

## 🧱 Vault Format


A `.vlt` file contains a serialized:

```rust
HashMap<String, VaultEntry>
```
Each VaultEntry includes:

- data: Vec<u8> — compressed & encrypted file contents

- nonce: Vec<u8> — random 128-bit AES-CTR nonce

- created_at: String — RFC3339 timestamp

- hash: Vec<u8> — SHA-256 digest of the original file

Vaults are paired with `.log` files to track all actions performed on them.

---

## 🚀 Quickstart

### 🔧 Build
```bash

git clone https://github.com/arjun7579/vault.git

cd vault

cargo build --release
```
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

## 🔐 Encryption & Password Storage

- **Encryption Algorithm:** AES-256 in CTR mode  
- **Key Derivation:** SHA-256 of:
  - Vault password  
  - File password  
  - RFC3339 creation timestamp  
- **Nonce:** Random 128-bit value generated per file and stored alongside the ciphertext entry  
- **Vault Password**  
  - Prompted once at vault creation  
  - **Salted** with 16 random bytes  
  - Hashed via SHA-256  
  - Stored in `/etc/.vault_pw_<vaultname>.hash`  
    - File permissions set to `0o600` (owner read/write only)  
    - Requires root/sudo to create or modify  
- **File Passwords**  
  - Prompted per file operation (`add`, `extract`, `remex`)  
  - **Not** stored in cleartext—only used in-memory for key derivation  
  - Combined with vault password and timestamp to derive the AES key  

---
## 🛠 Compression Details

- **Custom Huffman coder** written from scratch:
  1. **Frequency map**: Count occurrences of each byte in the input.
  2. **Deterministic tree build**:
     - Insert all `(byte, frequency)` into a `BinaryHeap` (min-heap).
     - Tie-break equal frequencies by byte value for stable output.
  3. **Code generation**:
     - Traverse the tree to assign each byte a unique bit‐vector.
     - Assert code lengths ≤ 64 bits (guarding against overflow).
  4. **Header serialization** (always sorted by byte):
     - `u16` number of unique symbols  
     - For each symbol: `u8` byte, then `u64` frequency  
     - `u64` total number of encoded bits (for padding)  
  5. **Payload encoding**:
     - Pack each byte’s bit‐vector into a contiguous bitstream.
     - Flush out full bytes as they fill, pad the last partial byte.
  6. **Decompression**:
     - Read the header to rebuild the exact same Huffman tree.
     - Read the bitstream, walk the tree bit-by-bit to recover original bytes.
---
## 📚 Logging

Every vault operation is logged to a plaintext file:

```console

Vault created

[2025-06-01T13:19:28.343876253+00:00] ADD: f1.txt @ 2025-06-01T13:19:28.342844292+00:00

[2025-06-01T13:19:45.159780936+00:00] ADD: f2.txt @ 2025-06-01T13:19:45.158930221+00:00

[2025-06-01T13:20:58.312826976+00:00] EXTRACT: f1.txt
```
---

# 📦 Dependencies

| Crate Name       | Purpose                                 | GitHub Repository |
|------------------|------------------------------------------|-------------------|
| `aes`            | AES-256 block cipher                     | [RustCrypto/block-ciphers](https://github.com/RustCrypto/block-ciphers) |
| `ctr`            | Counter (CTR) stream cipher mode         | [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) |
| `cipher`         | Common cipher traits used by `aes`/`ctr` | [RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `sha2`           | SHA-256 hashing for key derivation       | [RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `bincode`        | Fast binary serialization/deserialization| [bincode-org/bincode](https://github.com/bincode-org/bincode) |
| `rand`           | Random number generation (nonce, salt)   | [rust-random/rand](https://github.com/rust-random/rand) |
| `chrono`         | Timestamps in RFC3339                    | [chronotope/chrono](https://github.com/chronotope/chrono) |
| `rpassword`      | Secure terminal password prompt          | [conradkleinespel/rpassword](https://github.com/conradkleinespel/rpassword) |
| `serde`          | Serialization framework for structs      | [serde-rs/serde](https://github.com/serde-rs/serde) |
| `clap`           | CLI argument parsing                     | [clap-rs/clap](https://github.com/clap-rs/clap) |
| `bitstream-io`   | Bit-level I/O for custom compression     | [tuffy/bitstream-io](https://github.com/tuffy/bitstream-io) |
| `flate2`         | Compression via DEFLATE                  | [alexcrichton/flate2-rs](https://github.com/alexcrichton/flate2-rs) |
| `walkdir`        | Recursive directory traversal            | [BurntSushi/walkdir](https://github.com/BurntSushi/walkdir) |
| `colored`        | Text coloring in terminal (optional)     | [mackwic/colored](https://github.com/mackwic/colored) |
| `termcolor`      | Terminal-safe color output               | [BurntSushi/termcolor](https://github.com/BurntSushi/termcolor) |


---

## 🔭 Future Work

- 🔁 Vault versioning and file update tracking (track changes to files, support rollback)
- 🖼 GUI front-end using `egui` or `Tauri` for a cross-platform interface
- 🗂 Full directory and file metadata support (store size, type, permissions, modified time)
- 🔑 Pluggable key derivation backends (support Argon2/PBKDF2 in future)
- ☁️ Optional cloud backup & sync support (e.g. S3 or Dropbox CLI)


---

_Made with 🦀 by arjun7579_

---
Output Screenshots (on command line):

![image](https://github.com/user-attachments/assets/625910f1-a3b2-4792-bbe8-7a73920b7eed)

![image](https://github.com/user-attachments/assets/0e9db14f-7247-4298-b2d6-e27b7e428ef3)
