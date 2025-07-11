
# 🔐 Secure File Processing System (Hybrid Cryptography)

This system implements a secure file encryption and decryption mechanism using **hybrid cryptography**, combining **symmetric AES-256-GCM** encryption with **asymmetric RSA-4096** key encryption. It is built to support files of any size using a **chunked processing approach**, while ensuring **confidentiality, integrity, and secure key management**.

---

## 📜 Problem Overview

The system was designed to solve the following cryptographic goals:

1. **Handle large files securely**
2. **Encrypt files using a hybrid scheme (AES + RSA/ECC)**
3. **Detect any tampering or corruption**
4. **Gracefully handle failures during decryption**
5. **Be potentially secure against timing/memory attacks**
6. **Work consistently across files of all sizes**

---

## 🚀 Features

| Feature                    | Description |
|---------------------------|-------------|
| 🔐 AES-256-GCM Encryption | File is split into chunks, and each chunk isencrypted using AES in GCM mode. |
| 🔑 RSA-4096 Key Wrapping   | The AES key used is securely encrypted using a RSA-4096. |
| 📦 Chunked File Processing | Supports various file sizes by splitting them in chunks of size 1MB. |
| 🧾 Metadata + Checksums    | Metadata and SHA-256 checksums are stored to verify chunk authenticity. |
| ✅ Tag + Hash Verification | Checksums ensure that the data has not been altered or corrupted. |
| ⚠️ Graceful Error Handling | Detects and reports IV mismatches, decryption failures, or checksum mismatches. |

---

## 🔧 How It Works

### 📝 Encryption Flow (`encrypt_file`)

1. **AES Key Generation**: A new 256-bit AES key is randomly generated.
2. **RSA Key Generation**: RSA public and private key is generated and stored appropriately
3. **RSA Public Key Use**: The AES key is encrypted using the recipient's RSA public key (PKCS1_OAEP).
4. **Chunking**: The input file is split into fixed-size chunks (default: 1MB).
5. **AES-GCM Encryption**: Each chunk is encrypted individually using AES-GCM with a unique random nonce (initialization vector).
6. **Checksum Calculation**: A SHA-256 checksum is computed for each plaintext chunk.
7. **Metadata Storage**
8. **Output**: A directory is created containing:
   - Encrypted chunks (Subdirectory containing chunks)
   - Metadata file (`metadata.json`)
   - AES key encrypted using RSA (`encrypted_keys.bin`)
   - SHA-256 checksums of each chunk (`checksums.txt`)

---

### 🔓 Decryption Flow (`decrypt_file`)

1. **Load Metadata**: The system reads the metadata and RSA-encrypted AES key.
2. **RSA Decryption**: The private RSA key is used to decrypt the AES master key.
3. **Chunk-by-Chunk Verification**:
   - IV from metadata is compared to the one in the file
   - AES-GCM tag is verified
   - Plaintext checksum is matched against stored SHA-256
4. **Graceful Handling**:
   - If any chunk fails verification (IV mismatch, bad tag, wrong hash), it is reported with context.
   - Optionally, processing can continue or stop early based on strictness.

---

## 📁 File Structure

After encryption:

Once a file is encrypted, the `output_directory` will contain the following structure:

```
output_directory/
├── encrypted_keys.bin        # RSA-encrypted AES key (binary)
├── metadata.json             # Contains chunk details, AES settings, key fingerprint
├── checksums.txt             # Human-readable SHA-256 hashes for each plaintext chunk
└── chunks/                   # Directory with encrypted chunks
    ├── chunk_1.enc
    ├── chunk_2.enc
    ├── ...
    └── chunk_N.enc
```

### File Descriptions

- **`encrypted_keys.bin`**: Contains the AES-256 key encrypted with the recipient's RSA public key. Only the recipient with the corresponding private key can decrypt this.

- **`metadata.json`**:
  - Stores information like:
    - Original filename and size
    - Chunk size and total number of chunks
    - Per-chunk metadata: IV (nonce), encrypted filename, size, SHA-256 checksum
    - Public key fingerprint (SHA-256 hash of the public key)
  - Example snippet:
    ```json
    {
      "file_info": {
        "original_name": "test.pdf",
        "original_size": 5242880,
        "chunk_size": 1048576,
        "total_chunks": 5,
        "encryption_algorithm": "AES-256-GCM",
        "key_encryption": "RSA-4096"
      },
      "chunks": [
        {
          "chunk_id": 1,
          "encrypted_filename": "chunk_1.enc",
          "iv": "Base64EncodedNonce==",
          "checksum": "SHA256HashOfPlaintext",
          "size": 1048576
        }
      ],
      "keys": {
        "encrypted_master_key": "Base64EncodedRSAEncryptedKey==",
        "public_key_fingerprint": "SHA256HashOfPublicKey"
      }
    }
    ```

- **`checksums.txt`**: A human-readable file with per-chunk SHA-256 checksums. Example:
  ```
  chunk_1: abc123...
  chunk_2: def456...
  ...
  ```

- **`chunks/`**: Each file chunk is encrypted using AES-256-GCM and stored as a `.enc` file. Inside each:
  - First 12 bytes: Nonce (IV)
  - Middle: Ciphertext
  - Last 16 bytes: Authentication tag

---
## Working on files of various sizes

1. **9 MB**
   <img width="1221" height="186" alt="image" src="https://github.com/user-attachments/assets/4ccaeba0-6349-4f1e-a603-325a21e0a5cd" />

2. **66 KB**
   <img width="1221" height="80" alt="image" src="https://github.com/user-attachments/assets/ca494599-c800-4e27-829a-95adc8b7c5f4" />

3. **32 MB**
   <img width="1214" height="630" alt="image" src="https://github.com/user-attachments/assets/a246c7bd-93a9-4afc-996c-271230483696" />

4. **Checksums**
   <img width="1300" height="637" alt="image" src="https://github.com/user-attachments/assets/eeb142ca-f8a7-477d-a026-e819cd40389d" />



## 🧠 Notes on Security Guarantees

- **Confidentiality**: Strong AES-256 encryption ensures nobody can read the content without the decrypted AES key.
- **Integrity & Authenticity**:
  - AES-GCM tag prevents unauthorized modification.
  - SHA-256 per-chunk hash detects corruption or tampering.
- **Key Management**: RSA encryption ensures only the intended recipient can decrypt the AES key.
- **Tamper Detection**: Decryption halts with error if:
  - AES tag fails
  - IV doesn't match
  - SHA-256 hash mismatch

---
