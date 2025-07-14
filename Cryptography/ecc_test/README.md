# 🔐 Secure File Processing System

A comprehensive cryptographic file processing system that implements **hybrid cryptography** for secure file transfer and storage. 

---

## 📄 Overview

This consists of two main components:

- **Cryptographic Engine**: Handles file encryption/decryption using hybrid cryptography  
- **File Transfer System**: Manages secure client-server communication for encrypted file transmission

---


### Codes Used 

| File               | Description                                 |
|--------------------|---------------------------------------------|
| `encrypt.py`       | Encrypts file to be transferred             |
| `decrypt.py`       | Decrypts received file                      |
| `key_gen.py`       | Generates ECC key pair (curve P-384)        |
| `upload_server.py` | Flask server for receiving and processing encrypted files |
| `upload_client.py` | Client application for secure file transmission |

---

## 🔐 Cryptographic Implementation

### ✅ Encryption Pipeline

1. 🔑 **Key Generation and Exchange**
   - **Asymmetric Cryptography**: ECC P-384 curve
   - **Ephemeral Key Generation**: New key pair per session
   - **ECDH Key Exchange**: Generates shared secret via Elliptic Curve Diffie-Hellman

2. 🔐 **Key Derivation and Protection**
   - **HKDF**: HMAC-based Key Derivation Function from shared secret
   - **AES Key Wrapping**: Wraps AES key using derived KEK (Key Encryption Key) with AES-GCM
   - **Storing Metadata**: Stores encrypted AES key and ephemeral public key

3. 🗂️ **File Processing**
   - **Chunked Encryption**: Splitting file into chunks of size 1MB 
   - **AES-256-GCM**: Encrypting each chunk using AES-GCM with unique IV's for each chunk
   - **SHA-256 Checksums**: Calculating checksums (via SHA-256) for integrity verification

4. **Metadata Structure**
```json
{
  "file_info": {
    "original_name": "example.txt",
    "original_size": 12345678,
    "chunk_size": 1048576,
    "total_chunks": 12,
    "encryption_algorithm": "AES-256-GCM",
    "key_encryption": "ECC-384-HKDF"
  },
  "chunks": [...],
  "keys": {
    "encrypted_key": "base64_encoded_key",
    "ephemeral_public_key": "PEM_format_key"
  }
}
```
## 🔓 Decryption Pipeline

1.  🔑 **Key Recovery**
- **Shared Secret Reconstruction**: Reconstructing shared secret using ephemeral public key and static private key
- **KEK Derivation**: Obtaining KEK (Key encryption Key) using HKDF 
- **AES Key Decryption**: Unwrapping AES key

2.  📦 **Chunk Decryption**
- **Sequential Decryption**: Decrypting each chunk one at a time
- **IV + Checksum Verification**: Ensuring data integrity by verifying checksum and tags

3.  🧩 **Reassembly**
- **Chunk Assembly**: Combines decrypted chunks into final file

---

## 🔄 File Transfer System

### ⚙️ Client Operations (`upload_client.py`)
- **Public Key Request**: Retrieves server's ECC public key (GET)
- **File Encryption**: Encrypts file using hybrid encryption pipeline
- **Archiving**: Packages encrypted chunks and metadata into ZIP
- **Secure Upload**: Sends ZIP archive to server via POST

### 🖥️ Server Operations (`upload_server.py`)
- **Key Distribution**: Shares ECC public key with clients
- **File Reception**: Accepts encrypted ZIP archives via POST
- **Decryption**: Automatically unzips and decrypts file
- **Storage**: Saves the final decrypted file securely

---

## 🛡️ Security Features

- **Forward Secrecy**: Unique ephemeral ECC key pair for each session
- **Authenticated Encryption**: AES-GCM ensures confidentiality and authenticity
- **Checksum Verification**: SHA-256 to ensure data integrity
- **Unique IV**: Each chunk has a unique initialization vector 
- **Error Handling**: Errors are appropriately handled

---


## 🗂️ File Structure (Output Directory)
```
output_directory/
└── Chunks
    ├── chunk_1.enc
    ├── chunk_2.enc
    ├── chunk_3.enc
├── metadata.json
├── checksums.txt
├── encrypted_keys.bin
```
---

## ⚙️ Technical Specifications

| Feature               | Value                        |
|-----------------------|------------------------------|
| Symmetric Encryption  | AES-256-GCM                  |
| Asymmetric Encryption | ECC P-384                    |
| Hash Function         | SHA-256                      |
| Key Derivation        | HKDF with SHA-256            |
| Chunk Size            | 1MB                          |
---
## 🚀 Usage

First start the server
```python
python3 upload_server.py
```
Then run the client 
```python
python3 upload_client.py
```
(Ensure encrypt, dercypt, key generation scripts are saved in appropriate places)

Pycryptodome library has been used for hybrid cryptography part. File transfer code was modified from the code on this [website](https://medium.com/@mohitdubey_83162/python-building-a-file-upload-and-download-system-with-python-flask-69e19e2c83af) 
---

