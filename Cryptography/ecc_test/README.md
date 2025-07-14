# 🔐 Secure File Processing System

A comprehensive cryptographic file processing system that implements **hybrid cryptography** for secure file transfer and storage. This system combines **symmetric** and **asymmetric encryption** to provide **confidentiality**, **integrity**, and **secure key management** for files of arbitrary size.

---

## 📄 Overview

This implementation fulfills the requirements of a secure file processing system using hybrid cryptography. The system consists of two main components:

- **Cryptographic Engine**: Handles file encryption/decryption using hybrid cryptography  
- **File Transfer System**: Manages secure client-server communication for encrypted file transmission

---

## 🏗️ System Architecture

### Core Components

| File               | Description                                 |
|--------------------|---------------------------------------------|
| `encrypt.py`       | Implements the encryption pipeline with chunked file processing |
| `decrypt.py`       | Handles decryption and file reconstruction  |
| `key_gen.py`       | Generates ECC key pairs for asymmetric encryption |
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
   - **AES Key Wrapping**: Wraps AES key using derived KEK with AES-GCM
   - **Secure Metadata**: Stores encrypted AES key and ephemeral public key

3. 🗂️ **File Processing**
   - **Chunked Encryption**: 1MB per chunk (adjustable)
   - **AES-256-GCM**: Each chunk encrypted with a unique IV
   - **SHA-256 Checksums**: For integrity verification of each chunk

4. **Metadata Structure**
```json
{
  "file_info": {
    "original_name": "filename.ext",
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
- **Shared Secret Reconstruction**: Uses recipient's private key + ephemeral public key
- **KEK Derivation**: Applies HKDF to regenerate the Key Encryption Key
- **AES Key Decryption**: Unwraps AES key using AES-GCM

2.  📦 **Chunk Decryption**
- **Sequential Decryption**: Decrypts each chunk one at a time
- **IV + Checksum Verification**: Ensures correct initialization vectors and SHA-256 hashes

2.  🧩 **Reassembly**
- **Chunk Assembly**: Combines decrypted chunks into final file
- **Final Integrity Check**: Confirms correctness of reconstructed file

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

- ✅ **File Type Validation**: Restricts upload to safe extensions
- 🧹 **Temporary Directory Cleanup**: Cleans intermediate files automatically
- ⚠️ **Error Handling**: Minimal error messages to avoid information leaks

---

## 🔐 Security Properties

### 🔒 Cryptographic Strengths
- **Forward Secrecy**: Unique ephemeral ECC key pair for each session
- **Authenticated Encryption**: AES-GCM ensures confidentiality and authenticity
- **Checksum Verification**: SHA-256 ensures tamper resistance
- **Key Isolation**: AES key never exposed in plaintext

### 🔧 Implementation Security
- **Memory Efficiency**: 1MB chunk size avoids memory exhaustion
- **Timing Attack Resistance**: Consistent cryptographic operation times
- **Minimal Error Leakage**: Generalized error messages for attacker resistance

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
| Max File Size         | 512MB                        |

---

## 📈 Performance Considerations

- 🧠 **Memory Optimization**: Chunked streaming avoids RAM overload  
- 📦 **Network Optimization**: ZIP compression minimizes upload size 
- 🧹 **Storage Efficiency**: Temporary files are deleted automatically after processing  
- 📡 **Scalability**: Stateless Flask server supports concurrent clients efficiently  

---

> ✅ These structural and technical details ensure the system is robust, efficient, and production-ready for secure file transfer and processing at scale.
