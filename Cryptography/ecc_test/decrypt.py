import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def decrypt_file(encrypted_directory, output_file_path, private_key_path):
    # Reading metadata
    metadata_path = os.path.join(encrypted_directory, "metadata.json")
    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    # Loading recipient's (server) private key
    with open(private_key_path, "r") as f:
        recipient_private_key = ECC.import_key(f.read())
    
    key_data = metadata["keys"]

    # Obtaining shared secret key via ECDH
    ephemeral_public_key = ECC.import_key(key_data['ephemeral_public_key'])
    shared_point = recipient_private_key.d * ephemeral_public_key.pointQ
    shared_secret = shared_point.x.to_bytes(48, 'big')  # P-384 uses 48 bytes
    
    # Deriving key encryption key using HKDF
    kek = HKDF(
        master=shared_secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
    )
    
    # Decrypting AES-GCM key  
    encrypted_nonce = base64.b64decode(key_data['encrypted_nonce'])
    encrypted_tag = base64.b64decode(key_data['encrypted_tag'])
    encrypted_key = base64.b64decode(key_data['encrypted_key'])
    
    cipher = AES.new(kek, AES.MODE_GCM, nonce=encrypted_nonce)
    try:
        aes_key = cipher.decrypt_and_verify(encrypted_key, encrypted_tag)
    except ValueError:
        print("Key unwrapping failed")
        return False
    
    # Reconstructing file from encrypted chunks
    encrypted_chunks_path = os.path.join(encrypted_directory, "chunks")
    with open(output_file_path, "wb") as f:
        for chunk_metadata in metadata["chunks"]:
            chunk_name = chunk_metadata["encrypted_filename"]
            chunk_path = os.path.join(encrypted_chunks_path, chunk_name)
            iv_metadata = base64.b64decode(chunk_metadata["iv"])
            
            with open(chunk_path, "rb") as cp:
                encrypted_data = cp.read()
                
            chunk_nonce = encrypted_data[:12]
            tag = encrypted_data[-16:]
            cipher_text = encrypted_data[12:-16]
            
            # Verify IV matches
            if chunk_nonce != iv_metadata:
                print(f"Initialization Vector mismatch in {chunk_name}")
                return False
            
            # Decrypting chunk 
            try:
                chunk_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=chunk_nonce)
                plain_text = chunk_cipher.decrypt_and_verify(cipher_text, tag)
            except ValueError:
                print(f"Decryption failed in {chunk_name}")
                return False
            
            # Verifying checksum
            #checksum = hashlib.sha256(plain_text).hexdigest()
            checksum = SHA256.new(plain_text).hexdigest()
            if checksum != chunk_metadata["checksum"]:
                print(f"Checksum mismatch in {chunk_name}")
                return False
            
            f.write(plain_text)
    
    return True
