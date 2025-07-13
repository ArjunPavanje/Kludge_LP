'''
import os
import hashlib
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def decrypt_file(encrypted_directory, output_file_path, private_key_path):
    # Read metadata
    metadata_path = os.path.join(encrypted_directory, "metadata.json")
    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    # Load recipient's private key
    with open(private_key_path, "rb") as f:
        recipient_private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Load key wrap data
    key_wrap_path = os.path.join(encrypted_directory, "key_wrap.json")
    with open(key_wrap_path, "r") as f:
        key_wrap_data = json.load(f)
    
    # Load ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(
        key_wrap_data['ephemeral_public_key'].encode()
    )
    
    # Derive shared secret using ECDH
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    # Derive key encryption key using HKDF
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'AES-KEK',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Unwrap AES key
    nonce = base64.b64decode(key_wrap_data['nonce'])
    tag = base64.b64decode(key_wrap_data['tag'])
    wrapped_key = base64.b64decode(key_wrap_data['wrapped_key'])
    
    cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    aes_key = decryptor.update(wrapped_key) + decryptor.finalize()
    
    # Reconstruct file from encrypted chunks
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
                
                # Decrypt chunk
                try:
                    chunk_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(chunk_nonce, tag), backend=default_backend())
                    chunk_decryptor = chunk_cipher.decryptor()
                    plain_text = chunk_decryptor.update(cipher_text) + chunk_decryptor.finalize()
                except Exception as e:
                    print(f"Decryption failed in {chunk_name}: {e}")
                    return False
                
                # Verify checksum
                checksum = hashlib.sha256(plain_text).hexdigest()
                if checksum != chunk_metadata["checksum"]:
                    print(f"Checksum mismatch in {chunk_name}")
                    return False
                
                f.write(plain_text)
    
    return True
'''
'''
import os
import hashlib
import json
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def decrypt_file(encrypted_directory, output_file_path, private_key_path):
    # Read metadata
    metadata_path = os.path.join(encrypted_directory, "metadata.json")
    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    # Load recipient's private key
    with open(private_key_path, "rb") as f:
        recipient_private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Extract key wrap data from metadata
    key_data = metadata["keys"]
    ephemeral_public_key = serialization.load_pem_public_key(
        key_data['ephemeral_public_key'].encode()
    )
    
    # Derive shared secret using ECDH
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    # Derive key encryption key using HKDF
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'AES-KEK',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Unwrap AES key using 
    wrap_nonce = base64.b64decode(key_data['wrap_nonce'])
    wrap_tag = base64.b64decode(key_data['wrap_tag'])
    wrapped_key = base64.b64decode(key_data['wrapped_key'])
    
    cipher = AES.new(kek, AES.MODE_GCM, nonce=wrap_nonce)
    try:
        aes_key = cipher.decrypt_and_verify(wrapped_key, wrap_tag)
    except ValueError:
        print("Key unwrapping failed - authentication error")
        return False
    
    # Reconstruct file from encrypted chunks
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
                
                # Decrypt chunk using pycryptodome
                try:
                    chunk_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=chunk_nonce)
                    plain_text = chunk_cipher.decrypt_and_verify(cipher_text, tag)
                except ValueError:
                    print(f"Decryption failed in {chunk_name}")
                    return False
                
                # Verify checksum
                checksum = hashlib.sha256(plain_text).hexdigest()
                if checksum != chunk_metadata["checksum"]:
                    print(f"Checksum mismatch in {chunk_name}")
                    return False
                
                f.write(plain_text)
    
    return True
    '''


import os
import hashlib
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
    with open(private_key_path, "rt") as f:
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
            checksum = hashlib.sha256(plain_text).hexdigest()
            if checksum != chunk_metadata["checksum"]:
                print(f"Checksum mismatch in {chunk_name}")
                return False
            
            f.write(plain_text)
    
    return True
