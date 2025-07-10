import os 
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import base64
import math


def encrypt_file (input_file_path, output_directory, public_key_path, chunk_size = 1024*1024):
    os.makedirs(output_directory, exist_ok=True) # Making output directory if it doesn't already exist 
    chunk_no = 1
    checksums=""
    metadata = {
            "file_info" : {
                "original_name": os.path.basename(input_file_path),
                "original_size": os.path.getsize(input_file_path),
                "chunk_size": chunk_size,
                "total_chunks": math.ceil(os.path.getsize(input_file_path)/chunk_size),
                " encryption_algorithm ": " AES -256 - GCM " ,
                " key_encryption ": " RSA -4096"
                },
            "chunks":[],
            "keys": {}
            } 
    # Opening input file
    with open(input_file_path, 'rb') as f:
        # Creating key for AES GCM encryption
        key = get_random_bytes(32)

        # Accessing public key and encrypting AES key (RSA) 
        with open(public_key_path, "rb") as pb:
            public_key = RSA.import_key(pb.read())
        encrypted_key =  PKCS1_OAEP.new(public_key).encrypt(key)

        # Storing encrypted key
        key_path = os.path.join(output_directory, "encrypted_keys.bin")
        with open(key_path, "wb") as k:
            k.write(encrypted_key)
    
        metadata["keys"]["encrypted_master_key"] = base64.b64encode(encrypted_key).decode()
        metadata["keys"]["public_key_fingerprint"] = hashlib.sha256(public_key.export_key()).hexdigest()
        
        while True:
            chunk = f.read(chunk_size)
            if chunk == b'':
                break
            os.makedirs(os.path.join(output_directory, "chunks"), exist_ok=True) # Creating chunks directory
            chunk_path = os.path.join(output_directory, "chunks", f"chunk_{chunk_no}.enc")
            with open(chunk_path, "wb") as cf:
                
                #cf.write(chunk)
                checksum=hashlib.sha256(chunk).hexdigest() # Creating checksum (SHA-256)
                checksums+=f"chunk_{chunk_no}: {checksum}\n" 
                
                # AES GCM encryption 
                nonce = get_random_bytes(12) # Unique IV
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(chunk)
                
                # Writing encrypted chunk
                cf.write(nonce)
                cf.write(ciphertext)
                cf.write(tag)
                
                metadata["chunks"].append({
                    "chunk_id": chunk_no,
                    "encrypted_filename": f"chunk_{chunk_no}.enc",
                    "iv": base64.b64encode(nonce).decode(),
                    "checksum": checksum,
                    "size": len(chunk)
                
                    })
                chunk_no += 1

    with open(os.path.join(output_directory, "checksums.txt"), "w") as f:
        f.write(checksums)

    with open(os.path.join(output_directory, "metadata.json"), "w") as mf:
        json.dump(metadata, mf, indent=2)

    return metadata
pass

encrypt_file("/home/arjun//Documents/Kludge/LP/crypto/test.pdf", "/home/arjun/Documents/Kludge/LP/crypto/output_directory", "/home/arjun/Documents/Kludge/LP/crypto/public_key.pem")
