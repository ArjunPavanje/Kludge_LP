import os
import hashlib
import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_file(encrypted_directory, output_file_path, private_key_path):

    # Reading metadata file 
    metadata_path = os.path.join(encrypted_directory, "metadata.json")
    with open(metadata_path, "r") as m:
        metadata = json.load(m)

    # RSA private key 
    with open(private_key_path, "rb") as pv:
        private_key =  RSA.import_key(pv.read())

    # AES key 
    with open(os.path.join(encrypted_directory, "encrypted_keys.bin"), "rb") as ak:
        encrypted_key = ak.read()
    key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)

    # Reconstructing file 
    encrypted_chunks_path = os.path.join(encrypted_directory, "chunks")
    with open(output_file_path, "wb") as f:
        for chunk_metadata in metadata["chunks"]:
            chunk_name = chunk_metadata["encrypted_filename"]
            chunk_path = os.path.join(encrypted_chunks_path, chunk_name)
            iv_metadata = base64.b64decode(chunk_metadata["iv"])
            with open(chunk_path, "rb") as cp:
                encrypted_data = cp.read()
                nonce= encrypted_data[:12]
                tag = encrypted_data[-16:]
                cipher_text = encrypted_data[12:-16]
                
                # Checking for iv missmatch
                if(nonce != iv_metadata):
                    print(f"Initialization Vector missmatch in {chunk_name}")
                    return False

                # Decrypting 
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plain_text = cipher.decrypt_and_verify(cipher_text, tag) # Decrypting and verifying in one command
                except ValueError:
                    print(f"Decryption failed in {chunk_name}")
                    return False

                # Verifying hashes 
                checksum = hashlib.sha256(plain_text).hexdigest()
                checksum_metadata = chunk_metadata["checksum"]
                if(checksum_metadata != checksum):
                    print(f"Checksum mismatch in {chunk_name}")
                    return False

                f.write(plain_text)
    print("File decrypted successfully")
    return True

decrypt_file("/home/arjun/Documents/Kludge/LP/crypto/output_directory", "/home/arjun/Documents/Kludge/LP/crypto/out.pdf", "/home/arjun/Documents/Kludge/LP/crypto/private_key.pem")


