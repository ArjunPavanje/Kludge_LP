'''
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import json
import base64
import math
from Crypto.Cipher import AES

def encrypt_file(input_file_path, output_directory, public_key_path, chunk_size=1024*1024):


    os.makedirs(output_directory, exist_ok=True)
    chunk_no = 1
    checksums = ""

    # Saving metadata
    metadata = {
        "file_info": {
            "original_name": os.path.basename(input_file_path),
            "original_size": os.path.getsize(input_file_path),
            "chunk_size": chunk_size,
            "total_chunks": math.ceil(os.path.getsize(input_file_path)/chunk_size),
            "encryption_algorithm": "AES-256-GCM",
            "key_encryption": "ECC-384-HKDF"
        },
        "chunks": [],
        "keys": {}
    }

    # Generating key for AES-GCM encryption 
    aes_key = secrets.token_bytes(32)

    # Loading recipient's (server's) static public key
    with open(public_key_path, 'rb') as f:
        recipient_public_key = serialization.load_pem_public_key(f.read())

    # Generating ephemeral ECC key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Deriving shared secret key using ECDH
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Deriving key encryption key using HKDF
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'AES-KEK',
        backend=default_backend()
    ).derive(shared_secret)

    # Encoding AES key using the deerived key encryption key 
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    wrapped_key = encryptor.update(aes_key) + encryptor.finalize()

    # Storing encoded key and ephemeral public key
    key_wrap_data = {
        'wrapped_key': base64.b64encode(wrapped_key).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(encryptor.tag).decode(),
        'ephemeral_public_key': ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

    key_wrap_path = os.path.join(output_directory, "key_wrap.json")
    with open(key_wrap_path, "w") as f:
        json.dump(key_wrap_data, f, indent=2)

    metadata["keys"]["key_wrap_method"] = "ECC-384-HKDF"
    metadata["keys"]["ephemeral_public_key_fingerprint"] = hashlib.sha256(
        ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()

    # Encrypting file chunks via AES-GCM
    with open(input_file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if chunk == b'':
                break

            os.makedirs(os.path.join(output_directory, "chunks"), exist_ok=True)
            chunk_path = os.path.join(output_directory, "chunks", f"chunk_{chunk_no}.enc")

            with open(chunk_path, "wb") as cf:
                checksum = hashlib.sha256(chunk).hexdigest()
                checksums += f"chunk_{chunk_no}: {checksum}\n"

                # AES-GCM encryption
                chunk_nonce = secrets.token_bytes(12)
                chunk_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(chunk_nonce), backend=default_backend())
                chunk_encryptor = chunk_cipher.encryptor()
                ciphertext = chunk_encryptor.update(chunk) + chunk_encryptor.finalize()

                # Write encrypted chunk
                cf.write(chunk_nonce)
                cf.write(ciphertext)
                cf.write(chunk_encryptor.tag)

                metadata["chunks"].append({
                    "chunk_id": chunk_no,
                    "encrypted_filename": f"chunk_{chunk_no}.enc",
                    "iv": base64.b64encode(chunk_nonce).decode(),
                    "checksum": checksum,
                    "size": len(chunk)
                })

                chunk_no += 1

    # Write metadata and checksums
    with open(os.path.join(output_directory, "checksums.txt"), "w") as f:
        f.write(checksums)

    with open(os.path.join(output_directory, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata
'''


'''
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Protocol.KDF import HKDF
import json
import base64
import math

def encrypt_file(input_file_path, output_directory, public_key_path, chunk_size=1024*1024):

    os.makedirs(output_directory, exist_ok=True)
    chunk_no = 1
    checksums = ""

    # Generating AES-GCM key
    aes_key = get_random_bytes(32)

    # Loading recipient's (server) static public key
    with open(public_key_path, 'rb') as f:
        recipient_public_key = serialization.load_pem_public_key(f.read())

    # Generating ephemeral ECC key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Deriving shared secret key using ECDH
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Derive key encryption key using HKDF
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'AES-KEK',
        backend=default_backend()
    ).derive(shared_secret)

    # Wrap AES key using KEK with AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
    wrapped_key, tag = cipher.encrypt_and_digest(aes_key)

    metadata = {
        "file_info": {
            "original_name": os.path.basename(input_file_path),
            "original_size": os.path.getsize(input_file_path),
            "chunk_size": chunk_size,
            "total_chunks": math.ceil(os.path.getsize(input_file_path)/chunk_size),
            "encryption_algorithm": "AES-256-GCM",
            "key_encryption": "ECC-384-HKDF"
        },
        "chunks": [],
        "keys": {
            "key_wrap_method": "ECC-384-HDKF",
            "wrapped_key": base64.b64encode(wrapped_key).decode(),
            "wrap_nonce": base64.b64encode(nonce).decode(),
            "wrap_tag": base64.b64encode(tag).decode(),
            "ephemeral_public_key": ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "ephemeral_public_key_fingerprint": hashlib.sha256(
                ephemeral_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).hexdigest()
        }
    }

    # Encrypt file chunks with AES-256-GCM
    with open(input_file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if chunk == b'':
                break

            os.makedirs(os.path.join(output_directory, "chunks"), exist_ok=True)
            chunk_path = os.path.join(output_directory, "chunks", f"chunk_{chunk_no}.enc")

            with open(chunk_path, "wb") as cf:
                checksum = hashlib.sha256(chunk).hexdigest()
                checksums += f"chunk_{chunk_no}: {checksum}\n"

                # AES GCM encryption using pycryptodome
                chunk_nonce = get_random_bytes(12)
                chunk_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=chunk_nonce)
                ciphertext, chunk_tag = chunk_cipher.encrypt_and_digest(chunk)

                # Write encrypted chunk
                cf.write(chunk_nonce)
                cf.write(ciphertext)
                cf.write(chunk_tag)

                metadata["chunks"].append({
                    "chunk_id": chunk_no,
                    "encrypted_filename": f"chunk_{chunk_no}.enc",
                    "iv": base64.b64encode(chunk_nonce).decode(),
                    "checksum": checksum,
                    "size": len(chunk)
                })

                chunk_no += 1

    # Write metadata and checksums
    with open(os.path.join(output_directory, "checksums.txt"), "w") as f:
        f.write(checksums)

    with open(os.path.join(output_directory, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata
'''



import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import json
import base64
import math

def encrypt_file(input_file_path, output_directory, public_key_path, chunk_size=1024*1024):
    os.makedirs(output_directory, exist_ok=True)
    chunk_no = 1
    checksums = ""

    # Generating AES-GCM key
    aes_key = get_random_bytes(32)

    # Loading recipient's (server) static public key
    with open(public_key_path, 'rt') as f:
        recipient_public_key = ECC.import_key(f.read())

    # Generating ephemeral ECC key pair
    # The word ephemeral is because they change with each file sent (i.e. not static or constant)
    ephemeral_private_key = ECC.generate(curve='P-384')
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Performing ECDH to get shared secret
    shared_point = ephemeral_private_key.d * recipient_public_key.pointQ
    shared_secret = shared_point.x.to_bytes(48, 'big')  # P-384 uses 48 bytes

    # Derive key encryption key using HKDF
    kek = HKDF(
            master=shared_secret,
            key_len=32,
            salt=None,
            hashmod=SHA256,
    )

    # Wrapping AES key using KEK via AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
    encrypted_key, tag = cipher.encrypt_and_digest(aes_key)

    metadata = {
            "file_info": {
                "original_name": os.path.basename(input_file_path),
                "original_size": os.path.getsize(input_file_path),
                "chunk_size": chunk_size,
                "total_chunks": math.ceil(os.path.getsize(input_file_path)/chunk_size),
                "encryption_algorithm": "AES-256-GCM",
                "key_encryption": "ECC-384-HKDF"
                },
            "chunks": [],
            "keys": {
                "key_wrap_method": "ECC-384-HKDF",
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "encrypted_nonce": base64.b64encode(nonce).decode(),
                "encrypted_tag": base64.b64encode(tag).decode(),
                "ephemeral_public_key": ephemeral_public_key.export_key(format='PEM')
                }
            }

    # Encrypting file chunks (after splitting) with AES-GCM
    with open(input_file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if chunk == b'':
                break

            os.makedirs(os.path.join(output_directory, "chunks"), exist_ok=True)
            chunk_path = os.path.join(output_directory, "chunks", f"chunk_{chunk_no}.enc")

            with open(chunk_path, "wb") as cf:
                
                # Checksum
                checksum = hashlib.sha256(chunk).hexdigest()
                checksums += f"chunk_{chunk_no}: {checksum}\n"

                # AES GCM encryption 
                chunk_nonce = get_random_bytes(12)
                chunk_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=chunk_nonce)
                ciphertext, chunk_tag = chunk_cipher.encrypt_and_digest(chunk)

                # Writing encrypted chunk
                cf.write(chunk_nonce)
                cf.write(ciphertext)
                cf.write(chunk_tag)
                
                # Storing metadata
                metadata["chunks"].append({
                    "chunk_id": chunk_no,
                    "encrypted_filename": f"chunk_{chunk_no}.enc",
                    "iv": base64.b64encode(chunk_nonce).decode(),
                    "checksum": checksum,
                    "size": len(chunk)
                    })

            chunk_no += 1

    # Writing metadata and checksums
    with open(os.path.join(output_directory, "checksums.txt"), "w") as f:
        f.write(checksums)

    with open(os.path.join(output_directory, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata
