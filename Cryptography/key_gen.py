'''
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import ast

random_generator = Random.new().read
key = RSA.generate(4096, random_generator)

public_key = key.publickey().export_key()
private_key = key.export_key()
'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

public_key = private_key.public_key()


with open("private_key.enc", "wb") as f:
    f.write(private_key)
with open("public_key.enc", "wb") as pb:
    pb.write(public_key)

