import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import ast

random_generator = Random.new().read
key = RSA.generate(4096, random_generator)

public_key = key.publickey().export_key()
private_key = key.export_key()

with open("private_key.enc", "wb") as f:
    f.write(private_key)
with open("public_key.enc", "wb") as pb:
    pb.write(public_key)
