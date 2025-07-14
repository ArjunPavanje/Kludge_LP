import os
from Crypto.PublicKey import ECC

# Generating ECC public and private keys and storing them in ".pem" files and returning their paths
def key_gen(output_folder='keys'):
    os.makedirs(output_folder, exist_ok=True)
    
    # Generate ECC key pair using P-384 curve
    private_key = ECC.generate(curve='P-384')
    public_key =  private_key.public_key()
    
    private_key_path = os.path.join(output_folder, 'private_key.pem')
    public_key_path = os.path.join(output_folder, 'public_key.pem')
    
    # Saving private key
    with open(private_key_path, 'w') as f:
        f.write(private_key.export_key(format='PEM'))
    
    # Saving public key
    with open(public_key_path, 'w') as f:
        f.write(public_key.export_key(format='PEM'))
    
    return private_key_path, public_key_path




