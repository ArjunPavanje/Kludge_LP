import os
import requests
from encrypt import encrypt_file
import shutil

url = 'http://localhost:5000/'

# Request for obtaining public key from server 
resp = requests.get("http://localhost:5000/get_key")
public_key_path = resp.json()['public_key_path']

#input_file_path = input("Enter file path: ")
input_file_path = "/home/arjun/Documents/logo.png" 
output_directory = "output_directory"

metadata = encrypt_file(input_file_path, output_directory, public_key_path) 
file_name = os.path.basename(input_file_path)

# Turning output_directory into a zip file 
shutil.make_archive("output", "zip", output_directory)
file_path = "output.zip"

# Uploading the zip file, original file name using POST
with open(file_path, 'rb') as f:
    files = {'file': (os.path.basename(file_path), f)}
    data = {"filename" : file_name}
    response = requests.post(url, files=files, data = data)

# Printing server response
print(response.json())
