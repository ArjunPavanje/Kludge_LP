import os
import base64
import shutil
import socketio
from encrypt import encrypt_file

sio = socketio.Client()
sio.connect('http://localhost:5001')

def send_file( ):
    input_file_path = input("Enter input file path: ")
    output_directory = input("Enter output directory: ")
    public_key_path = "public_key.pem"
    
    metadata = encrypt_file(input_file_path, output_directory, public_key_path) 
    file_name = os.path.basename(input_file_path)

    # Turning output_directory into a zip file 
    shutil.make_archive("output", "zip", output_directory)
    with open("output.zip", "rb") as f:
        zip_data = f.read()
    encrypted_zip =  base64.b64encode(zip_data).decode()
    
    # Sending zip file 
    sio.emit("encoded_file", {"file_name":  file_name, "zip": encrypted_zip})

    print(f"{file_name} sent successfully")


while True:
    res = input("Do you want to upload a file(y/n)?")
    if(res == "n"):
        sio.disconnect()
        exit()
    else: 
        send_file()    
