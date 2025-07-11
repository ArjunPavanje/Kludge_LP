import os
import base64
import shutil
import socketio
from eventlet import wsgi, listen
import zipfile
from decrypt import decrypt_file

RECEIVED_DIR = "/home/arjun/Documents/Kludge_LP/Cryptography/received_files"
PRIVATE_KEY_PATH = "private_key.pem"

sio = socketio.Server(cors_allowed_origins="*")
app = socketio.WSGIApp(sio)

@sio.on("encoded_file")
def connect(sid, environ):
    print(f"Client connected: {sid}")
'''
def receive_file(sid, data):
    print("I AM WORKING")
    file_name = data["file_name"]
    zip_data = base64.b64decode(data["zip"])

    # Create folder for incoming files
    os.makedirs(RECEIVED_DIR, exist_ok=True)

    zip_path = os.path.join(RECEIVED_DIR, "input.zip")
    with open(zip_path, "wb") as f:
        f.write(zip_data)

    # Extract zip inside RECEIVED_DIR
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(RECEIVED_DIR)
    os.remove(zip_path)

    # Decrypt the extracted files
    output_file_path = os.path.join(RECEIVED_DIR, f"decrypted_{file_name}")
    try:
        decrypt_file(RECEIVED_DIR, output_file_path, PRIVATE_KEY_PATH)
        print(f"✅ Decrypted: {output_file_path}")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
'''


# 🚀 Start the Socket.IO server
print("🚀 Server listening on http://localhost:5000")
wsgi.server(listen(("0.0.0.0", 5001)), app)
