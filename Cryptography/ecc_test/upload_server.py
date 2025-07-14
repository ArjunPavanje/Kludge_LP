from flask import Flask, request, jsonify
import os
import shutil
import zipfile
from werkzeug.utils import secure_filename
from decrypt import decrypt_file  # Import your decrypt_file function here
from key_gen import key_gen

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEY_FOLDER'] = 'keys'


private_key_path, public_key_path = key_gen()

# Only known file types are allowed to be uploaded
def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['zip'])
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Allows client to request for static public key
@app.route('/get_key', methods=['GET'])
def get_key():
    return jsonify({'public_key_path': public_key_path})

# Handles uploaded zip file from client
@app.route('/', methods=['POST'])
def upload_file():
    print("File upload recieved")

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    # Getting original file name from client
    file_name = request.form.get("filename")


    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # Zip file is saved in uploads folder
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(upload_path)
        print(f"File saved at: {upload_path}")

        # Unzipping contents of zip file onto aa temproary folder
        if filename.endswith('.zip'):
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], filename + "_temp")
            os.makedirs(temp_dir, exist_ok=True)

            # Unzipping the file
            with zipfile.ZipFile(upload_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                print(f"Unzipped to: {temp_dir}")

            # Decrypting file
            decrypted_output = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
            success = decrypt_file(temp_dir, decrypted_output, private_key_path)

            # Clean up
            shutil.rmtree(temp_dir)
            print("Temproary directory removed")

            if success:
                return jsonify({'success': 'File decrypted', 'output': decrypted_output})
            else:
                return jsonify({'error': 'Decryption failed'})

    return jsonify({'error': 'Invalid file format'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
