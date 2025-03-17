from flask import Flask, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room
import jwt
import datetime
import os
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'  
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins="*")
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

users = {}  # Simulated User Database
messages = {}  # Stores Encrypted Messages
groups = {}  # Stores Group Members
file_keys = {}  # Stores Encrypted AES Keys for Files

# Generate RSA keys for users
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

# Encrypt and decrypt messages using AES
def encrypt_message(aes_key, message):
    key = SHA256.new(aes_key).digest()[:16]
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher_aes.nonce + tag + ciphertext).decode()

def decrypt_message(aes_key, encrypted_message):
    key = SHA256.new(aes_key).digest()[:16]
    encrypted_bytes = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

# Encrypt and decrypt files using AES
def encrypt_file(aes_key, file_path):
    key = SHA256.new(aes_key).digest()[:16]
    cipher_aes = AES.new(key, AES.MODE_EAX)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher_aes.nonce + tag + ciphertext)

    return encrypted_file_path

def decrypt_file(aes_key, file_path):
    key = SHA256.new(aes_key).digest()[:16]
    
    with open(file_path, 'rb') as f:
        encrypted_bytes = f.read()

    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)

    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, 'wb') as f:
        f.write(cipher_aes.decrypt_and_verify(ciphertext, tag))

    return decrypted_file_path

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    private_key, public_key = generate_rsa_keys()

    users[username] = {
        "password": hashed_password,
        "private_key": private_key,
        "public_key": public_key
    }

    return jsonify({"message": "User registered successfully", "public_key": public_key}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    if username not in users or not check_password_hash(users[username]["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = jwt.encode(
        {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({"message": "Login successful", "token": token, "public_key": users[username]["public_key"]})

# Secure Key Exchange
@app.route('/exchange-key', methods=['POST'])
def exchange_key():
    data = request.json
    sender = data["sender"]
    receiver = data["receiver"]

    if sender not in users or receiver not in users:
        return jsonify({"error": "User not found"}), 404

    aes_key = os.urandom(16)
    receiver_public_key = RSA.import_key(users[receiver]["public_key"])
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()

    return jsonify({"encrypted_aes_key": encrypted_aes_key})

# Group Messaging
@socketio.on('create_group')
def create_group(data):
    group_name = data["group_name"]
    users_list = data["users"]

    groups[group_name] = users_list
    for user in users_list:
        join_room(user)

    emit('group_created', {"group_name": group_name}, broadcast=True)

@socketio.on('send_group_message')
def handle_group_message(data):
    sender = data["sender"]
    group_name = data["group_name"]
    encrypted_message = data["encrypted_message"]

    if group_name in groups:
        for user in groups[group_name]:
            messages.setdefault(user, []).append({"sender": sender, "message": encrypted_message})
        emit('receive_group_message', {"sender": sender, "encrypted_message": encrypted_message}, room=group_name, broadcast=True)

# File Upload & Secure Sharing
@app.route('/upload', methods=['POST'])
def upload_file():
    username = request.form["username"]
    file = request.files["file"]

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    aes_key = os.urandom(16)
    encrypted_file_path = encrypt_file(aes_key, file_path)

    file_keys[file.filename] = aes_key
    return jsonify({"message": "File uploaded and encrypted successfully"}), 201

@app.route('/download/<filename>', methods=['POST'])
def download_file(filename):
    username = request.json["username"]
    aes_key = file_keys.get(filename)

    if aes_key:
        decrypted_file_path = decrypt_file(aes_key, os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc"))
        return send_from_directory(app.config['UPLOAD_FOLDER'], decrypted_file_path)
    return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=12345, debug=True)
