from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room
import jwt
import datetime
import os
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA  # Ensure pycryptodome is installed
from Crypto.Cipher import PKCS1_OAEP, AES
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'supersecretkey'

# Socket for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Rate limiter to prevent excessive requests
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Simulated Database (Replace with actual DB)
users = {}
messages = {}

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

# Function to encrypt message using AES
def encrypt_message(aes_key, message):
    key = SHA256.new(aes_key).digest()[:16]  # Ensure proper key size (AES-128)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher_aes.nonce + tag + ciphertext).decode()

# Function to decrypt message using AES
def decrypt_message(aes_key, encrypted_message):
    key = SHA256.new(aes_key).digest()[:16]  # Ensure proper key size (AES-128)
    encrypted_bytes = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

@app.route('/get_users', methods=['GET'])
def get_users():
    return jsonify({"users": list(users.keys())})

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    # Hash password for security
    hashed_password = generate_password_hash(password)

    # Generate RSA key pair for user
    private_key, public_key = generate_rsa_keys()

    # Store user details
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
    username = data.get("username")
    password = data.get("password")

    # Check if user exists
    if username not in users:
        return jsonify({"error": "Invalid username or password"}), 401

    # Verify password
    if not check_password_hash(users[username]["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Generate JWT token
    token = jwt.encode(
        {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    ).decode('utf-8')

    return jsonify({"message": "Login successful", "token": token, "public_key": users[username]["public_key"]})

# Secure Key Exchange (AES key encrypted with RSA)
@app.route('/exchange-key', methods=['POST'])
def exchange_key():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")

    if sender not in users or receiver not in users:
        return jsonify({"error": "User not found"}), 404

    # Generate AES key for secure chat
    aes_key = os.urandom(16)

    # Encrypt AES key with receiver's RSA public key
    receiver_public_key = RSA.import_key(users[receiver]["public_key"])
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()

    return jsonify({"encrypted_aes_key": encrypted_aes_key})

# Real-time Encrypted Chat (Sockets)
@socketio.on('send_message')
def handle_message(data):
    sender = data.get("sender")
    receiver = data.get("receiver")
    encrypted_message = data.get("encrypted_message")  # Already AES-encrypted

    if sender not in users or receiver not in users:
        emit('error', {"error": "User not found"}, broadcast=True)
        return

    # Store encrypted message
    if receiver not in messages:
        messages[receiver] = []
    messages[receiver].append({"sender": sender, "message": encrypted_message})

    # Notify receiver
    emit('receive_message', {"sender": sender, "encrypted_message": encrypted_message}, room=receiver, broadcast=True)

# User joins a room for real-time messages
@socketio.on('join')
def on_join(data):
    username = data.get("username")
    join_room(username)
    emit('message', {"message": f"{username} joined the chat"}, room=username, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=12345, debug=True)
