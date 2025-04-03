import socket
import threading
import hashlib
import sqlite3
import base64
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

rooms = {}
rooms_lock = threading.Lock()

print("Starting DH parameter generation (this may take a few seconds)...")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("DH parameters generated successfully")
parameters_bytes = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)
print("DH parameters serialized to bytes")

def init_db():
    conn = sqlite3.connect('chatroom.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT)''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(shared_secret):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"chatroom-key")
    raw_key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(raw_key)

def broadcast(room_key, message, exclude_socket=None):
    with rooms_lock:
        if room_key not in rooms:
            print(f"Room {room_key} not found for broadcast")
            return
        for username, (sock, cipher) in list(rooms[room_key].items()):
            if sock != exclude_socket and sock.fileno() != -1:
                try:
                    encrypted_msg = cipher.encrypt(message.encode())  # Use recipient's cipher
                    sock.send(encrypted_msg)
                    print(f"Broadcasted '{message}' to {username}")
                except Exception as e:
                    print(f"Broadcast error to {username}: {e}")
                    if isinstance(e, (OSError, socket.error)) and "Broken pipe" in str(e):
                        del rooms[room_key][username]

def handle_client(client_socket, address):
    print(f"New connection from {address}")
    username = None
    current_room = None
    
    try:
        print(f"Sending DH parameters to {address}")
        client_socket.send(parameters_bytes)
        print(f"Generating private key for {address}")
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"Sending public key to {address}")
        client_socket.send(public_key_bytes)
        print(f"Receiving client public key from {address}")
        client_public_bytes = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)
        
        if not isinstance(client_public_key, dh.DHPublicKey):
            print(f"Error: Invalid public key type from {address}")
            client_socket.close()
            return
        
        print(f"Computing shared secret for {address}")
        shared_secret = private_key.exchange(client_public_key)
        key = derive_key(shared_secret)
        cipher = Fernet(key)
        print(f"DH key exchange completed for {address}")
    except Exception as e:
        print(f"Error in DH exchange with {address}: {e}")
        client_socket.close()
        return
    
    conn = sqlite3.connect('chatroom.db')
    c = conn.cursor()

    while True:
        try:
            start_time = time.time()
            encrypted_data = client_socket.recv(1024)
            recv_time = time.time()
            if not encrypted_data:
                print(f"Client {address} disconnected (no data)")
                break
            data = cipher.decrypt(encrypted_data).decode()
            print(f"Received from {address} after {recv_time - start_time:.2f}s: {data}")
            parts = data.split(" ", 3)
            
            if parts[0] == "Register:" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                c.execute("SELECT username FROM users WHERE username = ?", (username,))
                if c.fetchone():
                    client_socket.send(cipher.encrypt("Username already taken".encode()))
                else:
                    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                              (username, hash_password(password)))
                    conn.commit()
                    client_socket.send(cipher.encrypt("Registered successfully".encode()))
                    print(f"{username} registered")
            
            elif parts[0] == "Login:" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                result = c.fetchone()
                if result and result[0] == hash_password(password):
                    client_socket.send(cipher.encrypt("Login successful".encode()))
                    print(f"{username} logged in")
                else:
                    client_socket.send(cipher.encrypt("Login failed".encode()))
            
            elif parts[0] == "Key:" and username and len(parts) == 2:
                current_room = parts[1]
                with rooms_lock:
                    if current_room not in rooms:
                        rooms[current_room] = {}
                    rooms[current_room][username] = (client_socket, cipher)  # Store socket and cipher
                client_socket.send(cipher.encrypt("hello, welcome".encode()))
                print(f"Sent 'hello, welcome' to {username} for room {current_room}")
                broadcast(current_room, f"Hello {username}", client_socket)
                broadcast(current_room, f"{username} entered the chat room", client_socket)
                print(f"{username} joined room {current_room}")
            
            elif parts[0] == "Public" and username and current_room and len(parts) >= 4:
                if parts[1] == "message:" and parts[2].startswith("from=") and parts[3].startswith("length="):
                    msg_body = " ".join(parts[4:]) if len(parts) > 4 else parts[3].split("=", 1)[1]
                    broadcast(current_room, f"{username}: {msg_body}")
                    print(f"Processed public message from {username}: {msg_body} after {time.time() - start_time:.2f}s")
                else:
                    client_socket.send(cipher.encrypt("Invalid public message format".encode()))
                    print(f"Invalid public message format: {data}")
            
            elif parts[0] == "Private" and username and current_room and len(parts) >= 2:
                header_body = " ".join(parts[1:]).split(" ", 1)
                if len(header_body) == 2:
                    header_parts = header_body[0].split(", ")
                    if len(header_parts) >= 2 and header_parts[0].startswith("length="):
                        length = header_parts[0].split("=")[1]
                        recipients = [r.split("=")[1] for r in header_parts[1:] if r.startswith("to=")]
                        msg_body = header_body[1]
                        with rooms_lock:
                            for recipient in recipients:
                                if recipient in rooms[current_room] and rooms[current_room][recipient][0].fileno() != -1:
                                    recipient_socket, recipient_cipher = rooms[current_room][recipient]
                                    recipient_socket.send(
                                        recipient_cipher.encrypt(f"Private from {username}: {msg_body}".encode())
                                    )
                                    print(f"Sent private message from {username} to {recipient}: {msg_body}")
            
            elif parts[0] == "List" and username and current_room:
                with rooms_lock:
                    user_list = ", ".join(rooms[current_room].keys())
                    client_socket.send(cipher.encrypt(f"Users in room: {user_list}".encode()))
                    print(f"Sent user list to {username}: {user_list}")
            
            elif parts[0] == "Exit" and username and current_room:
                client_socket.send(cipher.encrypt("goodbye".encode()))
                with rooms_lock:
                    if username in rooms[current_room]:
                        del rooms[current_room][username]
                        if not rooms[current_room]:
                            del rooms[current_room]
                        else:
                            broadcast(current_room, f"{username} left the chat room")
                break
            
            else:
                client_socket.send(cipher.encrypt("Invalid command".encode()))
                print(f"Invalid command: {data}")
        
        except Exception as e:
            print(f"Error with {address}: {e}")
            break
    
    with rooms_lock:
        if username and current_room and current_room in rooms and username in rooms[current_room]:
            del rooms[current_room][username]
            if not rooms[current_room]:
                del rooms[current_room]
            else:
                broadcast(current_room, f"{username} left the chat room")
    client_socket.close()
    conn.close()
    print(f"Connection with {address} closed")

# Server setup
init_db()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 15000
server_socket.bind((host, port))
server_socket.listen(5)
print(f"Server listening on {host}:{port}")

while True:
    try:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server_socket.close()
        break