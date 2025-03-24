import socket
import threading
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import base64

parameters = dh.generate_parameters(generator=2, key_size=2048)
parameters_bytes = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

users = {}
rooms = {}
users_lock = threading.Lock()
rooms_lock = threading.Lock()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chatroom-key"
    )
    raw_key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(raw_key)

def broadcast(room_key, message, exclude_socket=None):
    with rooms_lock:
        if room_key in rooms:
            for username, socket in rooms[room_key].items():
                if socket != exclude_socket:
                    try:
                        socket.send(cipher.encrypt(message.encode()))
                    except:
                        pass

def handle_client(client_socket, address):
    print(f"New connection from {address}")
    username = None
    current_room = None

   # Diffie-Hellman key exchange
    try:
        # Send DH parameters to client
        client_socket.send(parameters_bytes)
        
        # Generate server private/public key pair
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(public_key_bytes)
        
        # Receive client public key
        client_public_bytes = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)
        
        # Verify type
        if not isinstance(client_public_key, dh.DHPublicKey):
            print(f"Error: Invalid public key type from {address}")
            client_socket.close()
            return
        
        # Compute shared secret
        shared_secret = private_key.exchange(client_public_key)
        key = derive_key(shared_secret)
        global cipher  # Simplified for example; avoid in production
        cipher = Fernet(key)
    except Exception as e:
        print(f"Error in DH exchange with {address}: {e}")
        client_socket.close()
        return

    while True:
        try:
            encrypted_data = client_socket.recv(1024).decode()
            if not encrypted_data:
                break

            data = cipher.decrypt(encrypted_data).decode() 

            parts = data.split()
            if len(parts) < 2:
                client_socket.send(cipher.encrypt("Invalid command format".encode()))
                continue

            command = parts[0]

            if command == "Register:" and len(parts) == 3:
                username, password = parts[1], parts[2]
                with users_lock:
                    if username in users:
                        client_socket.send(cipher.encrypt("Username already taken".encode()))
                    else:
                        users[username] = hash_password(password)
                        client_socket.send(cipher.encrypt("Registered successfully".encode()))
                        print(f"{username} registered.")


            elif command == "Login:" and len(parts) == 3:
                username, password = parts[1], parts[2]
                with users_lock:
                    if username not in users:
                        client_socket.send(cipher.encrypt("Username not found".encode()))
                    elif users[username] == hash_password(password):
                        client_socket.send(cipher.encrypt("Login successful...".encode()))
                        print(f"{username} logged in")
                    else:
                        client_socket.send(cipher.encrypt("Incorrect password".encode()))
            elif command == "Key:" and len(parts) == 2 and username:
                current_room = parts[1]
                with rooms_lock:
                    if current_room not in rooms:
                        rooms[current_room] = {}
                    rooms[current_room][username] = client_socket

                client_socket.send(cipher.encrypt("Hello, welcome".encode()))
                broadcast(current_room, f"Hello {username}", client_socket)
                broadcast(current_room, f"{username} entered the chat room")
                print(f"{username} joined from {current_room}")
            else:
                client_socket.send(cipher.encrypt("Invalid command".encode()))


        except Exception as e:
            print(f"Error handling client {address}. Exception: {e}")
            break

    if username and current_room and current_room in rooms:
        with rooms_lock:
            if username in rooms[current_room]:
                del rooms[current_room][username]
                if not rooms[current_room]:
                    del rooms[current_room]
                else:
                    broadcast(current_room, f"{username} left the chat room")
    client_socket.close()
    print(f"Connection with {address} closed")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 15000
server_socket.bind((host, port))

server_socket.listen(7)
print(f"Server is listening on: {host}:{port}")

while True:
    try:
        client_socket, address = server_socket.accept()
        print(f"Connection from: {address}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server_socket.close()
        break
