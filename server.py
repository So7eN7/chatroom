import socket
import threading
import hashlib
from cryptography.fernet import Fernet

KEY = b'32-byte-key'
cipher = Fernet(Fernet.generate_key())

users = {}
users_lock = threading.Lock()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def handle_client(client_socket, address):
    print(f"New connection from {address}")
    logged_in = False

    while True:
        try:
            encrypted_data = client_socket.recv(1024).decode()
            if not encrypted_data:
                break

            data = cipher.decrypt(encrypted_data).decode() 

            parts = data.split()
            if len(parts) < 3:
                response = "Invalid command format"
                client_socket.send(cipher.encrypt(response.encode()))
                continue
            command, username, password = parts[0], parts[1], parts[2]

            if command == "Register:":
                with users_lock:
                    if username in users:
                        response = "Username already taken"
                        client_socket.send(cipher.encrypt(response.encode()))
                    else:
                        users[username] = hash_password(password)
                        response = "Registered successfully"
                        print(f"{username} registered.")

                    client_socket.send(cipher.encrypt(response.encode()))

            elif command == "Login:":
                with users_lock:
                    if username not in users:
                        response = "Username not found"
                    elif users[username] == hash_password(password):
                        response = "Login successful..."
                        logged_in = True
                        print(f"{username} logged in")
                    else:
                        response = "Incorrect Password"
                    client_socket.send(cipher.encrypt(response.encode()))
            else:
                response = "Unknown command"
                client_socket.send(cipher.encrypt(response.encode()))


            if logged_in:
                client_socket.send(cipher.encrypt("Ready for chat commands.".encode()))

        except Exception as e:
            print(f"Error handling client {address}. Exception: {e}")
            break

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
