import socket
from cryptography.fernet import Fernet

KEY = b'32-byte-key'
cipher = Fernet(Fernet.generate_key())


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 15000

client_socket.connect((host, port))

action = input("Register or Login: ").strip().lower()
username = input("Username: ").strip()
password = input("Password: ").strip()

if action == "register":
    command = f"Register: {username} {password}"
elif action == "login":
    command = f"Login: {username} {password}"
else:
    print("Invalid action")
    client_socket.close()
    exit()

encrypted_command = cipher.encrypt(command.encode())
client_socket.send(encrypted_command)

encrypted_response = client_socket.recv(1024).decode()
response = cipher.decrypt(encrypted_response).decode()
print(f"Server response: {response}")

if response == "Login successful":
    encrypted_next_response = client_socket.recv(1024).decode()
    next_response = cipher.decrypt(encrypted_next_response).decode()
    print(f"Server response: {next_response}")

client_socket.close()
