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
command = f"{action.capitalize()}: {username} {password}"

client_socket.send(cipher.encrypt(command.encode()))

response = cipher.decrypt(client_socket.recv(1024)).decode()
print(f"Server response: {response}")

if response == "Login successful":
    room_key = input("Enter room key: ").strip()
    client_socket.send(cipher.encrypt(f"Key: {room_key}".encode()))

    welcome = cipher.decrypt(client_socket.recv(1024)).decode()
    print(f"Server response: {welcome}")

    notification = cipher.decrypt(client_socket.recv(1024)).decode()
    print(f"Room: {notification}")

client_socket.close()
