import socket

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

client_socket.send(command.encode())

response = client_socket.recv(1024).decode()
print(f"Server response: {response}")

if response == "Login successful":
    next_response = client_socket.recv(1024).decode()
    print(f"Server response: {next_response}")

client_socket.close()
