import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 15000

client_socket.connect((host, port))

message = input("Enter your message: ")
client_socket.send(message.encode())

response = client_socket.recv(1024).decode()
print(f"Server response: {response}")

client_socket.close()
