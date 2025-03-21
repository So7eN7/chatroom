import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 15000
server_socket.bind((host, port))

server_socket.listen(1)
print(f"Server is listening on: {host}:{port}")

while True:
    client_socket, address = server_socket.accept()
    print(f"Connection from: {address}")

    data = client_socket.recv(1024).decode()
    print(f"Received: {data}")

    client_socket.send(data.encode())
    client_socket.close()
