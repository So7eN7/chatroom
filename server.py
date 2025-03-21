import socket
import threading

def handle_client(client_socket, address):
    try:
        data = client_socket.recv(1024).decode()
        print(f"From {address} received: {data}")

        client_socket.send(data.encode())
        print(f"Echoed {data} from {address}")
    except Exception as e:
        print(f"Error handling client {address}. Exception: {e}")
    client_socket.close()
    print(f"Connection with {address} closed")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 15000
server_socket.bind((host, port))

server_socket.listen(7)
print(f"Server is listening on: {host}:{port}")

while True:
    client_socket, address = server_socket.accept()
    print(f"Connection from: {address}")

    client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
    client_thread.start()
