import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import base64

def derive_key(shared_secret):
    """Derive a symmetric key from the DH shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chatroom-key"
    )
    raw_key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(raw_key)

def main():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = "127.0.0.1"
    port = 15000

    client_socket.connect((host, port))

    # Diffie-Hellman key exchange
    try:
        # Receive DH parameters from server
        parameters_bytes = client_socket.recv(2048)
        parameters = serialization.load_pem_parameters(parameters_bytes)
        
        # Generate client private/public key pair using server parameters
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # Receive server public key
        server_public_bytes = client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(server_public_bytes)
        
        # Send client public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(public_key_bytes)
        
        # Verify type
        if not isinstance(server_public_key, dh.DHPublicKey):
            print("Error: Invalid public key type from server")
            client_socket.close()
            return
        
        # Compute shared secret
        shared_secret = private_key.exchange(server_public_key)
        key = derive_key(shared_secret)
        cipher = Fernet(key)
    except Exception as e:
        print(f"Error in DH exchange: {e}")
        client_socket.close()
        return

    action = input("Register or Login: ").strip().lower()
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    command = f"{action.capitalize()}: {username} {password}"

    client_socket.send(cipher.encrypt(command.encode()))

    response = cipher.decrypt(client_socket.recv(1024)).decode()
    print(f"Server response: {response}")

    if response == "Login successful...":
        room_key = input("Enter room key: ").strip()
        client_socket.send(cipher.encrypt(f"Key: {room_key}".encode()))

        welcome = cipher.decrypt(client_socket.recv(1024)).decode()
        print(f"Server response: {welcome}")

        notification = cipher.decrypt(client_socket.recv(1024)).decode()
        print(f"Room: {notification}")

        while True:
            msg_type = input("Type 'public' or 'private' (or 'exit'): ").strip().lower()
            if msg_type == "exit":
                break
            message = input("Message: ").strip()
            if msg_type == "public":
                command = f"Public message: from={username} length={len(message)} {message}"
                client_socket.send(cipher.encrypt(command.encode()))
            elif msg_type == "private":
                recipients = input("To (comma-separated usernames): ").strip().replace(" ", "")
                command = f"Private message: length={len(message)}, to={recipients} {message}"
                client_socket.send(cipher.encrypt(command.encode()))

            try:
                response = cipher.decrypt(client_socket.recv(1024)).decode()
                print(f"Room: {response}")
            except:
                pass

    client_socket.close()

if __name__ == "__main__":
    main()
