import socket
import threading
import tkinter as tk
import base64
import time
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Room Client")
        self.client_socket = None
        self.cipher = None
        self.username = None
        self.room_key = None
        self.running = False
        self.socket_lock = threading.Lock()

        # Login/Register Frame
        self.auth_frame = tk.Frame(root)
        self.auth_frame.pack(pady=10)
        tk.Label(self.auth_frame, text="Action:").grid(row=0, column=0)
        self.action_var = tk.StringVar(value="login")
        tk.Radiobutton(self.auth_frame, text="Login", variable=self.action_var, value="login").grid(row=0, column=1)
        tk.Radiobutton(self.auth_frame, text="Register", variable=self.action_var, value="register").grid(row=0, column=2)
        tk.Label(self.auth_frame, text="Username:").grid(row=1, column=0)
        self.username_entry = tk.Entry(self.auth_frame)
        self.username_entry.grid(row=1, column=1, columnspan=2)
        tk.Label(self.auth_frame, text="Password:").grid(row=2, column=0)
        self.password_entry = tk.Entry(self.auth_frame, show="*")
        self.password_entry.grid(row=2, column=1, columnspan=2)
        tk.Button(self.auth_frame, text="Submit", command=self.authenticate).grid(row=3, column=1, columnspan=2)

        # Room Frame
        self.room_frame = tk.Frame(root)
        tk.Label(self.room_frame, text="Room Key:").grid(row=0, column=0)
        self.room_entry = tk.Entry(self.room_frame)
        self.room_entry.grid(row=0, column=1)
        tk.Button(self.room_frame, text="Join Room", command=self.join_room).grid(row=0, column=2)

        # Chat Frame
        self.chat_frame = tk.Frame(root)
        self.chat_display = tk.Text(self.chat_frame, height=20, width=50, state="disabled")
        self.chat_display.pack(pady=5)
        self.chat_display.tag_config("public", foreground="black")
        self.chat_display.tag_config("private", foreground="blue")
        self.chat_display.tag_config("system", foreground="green")
        self.msg_entry = tk.Entry(self.chat_frame, width=40)
        self.msg_entry.pack(side=tk.LEFT, pady=5)
        tk.Button(self.chat_frame, text="Send", command=self.send_message).pack(side=tk.LEFT)
        tk.Button(self.chat_frame, text="List Users", command=self.list_users).pack(side=tk.LEFT)
        tk.Button(self.chat_frame, text="Exit", command=self.exit_chat).pack(side=tk.LEFT)

    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("127.0.0.1", 15000))
        self.client_socket.settimeout(5.0)
        parameters_bytes = self.client_socket.recv(2048)
        parameters = serialization.load_pem_parameters(parameters_bytes)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        server_public_bytes = self.client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(server_public_bytes)
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(public_key_bytes)
        
        if not isinstance(server_public_key, dh.DHPublicKey):
            raise ValueError("Invalid server public key type")
        
        shared_secret = private_key.exchange(server_public_key)
        key = derive_key(shared_secret)
        self.cipher = Fernet(key)

    def authenticate(self):
        action = self.action_var.get()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        try:
            self.connect()
            command = f"{action.capitalize()}: {username} {password}"
            self.client_socket.send(self.cipher.encrypt(command.encode()))
            response = self.cipher.decrypt(self.client_socket.recv(1024)).decode()
            print(f"Auth response: {response}")
            if response == "Login successful":
                self.username = username
                self.auth_frame.pack_forget()
                self.room_frame.pack(pady=10)
                self.running = True
            elif response == "Registered successfully":
                messagebox.showinfo("Success", "Registered successfully. Please login.")
            else:
                messagebox.showerror("Error", response)
                self.cleanup_socket()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            self.cleanup_socket()

    def join_room(self):
        self.room_key = self.room_entry.get().strip()
        if not self.room_key:
            messagebox.showerror("Error", "Room key required")
            return
        try:
            with self.socket_lock:
                if not self.client_socket or self.client_socket.fileno() == -1:
                    raise ConnectionError("Socket is closed")
                print(f"Sending room key: {self.room_key}")
                self.client_socket.send(self.cipher.encrypt(f"Key: {self.room_key}".encode()))
            response = self.cipher.decrypt(self.client_socket.recv(1024)).decode()
            print(f"Join room response: {response}")
            if response == "hello, welcome":
                self.room_frame.pack_forget()
                self.chat_frame.pack(pady=10)
                self.chat_display.config(state="normal")
                self.chat_display.insert(tk.END, f"Connected to room {self.room_key}\n", "system")
                self.chat_display.config(state="disabled")
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                messagebox.showerror("Error", f"Failed to join room: {response}")
        except socket.timeout:
            messagebox.showerror("Error", "Server response timed out. Try again.")
        except Exception as e:
            messagebox.showerror("Error", f"Join room failed: {e}")
            print(f"Join room exception: {e}")

    def receive_messages(self):
        while self.running:
            try:
                with self.socket_lock:
                    if not self.client_socket or self.client_socket.fileno() == -1:
                        print("Socket closed, stopping receive thread")
                        break
                    start_time = time.time()
                    encrypted_data = self.client_socket.recv(1024)
                    recv_time = time.time()
                if not encrypted_data:
                    print("Received empty data, checking if intentional")
                    continue
                message = self.cipher.decrypt(encrypted_data).decode()
                print(f"Received message after {recv_time - start_time:.2f}s: {message}")
                if message == "goodbye":
                    self.running = False
                    self.chat_display.config(state="normal")
                    self.chat_display.insert(tk.END, "Disconnected from room\n", "system")
                    self.chat_display.config(state="disabled")
                    break
                self.chat_display.config(state="normal")
                if message.startswith("Private from"):
                    self.chat_display.insert(tk.END, f"{message}\n", "private")
                elif message.endswith("entered the chat room") or message.endswith("left the chat room"):
                    self.chat_display.insert(tk.END, f"{message}\n", "system")
                elif message.startswith("Users in room:"):
                    self.chat_display.insert(tk.END, f"{message}\n", "system")
                else:
                    self.chat_display.insert(tk.END, f"{message}\n", "public")
                self.chat_display.config(state="disabled")
                self.chat_display.see(tk.END)
            except socket.timeout:
                print("Receive timeout after 5s, continuing")
                continue
            except ConnectionResetError as e:
                print(f"Receive error: Connection reset by server - {e}")
                break
            except BrokenPipeError as e:
                print(f"Receive error: Broken pipe - {e}")
                break
            except Exception as e:
                print(f"Receive error: {type(e).__name__} - {e}")
                if "connection" in str(e).lower() or "broken pipe" in str(e).lower():
                    break
        if self.running:
            self.root.after(0, self.handle_disconnect)
        self.cleanup_socket()

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        print(f"Preparing to send message: {msg}")
        parts = msg.split(" ", 2)
        if parts[0].lower() == "private" and len(parts) == 3:
            recipients, body = parts[1], parts[2]
            command = f"Private message: length={len(body)}, to={recipients} {body}"
        else:
            command = f"Public message: from={self.username} length={len(msg)} {msg}"
        self.send_command(command)
        self.msg_entry.delete(0, tk.END)

    def list_users(self):
        self.send_command("List")

    def send_command(self, command):
        try:
            with self.socket_lock:
                if not self.client_socket or self.client_socket.fileno() == -1:
                    raise ConnectionError("Socket is closed")
                print(f"Sending command: {command}")
                start_time = time.time()
                self.client_socket.send(self.cipher.encrypt(command.encode()))
                send_time = time.time()
                print(f"Command sent successfully after {send_time - start_time:.2f}s")
        except socket.timeout:
            messagebox.showerror("Error", "Send timed out. Server may be unresponsive.")
        except Exception as e:
            print(f"Send error: {type(e).__name__} - {e}")
            messagebox.showerror("Error", f"Send failed: {e}")
            self.handle_disconnect()

    def exit_chat(self):
        self.running = False
        self.send_command("Exit")
        self.chat_frame.pack_forget()
        self.auth_frame.pack(pady=10)

    def cleanup_socket(self):
        with self.socket_lock:
            if self.client_socket and self.client_socket.fileno() != -1:
                try:
                    self.client_socket.close()
                except:
                    pass
            self.client_socket = None
        self.running = False

    def handle_disconnect(self):
        messagebox.showerror("Error", "Lost connection to server")
        self.chat_frame.pack_forget()
        self.auth_frame.pack(pady=10)

def derive_key(shared_secret):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"chatroom-key")
    raw_key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(raw_key)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()