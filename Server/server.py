import socket
import threading
import datetime
import sqlite3
import pyotp
import qrcode
import secrets
import ssl
import pyargon2
import rsa

# Initialisation des logs
log_connections_file = 'log_connections.txt'
log_messages_file = 'log_messages.txt'
log_login_file = 'log_login.txt'

# List to keep track of connected clients
connected_clients = []
username_to_address = {}
clients_lock = threading.Lock()

#cypher the logs messages
(PUBKEY, PRIVKEY) = rsa.newkeys(512)


# Function to log connections
def log_connection(client_address):
    with open(log_connections_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - Connection from {client_address[0]}:{client_address[1]}\n')
        print(f'{datetime.datetime.now()} - Connection from {client_address[0]}:{client_address[1]}\n')

# Function to log disconnections
def log_disconnection(client_address, username=None):
    if username!=None:
        with open(log_connections_file, 'a') as log_file:
            log_file.write(f'{datetime.datetime.now()} - Disconnection of {username} ({client_address[0]}:{client_address[1]})\n')
    else:
        with open(log_connections_file, 'a') as log_file:
            log_file.write(f'{datetime.datetime.now()} - Disconnected from ({client_address[0]}:{client_address[1]})\n')

# Function to log messages
def log_message(message):
    with open(log_messages_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - {rsa.encrypt(message,PUBKEY)}\n')

# User management class
class UserManager:
    def __init__(self, db_filename='users.db'):
        self.db_filename = db_filename
        self.create_users_table()

    def create_users_table(self):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hashed_password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    secret TEXT NOT NULL
                )
            ''')

    def register_user(self, username, hashed_password, salt, secret):
        if self.user_exists(username):
            return False  # User already exists
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                INSERT INTO users (username, hashed_password, salt, secret)
                VALUES (?, ?, ?, ?)
            ''', (username, hashed_password, salt, secret))
        return True
    
    def get_salt(self, username):
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.execute('''
                SELECT salt FROM users WHERE username = ?
            ''', (username,))
            return cursor.fetchone()

    def user_exists(self, username):
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.execute('''
                SELECT 1 FROM users WHERE username = ?
            ''', (username,))
            return cursor.fetchone() is not None

    def authenticate_user(self, username, hashed_password):
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.execute('''
                SELECT hashed_password, salt FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            stored_password, salt = row
            return hashed_password == stored_password
        
    def verify_otp(self, username, log_otp):
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.execute('''
                SELECT username, secret FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            _, stored_otp = row
            totp = pyotp.TOTP(stored_otp)
            return totp.verify(log_otp)

def handle_client(client_socket, client_address, user_manager):
    log_connection(client_address)
    username = None

    with clients_lock:
        connected_clients.append(client_socket)

    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break

            # Handle registration and login messages
            if message.startswith("REGISTER:"):
                _, reg_username, reg_hashed_password, reg_salt, reg_secret = message.split(":")
                if user_manager.register_user(reg_username, reg_hashed_password, reg_salt, reg_secret):
                    client_socket.send("REGISTER_SUCCESS".encode('utf-8'))
                else:
                    client_socket.send("REGISTER_FAILURE".encode('utf-8'))

            elif message.startswith("LOGIN_USER:"):
                _, log_username = message.split(":")
                if user_manager.user_exists(log_username):
                    log_salt = user_manager.get_salt(log_username)[0]
                    client_socket.send(f"LOGIN_USER_SUCCESS:{log_salt}".encode('utf-8'))
                else:
                    client_socket.send("LOGIN_USER_FAILURE".encode('utf-8'))

            elif message.startswith("LOGIN_PASS:"):
                _, log_username, log_hashed_password, log_otp = message.split(":")
                if user_manager.authenticate_user(log_username, log_hashed_password) and user_manager.verify_otp(log_username, log_otp):
                    client_socket.send("LOGIN_PASS_SUCCESS".encode('utf-8'))
                    username = log_username
                    with open(log_login_file, 'a') as log_file:
                        log_file.write(f'{datetime.datetime.now()} - {username} logged in from ({client_address[0]}:{client_address[1]})\n')
                else:
                    client_socket.send("LOGIN_PASS_FAILURE".encode('utf-8'))


            elif message.startswith("NEW_USER:"):
                _, message = message.split(':') 
                response = f'{message} joined the chat'
                username = message
                with open(log_messages_file, 'a') as log_file:
                    log_file.write(f'{datetime.datetime.now()} - {username} successfully joined the chat from ({client_address[0]}:{client_address[1]})\n')
                with clients_lock:
                    for client in connected_clients:
                        client.send(response.encode('utf-8'))

            # Handle other messages and broadcast them to all clients
            else:
                log_message(message)
                response = f'{message}'
                with clients_lock:
                    for client in connected_clients:
                        client.send(response.encode('utf-8'))

    except ConnectionResetError:
        pass

    finally:
        with clients_lock:
            connected_clients.remove(client_socket)
            if username != None:
                for client in connected_clients:
                    client.send(f'{username} left the chat.'.encode('utf-8'))
            if username in username_to_address:
                del username_to_address[username]
        client_socket.close()
        if username != None:
            log_disconnection(client_address, username)
            print(f'{datetime.datetime.now()} - Disconnection of {username} ({client_address[0]}:{client_address[1]})\n')
        else:
            log_disconnection(client_address)
            print(f'Disconnected from {client_address[0]}:{client_address[1]}')

def start_server(host='127.0.0.1', port=12345):
    user_manager = UserManager()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("../CERT/cert-server.pem","../CERT/cert-key.pem")

    server_ssl = context.wrap_socket(server_socket, server_side=True)

    print(f'Server listening on {host}:{port}')
    while True:
        client_socket, client_address = server_ssl.accept()
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address, user_manager)
        )
        client_handler.start()

if __name__ == '__main__':
    start_server()
