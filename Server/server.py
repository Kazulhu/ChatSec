import socket
import threading
import datetime
import sqlite3
import pyotp
import qrcode
import secrets
import ssl
import rsa as rs
import pyargon2
import os
import shutil
from messageTableManagement import *

# Initialisation des logs
log_connections_file = 'log_connections.txt'
log_messages_file = 'log_messages.txt'
log_login_file = 'log_login.txt'

#cypher the logs messages
(PUBKEY, PRIVKEY) = rs.newkeys(512)

# List to keep track of connected clients
connected_clients = []
username_to_socket = {}
clients_lock = threading.Lock()

def save_private_key(private_key, filename='message_private_key.pem'):
    index = 1
    while os.path.exists(filename):
        filename = f"{os.path.splitext(filename)[0]}_{index}.pem"
        index += 1
    
    with open(filename, 'wb') as f:
        f.write(private_key.save_pkcs1())

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
            print(f'{datetime.datetime.now()} - Disconnection of {username} ({client_address[0]}:{client_address[1]})\n')
    else:
        with open(log_connections_file, 'a') as log_file:
            log_file.write(f'{datetime.datetime.now()} - Disconnected from ({client_address[0]}:{client_address[1]})\n')
            print(f'{datetime.datetime.now()} - Disconnected from ({client_address[0]}:{client_address[1]})\n')

# Function to log messages
def log_message(message):
    with open(log_messages_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - {rs.encrypt(message.encode('utf8'),PUBKEY)}\n')

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

def delete_files():
    if os.path.exists(files_folder):
        shutil.rmtree(files_folder)

def update_user_list():
    user_list = ','.join(username_to_socket.keys())
    with clients_lock:
        for client in connected_clients:
            client.send(f"USER_LIST:{user_list}".encode('utf-8'))

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
                    username_to_socket[username] = client_socket
                    with open(log_login_file, 'a') as log_file:
                        log_file.write(f'{datetime.datetime.now()} - {username} logged in from ({client_address[0]}:{client_address[1]})\n')
                    print(f'{datetime.datetime.now()} - {username} logged in from ({client_address[0]}:{client_address[1]})\n')
                    update_user_list()
                else:
                    client_socket.send("LOGIN_PASS_FAILURE".encode('utf-8'))

            elif message.startswith("UPLOAD_FILE:"):
                filename = message.split(":")[1]
                threading.Thread(target=handle_file_upload, args=(client_socket, filename)).start()
                

            elif message.startswith("DOWNLOAD_FILE:"):
                filename = message.split(":")[1]
                threading.Thread(target=handle_file_download, args=(client_socket, filename)).start()

            elif message.startswith("ACCEPT_DOWNLOAD:"):
                filename = message.split(":")[1]
                threading.Thread(target=handle_file_download, args=(client_socket, filename)).start()     

            elif message.startswith("REPORT:"):
                _, reporter_username, reported_username = message.split(":")
                report_message = f"User '{reporter_username}' reported user '{reported_username}'."
                log_message(report_message)
                print(report_message)

            elif message.startswith("NEW_USER:"):
                _, message = message.split(':') 
                response = f'{message} joined the chat'
                username = message
                with open(log_messages_file, 'a') as log_file:
                    log_file.write(f'{datetime.datetime.now()} - {username} successfully joined the chat from ({client_address[0]}:{client_address[1]})\n')
                with clients_lock:
                    for client in connected_clients:
                        client.send(response.encode('utf-8'))

            elif message.startswith("DM:"):
                _, sender, recipient, dm_content = message.split(":")
                recipient_socket = find_client_socket(recipient)
                if recipient_socket:
                    recipient_socket.send(f"DM:{sender}:{recipient}:{dm_content}".encode('utf-8'))
                

            elif message.startswith("LOGOUT:"):
                _, username = message.split(":")
                del username_to_socket[username]
                print(f"User logged out: {username}")
                update_user_list()


            # Handle other messages and broadcast them to all clients
            else:
                log_message(message)
                response = f'{message}'
                with clients_lock:
                    for client in connected_clients:
                        client.sendall(response.encode('utf-8'))

    except ConnectionResetError:
        pass

    finally:
        #delete_files()
        with clients_lock:
            connected_clients.remove(client_socket)

            if username != None:
                for client in connected_clients:
                    client.send(f'{username} left the chat.'.encode('utf-8'))
                del username_to_socket[username]

        update_user_list()
        client_socket.close()
        if username != None:
            log_disconnection(client_address, username)
            print(f'{datetime.datetime.now()} - Disconnection of {username} ({client_address[0]}:{client_address[1]})\n')
        else:
            log_disconnection(client_address)

def find_client_socket(username):
    if username in username_to_socket:
        return username_to_socket[username]
    else:
        return None

def handle_file_upload(client_socket, filename):
    filepath = os.path.join(files_folder, filename)
    with open(filename, 'wb') as file:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                file.write(data)
    print(f"File '{filename}' received successfully.")
    broadcast_file_link(filename)


def handle_file_download(client_socket, filename):
    filepath = os.path.join(files_folder, filename)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            client_socket.send(chunk)
    client_socket.send(b"END_OF_FILE")

def broadcast_file_link(filename):
    message = f'FILE_LINK:{filename}'
    with clients_lock:
        for client in connected_clients:
            client.send(message.encode('utf-8'))


def start_server(host='0.0.0.0', port=443):
    user_manager = UserManager()
    message_manager = MessageTableManagement()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    global files_folder
    files_folder = 'files'
    if not os.path.exists(files_folder):
        os.makedirs(files_folder)


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
    save_private_key(PRIVKEY)
    start_server()
