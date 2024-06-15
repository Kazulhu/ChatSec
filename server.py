import socket
import threading
import datetime

# Initialisation des logs
log_connections_file = 'log_connections.txt'
log_messages_file = 'log_messages.txt'

def log_connection(client_address):
    with open(log_connections_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - Connection from {client_address[0]}:{client_address[1]}\n')

def log_disconnection(username, client_address):
    with open(log_connections_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - Disconnection of {username} ({client_address[0]}:{client_address[1]})\n')

def log_message(message):
    with open(log_messages_file, 'a') as log_file:
        log_file.write(f'{datetime.datetime.now()} - {message}\n')

def handle_client(client_socket, client_address):
    log_connection(client_address)
    username = None
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            
            # Traite le message de connexion de l'utilisateur
            if message.startswith("NEW_USER:"):
                username = message[len("NEW_USER:"):].strip()
                clients[username] = client_socket
                update_user_list()
                continue
            
            # Journalise le message
            log_message(message)

            # Diffusion des messages à tous les clients
            if message.startswith("DM:"):
                _, sender, recipient, dm_message = message.split(":", 3)
                if recipient in clients:
                    clients[recipient].send(message.encode('utf-8'))
            else:
                broadcast(message, client_socket)
        except:
            break
    
    if username:
        log_disconnection(username, client_address)
        del clients[username]
        update_user_list()
    client_socket.close()

def broadcast(message, sender_socket):
    for client_socket in clients.values():
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except:
                pass

def update_user_list():
    user_list = "USER_LIST:" + ",".join(clients.keys())
    for client_socket in clients.values():
        try:
            client_socket.send(user_list.encode('utf-8'))
        except:
            pass

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    print("Server started on port 12345")

    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    clients = {}
    start_server()
