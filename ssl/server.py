import socket
import ssl

#Définir le Socket
host = "192.168.1.13"
port = 10500
socket_obj = socket.socket(socket.AF_INET, socket. SOCK_STREAM)

#Création d'un context (permettant l'implémentation de SSL)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context. load_cert_chain("CERT/cert-server.pem","CERT/cert-key.pem")

#Start Server
socket_obj.bind((host,port))
socket_obj. listen(5)
print("Server start")

#Secure the server
server_ssl = context.wrap_socket(socket_obj, server_side=True)

#Accept Connection
client, ip = server_ssl.accept ()
print("L'ip", ip,"c'est connecté")

#recevoir un message
msg = client.recv(1024).decode()
print("Client :",msg)

client.close()
server_ssl.close()
socket_obj.close()