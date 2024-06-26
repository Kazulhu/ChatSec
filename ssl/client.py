import socket
import ssl

#Définir le Socket
host = "192.168.1.13"
port = 10500
socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Création du context ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context. load_verify_locations("CA/ca-cert. pem")

#Secure the client
client_ssl = context.wrap_socket(socket_obj, server_hostname=host)
client_ssl.connect((host,port))

#Echange d'un message

msg = input("-> "). encode()
client_ssl.send(msg)