import rsa
import datetime
import sys
from server import PRIVKEY  #If the server is constantly running

PRIVKEY = "<your private key here>"

# Chemin vers le fichier de log
log_messages_file = 'log_messages.txt'

# Fonction pour lire et déchiffrer les messages à partir du fichier de log
def read_and_decrypt_log(log_file):
    with open(log_file, 'r') as log:
        for line in log:
            if line.strip():  # Ignorer les lignes vides
                timestamp, encrypted_message = line.split(' - ')
                encrypted_message = bytes.fromhex(encrypted_message.strip())
                decrypted_message = rsa.decrypt(encrypted_message, PRIVKEY).decode('utf-8')
                print(f'{timestamp} - {decrypted_message}')

# Exécution du script avec gestion de ligne de commande
if __name__ == '__main__':
    if len(sys.argv) > 1:
        log_messages_file = sys.argv[1]  # Utilisation du chemin fourni en argument
    read_and_decrypt_log(log_messages_file)
