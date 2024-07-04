import sqlite3
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class MessageTableManagement:
    def __init__(self, db_filename='messages.db'):
        self.db_filename = db_filename
        self.create_table_message()

    def create_table_message(self):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    destinataire TEXT NOT NULL,
                    encrypted_message BLOB NOT NULL,
                    stored_time TEXT NOT NULL
                )
            ''')

    def store_message(self, source, destinataire, message, public_key_pem):
        encrypted_message = self.encrypt_message(message, public_key_pem)
        stored_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                INSERT INTO messages (source, destinataire, encrypted_message, stored_time)
                VALUES (?, ?, ?, ?)
            ''', (source, destinataire, encrypted_message, stored_time))

    def get_messages(self, destinataire, private_key_pem):
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.execute('''
                SELECT source, encrypted_message, stored_time FROM messages WHERE destinataire = ?
            ''', (destinataire,))
            messages = []
            for row in cursor.fetchall():
                source, encrypted_message, stored_time = row
                decrypted_message = self.decrypt_message(encrypted_message, private_key_pem)
                messages.append((source, decrypted_message, stored_time))
            return messages

    def encrypt_message(self, message, public_key_pem):
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self, encrypted_message, private_key_pem):
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()

    def delete_old_messages(self, older_than_days):
        one_day_ago = datetime.datetime.now() - datetime.timedelta(days=older_than_days)
        one_day_ago_str = one_day_ago.strftime('%Y-%m-%d %H:%M:%S')
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                DELETE FROM messages WHERE stored_time < ?;
            ''', (one_day_ago_str,))

    def __del__(self):
        self.close()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem