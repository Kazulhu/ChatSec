import sqlite3

def Chiffrement(text):
    result = ""

    for char in text:
        if char.isupper():
            result += chr((ord(char) - ord('A') + 15) % 26 + ord('A'))
        elif char.islower():
            result += chr((ord(char) - ord('a') + 15) % 26 + ord('a'))
        else:
            result += char

    return result

class MessageTableManagement:

    def __init__(self, db_filename='messages.db'):
        self.db_filenale = db_filename
        self.table = self.CreateTableMessage()

    
    def CreateTableMessage(self):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messgaes (
                    source TEXT PRIMARY KEY,
                    destinataire TEXT PRIMARY KEY,
                    message TEXT NOT NULL,
                )
            ''')

    def StoreMessage(self, source, destinataire, message):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                INSERT INTO users (username, hashed_password, salt)
                VALUES (?, ?, ?)
            ''', (source, destinataire , Chiffrement(message)))