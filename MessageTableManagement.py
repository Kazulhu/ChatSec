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
                CREATE TABLE IF NOT EXISTS messages (
                    source TEXT PRIMARY KEY,
                    destinataire TEXT PRIMARY KEY,
                    message TEXT NOT NULL,
                )
            ''')

    def StoreMessage(self, source, destinataire, message):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                INSERT INTO messages (source, destinataire, message)
                VALUES (?, ?, ?)
            ''', (source, destinataire , Chiffrement(message)))

    def GetMessageFromDatabase(self, SourceUsername, DestinataireUsername, DMmode):
        with sqlite3.connect(self.db_filenale) as file:
            if not DMmode:
                file.execute('''
                         SELECT * FROM messages WHERE source = ?
                         ''', (SourceUsername))
            else:
                file.execute('''
                         SELECT * FROM messages WHERE source = ? AND destinataire = ?
                         ''', (SourceUsername, DestinataireUsername))
