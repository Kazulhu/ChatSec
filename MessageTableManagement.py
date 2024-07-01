import sqlite3
import datetime

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
        self.db_filename = db_filename
        self.table = self.CreateTableMessage()

    
    def CreateTableMessage(self):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INT PRIMARY KEY,
                    source TEXT NOT NULL,
                    destinataire TEXT NOT NULL,
                    message TEXT NOT NULL,
                    StoredTime TEXT NOT NULL
                )
            ''')

    def StoreMessage(self, id, source, destinataire, message):
        with sqlite3.connect(self.db_filename) as conn:
            conn.execute('''
                INSERT INTO messages (id, source, destinataire, message, StoredTime)
                VALUES (?, ?, ?, ?, ?)
            ''', (id, source, destinataire , (message), datetime.datetime.now()))

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
    
    def TimeLimiteDeleteMessage(self):
        with sqlite3.connect(self.db_filename) as conn:
            one_minute_ago = datetime.datetime.now() - datetime.timedelta(minutes=1440)
            one_minute_ago_str = one_minute_ago.strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('''
                DELETE FROM messages WHERE StoredTime < ?;
            ''', (one_minute_ago_str,))


#Test = MessageTableManagement()
#Test.TimeLimiteDeleteMessage()
#Test.StoreMessage(8,"Antoine", "Guillaume", "A plus")

