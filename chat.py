import sys
import socket
import threading
from PyQt5.QtWidgets import (QApplication, QWidget, QTextEdit, QLineEdit, QPushButton, 
                             QVBoxLayout, QHBoxLayout, QListWidget, QMenu, QAction, QMessageBox, QStackedWidget)
from PyQt5.QtCore import pyqtSignal, Qt, QPoint

# Classe représentant une fenêtre de messagerie directe (DM) avec un autre utilisateur
class DMWindow(QWidget):
    def __init__(self, username, recipient, client_socket):
        super().__init__()

        self.username = username  # Nom d'utilisateur actuel
        self.recipient = recipient  # Destinataire du message
        self.client_socket = client_socket  # Socket client pour la communication

        self.setWindowTitle(f'DM with {self.recipient}')  # Titre de la fenêtre DM

        self.layout = QVBoxLayout()  # Disposition verticale principale

        # Zone de texte pour afficher les messages de chat, en lecture seule
        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.layout.addWidget(self.chat_area)

        # Champ de saisie pour les messages
        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText('Type your message here...')
        self.layout.addWidget(self.message_input)

        # Bouton pour envoyer les messages
        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        # Bouton pour revenir au chat global
        self.back_button = QPushButton('Back to Global Chat', self)
        self.back_button.clicked.connect(self.go_back)
        self.layout.addWidget(self.back_button)

        self.setLayout(self.layout)  # Appliquer la disposition
        self.setGeometry(100, 100, 800, 600)  # Définir la taille de la fenêtre

    # Méthode pour envoyer un message
    def send_message(self):
        message = self.message_input.text()
        if message:
            self.message_input.clear()  # Effacer le champ de saisie après l'envoi
            message_with_recipient = f"DM:{self.username}:{self.recipient}:{message}"
            self.client_socket.send(message_with_recipient.encode('utf-8'))  # Envoyer le message au serveur
            self.chat_area.append(f"{self.username}: {message}")  # Afficher le message envoyé dans la zone de chat

    # Méthode pour revenir à la fenêtre de chat global
    def go_back(self):
        self.parent().setCurrentIndex(0)  # Changer l'index du widget empilé pour revenir au chat global

# Classe représentant la fenêtre principale de chat
class ChatWindow(QWidget):
    message_received = pyqtSignal(str)  # Signal pour recevoir des messages
    users_list_updated = pyqtSignal(list)  # Signal pour mettre à jour la liste des utilisateurs

    def __init__(self, username, stacked_widget, client_socket):
        super().__init__()

        self.username = username  # Nom d'utilisateur actuel
        self.stacked_widget = stacked_widget  # Widget empilé pour gérer plusieurs fenêtres
        self.client_socket = client_socket  # Socket client pour la communication
        self.dm_windows = {}  # Dictionnaire pour gérer les fenêtres DM ouvertes

        self.setWindowTitle(f'Chat - {self.username}')  # Titre de la fenêtre de chat

        self.layout = QVBoxLayout()  # Disposition verticale principale

        self.chat_layout = QHBoxLayout()  # Disposition horizontale pour le chat et la liste des utilisateurs
        # Zone de texte pour afficher les messages de chat global, en lecture seule
        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.chat_layout.addWidget(self.chat_area)

        # Liste des utilisateurs connectés
        self.users_list = QListWidget(self)
        self.users_list.setContextMenuPolicy(Qt.CustomContextMenu)  # Menu contextuel pour les utilisateurs
        self.users_list.customContextMenuRequested.connect(self.show_user_menu)
        self.chat_layout.addWidget(self.users_list)

        self.layout.addLayout(self.chat_layout)

        # Champ de saisie pour les messages
        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText('Type your message here...')
        self.layout.addWidget(self.message_input)

        # Bouton pour envoyer les messages
        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.setLayout(self.layout)  # Appliquer la disposition
        self.setGeometry(100, 100, 800, 600)  # Définir la taille de la fenêtre

        self.message_received.connect(self.display_message)  # Connecter le signal de réception de message
        self.users_list_updated.connect(self.update_users_list)  # Connecter le signal de mise à jour de la liste des utilisateurs

        # Démarrer un thread pour recevoir les messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Notifier le serveur du nouvel utilisateur
        self.client_socket.send(f"NEW_USER:{self.username}".encode('utf-8'))

    # Méthode pour envoyer un message
    def send_message(self):
        message = self.message_input.text()
        if message:
            self.message_input.clear()  # Effacer le champ de saisie après l'envoi
            message_with_username = f"{self.username}: {message}"
            self.client_socket.send(message_with_username.encode('utf-8'))  # Envoyer le message au serveur
            self.chat_area.append(message_with_username)  # Afficher le message envoyé dans la zone de chat

    # Méthode pour recevoir les messages
    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')  # Recevoir le message du serveur
                if message.startswith("USER_LIST:"):
                    users = message[len("USER_LIST:"):].split(',')
                    self.users_list_updated.emit(users)  # Mettre à jour la liste des utilisateurs
                elif message.startswith("DM:"):
                    self.message_received.emit(message)  # Recevoir un message direct
                else:
                    self.message_received.emit(message)  # Recevoir un message global
            except:
                break

    # Méthode pour afficher les messages
    def display_message(self, message):
        if message.startswith("DM:"):
            _, sender, recipient, dm_message = message.split(":", 3)
            if recipient == self.username:
                if sender in self.dm_windows:
                    self.dm_windows[sender].display_message(f"{sender}: {dm_message}")
                else:
                    self.open_dm(sender, initial_message=f"{sender}: {dm_message}")
        else:
            self.chat_area.append(message)  # Afficher le message dans la zone de chat

    # Méthode pour mettre à jour la liste des utilisateurs
    def update_users_list(self, users):
        self.users_list.clear()
        self.users_list.addItems(users)  # Ajouter les utilisateurs à la liste

    # Méthode pour afficher le menu contextuel pour un utilisateur
    def show_user_menu(self, pos: QPoint):
        item = self.users_list.itemAt(pos)
        if item is not None:
            menu = QMenu(self)
            report_action = QAction('Report', self)
            dm_action = QAction('Send DM', self)

            report_action.triggered.connect(lambda: self.report_user(item.text()))
            dm_action.triggered.connect(lambda: self.open_dm(item.text()))

            menu.addAction(dm_action)
            menu.addAction(report_action)
            menu.exec_(self.users_list.mapToGlobal(pos))

    # Méthode pour signaler un utilisateur
    def report_user(self, username):
        QMessageBox.information(self, 'Report', f'User {username} has been reported.')

    # Méthode pour ouvrir une fenêtre de DM avec un utilisateur
    def open_dm(self, recipient, initial_message=None):
        if recipient not in self.dm_windows:
            dm_window = DMWindow(self.username, recipient, self.client_socket)
            self.dm_windows[recipient] = dm_window
            self.stacked_widget.addWidget(dm_window)
        if initial_message:
            self.dm_windows[recipient].display_message(initial_message)
        self.stacked_widget.setCurrentWidget(self.dm_windows[recipient])

# Classe représentant une fenêtre de messagerie directe (DM) avec un autre utilisateur (définie à nouveau)
# Redéfinir cette classe est une erreur, il suffit d'utiliser la première définition
class DMWindow(QWidget):
    def __init__(self, username, recipient, client_socket):
        super().__init__()

        self.username = username
        self.recipient = recipient
        self.client_socket = client_socket

        self.setWindowTitle(f'DM with {self.recipient}')

        self.layout = QVBoxLayout()

        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.layout.addWidget(self.chat_area)

        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText('Type your message here...')
        self.layout.addWidget(self.message_input)

        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.back_button = QPushButton('Back to Global Chat', self)
        self.back_button.clicked.connect(self.go_back)
        self.layout.addWidget(self.back_button)

        self.setLayout(self.layout)
        self.setGeometry(100, 100, 800, 600)

    def send_message(self):
        message = self.message_input.text()
        if message:
            self.message_input.clear()
            message_with_recipient = f"DM:{self.username}:{self.recipient}:{message}"
            self.client_socket.send(message_with_recipient.encode('utf-8'))
            self.chat_area.append(f"{self.username}: {message}")

    def display_message(self, message):
        self.chat_area.append(message)

    def go_back(self):
        self.parent().setCurrentIndex(0)

# Partie principale de l'application
if __name__ == '__main__':
    app = QApplication(sys.argv)  # Créer l'application PyQt

    if len(sys.argv) != 2:
        print("Usage: chat.py <username>")
        sys.exit(1)

    username = sys.argv[1]  # Récupérer le nom d'utilisateur depuis les arguments de la ligne de commande

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Créer un socket client
    client_socket.connect(('localhost', 12345))  # Se connecter au serveur

    stacked_widget = QStackedWidget()  # Créer un widget empilé pour gérer plusieurs fenêtres

    chat_window = ChatWindow(username, stacked_widget, client_socket)  # Créer la fenêtre de chat principale
    stacked_widget.addWidget(chat_window)  # Ajouter la fenêtre de chat au widget empilé

    stacked_widget.setCurrentWidget(chat_window)  # Afficher la fenêtre de chat principale
    stacked_widget.show()  # Afficher le widget empilé

    sys.exit(app.exec_())  # Démarrer la boucle d'événements de l'application PyQt
