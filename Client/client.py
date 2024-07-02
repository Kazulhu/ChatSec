import sys
import socket
import threading
import secrets
import pyargon2 # type: ignore
import pyotp    # type: ignore
import qrcode   # type: ignore
import ssl
import os
from time import sleep
from io import BytesIO
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QListWidget, QMenu, QAction, QMessageBox, QStackedWidget, QFileDialog, QTextBrowser    # type: ignore
from PyQt5.QtCore import pyqtSignal, Qt, QPoint, QByteArray # type: ignore
from PyQt5.QtGui import QPixmap, QTextCursor # type: ignore

# Global variables
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# Function to hash passwords with Argon2, salt, and pepper
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)  # Generate a random salt
    pepper = "1d87d7d452d7af0b1c2674adfbc3a54ed46d85656ace1bfd9ac81b18b794ae50"
    hashed_password = pyargon2.hash(password + pepper, salt)
    return hashed_password, salt

# User interface for login and registration
class ClientApp(QStackedWidget):
    def __init__(self):
        super().__init__()

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations("../CA_local/ca-cert.pem")

        self.client_ssl = self.context.wrap_socket(self.client_socket, server_hostname=SERVER_HOST)
        

        self.username = None

        self.login_window = LoginWindow(self)
        self.register_window = RegisterWindow(self)

        self.addWidget(self.login_window)
        self.addWidget(self.register_window)

        self.setCurrentIndex(0)
        self.setWindowTitle('Secure Sphere')
        self.setGeometry(100, 100, 500, 400)

        self.client_ssl.connect((SERVER_HOST,SERVER_PORT))

    def switch_to_login(self):
        self.setCurrentIndex(0)

    def switch_to_register(self):
        self.setCurrentIndex(1)

# Login window
class LoginWindow(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent

        self.layout = QVBoxLayout()

        self.label_username = QLabel('Username:')
        self.layout.addWidget(self.label_username)

        self.input_username = QLineEdit(self)
        self.input_username.setPlaceholderText('Enter your username')
        self.layout.addWidget(self.input_username)

        self.label_password = QLabel('Password:')
        self.layout.addWidget(self.label_password)

        self.input_password = QLineEdit(self)
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setPlaceholderText('Enter your password')
        self.layout.addWidget(self.input_password)

        self.input_otp = QLineEdit(self)
        self.input_otp.setPlaceholderText('Enter OTP')
        self.layout.addWidget(self.input_otp)

        self.input_password.clear()
        self.input_username.clear()
        self.input_otp.clear()

        self.button_login = QPushButton('Login', self)
        self.button_login.clicked.connect(self.login)
        self.layout.addWidget(self.button_login)

        self.button_register = QPushButton('Register', self)
        self.button_register.clicked.connect(self.parent.switch_to_register)
        self.layout.addWidget(self.button_register)

        self.setLayout(self.layout)

    def login(self):
        username = self.input_username.text()
        password = self.input_password.text()
        otp = self.input_otp.text()

        hashed_password, salt = hash_password(password)

        self.parent.client_ssl.send(f"LOGIN_USER:{username}".encode('utf-8'))
        response = self.parent.client_ssl.recv(1024).decode('utf-8')

        if response.startswith("LOGIN_USER_SUCCESS"):
            _, log_salt = response.split(":")
            log_hashed_password, _ = hash_password(password, log_salt)

            self.parent.client_ssl.send(f"LOGIN_PASS:{username}:{log_hashed_password}:{otp}".encode('utf-8'))
            response = self.parent.client_ssl.recv(1024).decode('utf-8')

            if response == "LOGIN_PASS_SUCCESS":
                QMessageBox.information(self, 'Success', "Login successful")
                self.input_password.clear()
                self.input_username.clear()
                self.input_otp.clear()
                self.launch_chat(username)
            else:
                QMessageBox.warning(self, 'Error', "Password incorrect")

        elif response == "LOGIN_USER_FAILURE":
            QMessageBox.warning(self, 'Error', "Username doesn't exist.")

    def launch_chat(self, username):
        chat_window = ChatWindow(username, self.parent.client_ssl)
        self.parent.addWidget(chat_window)
        self.parent.setCurrentWidget(chat_window)

# Registration window
class RegisterWindow(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent

        self.layout = QVBoxLayout()

        self.label_username = QLabel('Username:')
        self.layout.addWidget(self.label_username)

        self.input_username = QLineEdit(self)
        self.input_username.setPlaceholderText('Choose a username')
        self.layout.addWidget(self.input_username)

        self.label_password = QLabel('Password:')
        self.layout.addWidget(self.label_password)

        self.input_password = QLineEdit(self)
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setPlaceholderText('Choose a password')
        self.layout.addWidget(self.input_password)

        self.label_confirm_password = QLabel('Confirm Password:')
        self.layout.addWidget(self.label_confirm_password)

        self.input_confirm_password = QLineEdit(self)
        self.input_confirm_password.setEchoMode(QLineEdit.Password)
        self.input_confirm_password.setPlaceholderText('Confirm your password')
        self.layout.addWidget(self.input_confirm_password)

        self.input_password.clear()
        self.input_confirm_password.clear()
        self.input_username.clear()

        self.button_register = QPushButton('Register', self)
        self.button_register.clicked.connect(self.register)
        self.layout.addWidget(self.button_register)

        self.register_qr_label = QLabel(self)
        self.layout.addWidget(self.register_qr_label)
        self.register_qr_label.hide()

        self.button_back = QPushButton('Back', self)
        self.button_back.clicked.connect(self.go_back)
        self.layout.addWidget(self.button_back)

        self.setLayout(self.layout)

    def go_back(self):
        self.register_qr_label.hide()
        self.parent.switch_to_login()


    def print_qr_code(self, username, secret):

        # Create a TOTP object
        totp = pyotp.TOTP(secret)

        # Generate the OTP URL
        otp_url = totp.provisioning_uri(name=username, issuer_name="SecureSphere")

        # Generate the QR code
        qr = qrcode.make(otp_url)

        # Save the QR code as an image
        qr_image = BytesIO()
        qr.save(qr_image, format="PNG")
        qr_image.seek(0)

        pixmap = QPixmap()
        pixmap.loadFromData(QByteArray(qr_image.getvalue()), "PNG")
        self.register_qr_label.setPixmap(pixmap)
        self.register_qr_label.show()

    def register(self):
        username = self.input_username.text()
        password = self.input_password.text()
        confirm_password = self.input_confirm_password.text()

        if password != confirm_password:
            QMessageBox.warning(self, 'Error', 'Passwords do not match')
            return
        
        hashed_password, salt = hash_password(password)

        # Generate a base32 secret for the OTP
        secret = pyotp.random_base32()

        self.print_qr_code(username, secret)

        self.parent.client_ssl.send(f"REGISTER:{username}:{hashed_password}:{salt}:{secret}".encode('utf-8'))
        response = self.parent.client_ssl.recv(1024).decode('utf-8')

        if response == "REGISTER_SUCCESS":
            QMessageBox.information(self, 'Success', 'Registration successful, scan the qrcode:')
            self.input_password.clear()
            self.input_confirm_password.clear()
            self.input_username.clear()
        else:
            QMessageBox.warning(self, 'Error', 'Username already exists')

class EnterToSubmitTextEdit(QTextEdit):
    # Define a new signal that will be emitted when the Enter key is pressed
    enterPressed = pyqtSignal()

    def keyPressEvent(self, event):
        # If the Enter key is pressed, emit the enterPressed signal
        if (event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter) and not event.modifiers() & Qt.ShiftModifier:
            self.enterPressed.emit()
        else:
            # Otherwise, call the parent class's keyPressEvent method
            super().keyPressEvent(event)

# Chat window
class ChatWindow(QWidget):
    message_received = pyqtSignal(str)
    users_list_updated = pyqtSignal(list)

    def __init__(self, username, client_ssl):
        super().__init__()

        self.username = username
        self.client_ssl = client_ssl
        self.dm_windows = {}

        self.setWindowTitle(f'Chat - {self.username}')

        self.layout = QVBoxLayout()

        self.chat_layout = QHBoxLayout()

        self.chat_area = QTextBrowser(self)
        self.chat_area.setReadOnly(True)
        self.chat_area.anchorClicked.connect(self.handle_link_click)
        self.chat_layout.addWidget(self.chat_area)

        self.users_list = QListWidget(self)
        self.users_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.users_list.customContextMenuRequested.connect(self.show_user_menu)
        self.chat_layout.addWidget(self.users_list)

        self.layout.addLayout(self.chat_layout)

        #self.message_input = QLineEdit(self)
        self.message_input = EnterToSubmitTextEdit()
        self.message_input.enterPressed.connect(self.send_message)
        self.message_input.setPlaceholderText('Type your message here...')
        self.layout.addWidget(self.message_input)

        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.upload_button = QPushButton('Upload File', self)
        self.upload_button.clicked.connect(self.upload_file)
        self.layout.addWidget(self.upload_button)

        if not os.path.exists('download'):
            os.makedirs('download')

        self.setLayout(self.layout)
        self.setGeometry(100, 100, 800, 600)

        self.message_received.connect(self.display_message)
        self.users_list_updated.connect(self.update_users_list)
        

        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.client_ssl.send(f"NEW_USER:{self.username}".encode('utf-8'))

    # Send file
    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open file', '', 'All Files (*)')
        if file_path:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            threading.Thread(target=self._upload_file_thread, args=(file_path, filename)).start()

    def _upload_file_thread(self, file_path, filename):
        self.client_ssl.send(f'UPLOAD_FILE:{filename}'.encode('utf-8'))

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                self.client_ssl.send(chunk)
        self.client_ssl.send(b"END_OF_FILE")
    

    def send_message(self):
        message = self.message_input.toPlainText()
        if message:
            self.message_input.clear()
            message_with_username = f"{self.username}: {message}"
            self.client_ssl.send(message_with_username.encode('utf-8'))

    def receive_messages(self):
        while True:
            try:
                message = self.client_ssl.recv(1024).decode('utf-8')
                if message.startswith("USER_LIST:"):
                    users = message[len("USER_LIST:"):].split(',')
                    self.users_list_updated.emit(users)
                elif message.startswith("DM:"):
                    self.message_received.emit(message)
                elif message.startswith("FILE_LINK:"):
                    filename = message.split(":")[1]
                    self.message_received.emit(f'<a href="download:{filename}">{filename}</a>')
                else:
                    self.message_received.emit(message)
            except:
                break

    # Handle the link click
    def handle_link_click(self, url):
        if url.startswith("download:"):
            filename = url[len("download:"):]
            threading.Thread(target=self._download_file_thread, args=(filename,)).start()
        
    def _download_file_thread(self, filename):
        self.client_ssl.send(f'DOWNLOAD_FILE:{filename}'.encode('utf-8'))
        filepath = os.path.join('download', filename)

        with open(filepath, 'wb') as f:
            while True:
                chunk = self.client_ssl.recv(1024)
                if chunk == b"END_OF_FILE":
                    break
                f.write(chunk)

        QMessageBox.information(self, 'Download Complete', f'File {filename} downloaded successfully.')
    



    def display_message(self, message):
        if message.startswith("DM:"):
            _, sender, recipient, dm_message = message.split(":", 3)
            if recipient == self.username:
                if sender in self.dm_windows:
                    self.dm_windows[sender].display_message(f"{sender}: {dm_message}")
                else:
                    self.open_dm(sender, initial_message=f"{sender}: {dm_message}")
        else:
            self.chat_area.append(message)

    def update_users_list(self, users):
        self.users_list.clear()
        self.users_list.addItems(users)

    def show_user_menu(self, pos: QPoint):
        item = self.users_list.itemAt(pos)
        if item is not None:
            menu = QMenu(self)
            report_action = QAction('Report', self)
            report_action.triggered.connect(lambda: self.report_user(item.text()))
            menu.addAction(report_action)

            dm_action = QAction('Send DM', self)
            dm_action.triggered.connect(lambda: self.open_dm(item.text()))
            menu.addAction(dm_action)

            menu.exec_(self.users_list.mapToGlobal(pos))

    def report_user(self, username):
        QMessageBox.information(self, 'Report', f'User {username} has been reported.')

    def open_dm(self, recipient, initial_message=None):
        if recipient in self.dm_windows:
            dm_window = self.dm_windows[recipient]
        else:
            dm_window = DMWindow(self.username, recipient, self.client_ssl)
            self.dm_windows[recipient] = dm_window
        if initial_message:
            dm_window.display_message(initial_message)
        dm_window.show()

# Direct Message (DM) window
class DMWindow(QWidget):
    def __init__(self, sender, recipient, client_ssl):
        super().__init__()

        self.sender = sender
        self.recipient = recipient
        self.client_ssl = client_ssl

        self.setWindowTitle(f'DM - {self.recipient}')

        self.layout = QVBoxLayout()

        self.dm_area = QTextEdit(self)
        self.dm_area.setReadOnly(True)
        self.layout.addWidget(self.dm_area)

        self.message_input = EnterToSubmitTextEdit()
        self.message_input.enterPressed.connect(self.send_message)
        self.message_input.setPlaceholderText('Type your message here...')
        self.layout.addWidget(self.message_input)

        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_dm)
        self.layout.addWidget(self.send_button)

        self.setLayout(self.layout)
        self.setGeometry(100, 100, 400, 300)

    def send_dm(self):
        message = self.message_input.text()
        if message:
            self.message_input.clear()
            dm_message = f"DM:{self.sender}:{self.recipient}:{message}"
            self.client_ssl.send(dm_message.encode('utf-8'))

    def display_message(self, message):
        self.dm_area.append(message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client_app = ClientApp()
    client_app.show()
    sys.exit(app.exec_())
