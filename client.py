import sys
import re
import subprocess
import socket
import threading
import secrets
import pyargon2
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget

# Function to hash passwords with Argon2, salt, and pepper
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)  # Generate a random salt
    pepper = "1d87d7d452d7af0b1c2674adfbc3a54ed46d85656ace1bfd9ac81b18b794ae50"
    hashed_password = pyargon2.hash(password + pepper, salt)
    return hashed_password, salt

# Definition of the login window
class LoginWindow(QWidget):
    def __init__(self, stacked_widget, client_socket):
        super().__init__()

        self.stacked_widget = stacked_widget
        self.client_socket = client_socket

        self.layout = QVBoxLayout()

        # Label and input field for username
        self.label_username = QLabel('Username:')
        self.layout.addWidget(self.label_username)

        self.input_username = QLineEdit(self)
        self.input_username.setPlaceholderText('Enter your username')
        self.layout.addWidget(self.input_username)

        # Label and input field for password
        self.label_password = QLabel('Password:')
        self.layout.addWidget(self.label_password)

        self.input_password = QLineEdit(self)
        self.input_password.setEchoMode(QLineEdit.Password)  # Hide the password while typing
        self.input_password.setPlaceholderText('Enter your password')
        self.layout.addWidget(self.input_password)

        # Login button
        self.button_login = QPushButton('Login', self)
        self.button_login.clicked.connect(self.login)
        self.layout.addWidget(self.button_login)

        # Button to open the registration window
        self.button_register = QPushButton('Register', self)
        self.button_register.clicked.connect(self.open_register)
        self.layout.addWidget(self.button_register)

        self.setLayout(self.layout)

    # Function called when attempting to log in
    def login(self):
        username = self.input_username.text()
        password = self.input_password.text()

        #hashed_password, salt = hash_password(password)

        # Send login request to server
        self.client_socket.send(f"LOGIN_USER:{username}".encode('utf-8'))
        response = self.client_socket.recv(1024).decode('utf-8')

        if response.startswith("LOGIN_USER_SUCCESS"):
            _, log_salt = response.split(":")
            log_hashed_password, _ = hash_password(password, log_salt)

            self.client_socket.send(f"LOGIN_PASS:{username}:{log_hashed_password}".encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')

            if response == "LOGIN_PASS_SUCCESS":
                QMessageBox.information(self, 'Success', "Login successful")
                self.launch_chat(username)  # Launch chat after successful login
            else:
                QMessageBox.warning(self, 'Error', "Password incorrect")

        elif response == "LOGIN_USER_FAILURE":
            QMessageBox.warning(self, 'Error', "Username doesn't exist.")

    # Function to open the registration window
    def open_register(self):
        self.stacked_widget.setCurrentIndex(1)

    # Function to launch the chat (commented for now)
    def launch_chat(self, username):
        """subprocess.Popen([sys.executable, 'chat.py', username])"""
        app.quit()


# Definition of the registration window
class RegisterWindow(QWidget):
    def __init__(self, stacked_widget, client_socket):
        super().__init__()

        self.stacked_widget = stacked_widget
        self.client_socket = client_socket

        self.layout = QVBoxLayout()

        # Label and input field for username
        self.label_username = QLabel('Username:')
        self.layout.addWidget(self.label_username)

        self.input_username = QLineEdit(self)
        self.input_username.setPlaceholderText('Choose a username')
        self.layout.addWidget(self.input_username)

        # Label and input field for password
        self.label_password = QLabel('Password:')
        self.layout.addWidget(self.label_password)

        self.input_password = QLineEdit(self)
        self.input_password.setEchoMode(QLineEdit.Password)  # Hide the password while typing
        self.input_password.setPlaceholderText('Choose a password')
        self.layout.addWidget(self.input_password)

        # Label and input field for password confirmation
        self.label_confirm_password = QLabel('Confirm Password:')
        self.layout.addWidget(self.label_confirm_password)

        self.input_confirm_password = QLineEdit(self)
        self.input_confirm_password.setEchoMode(QLineEdit.Password)  # Hide the password while typing
        self.input_confirm_password.setPlaceholderText('Confirm your password')
        self.layout.addWidget(self.input_confirm_password)

        # Register button
        self.button_register = QPushButton('Register', self)
        self.button_register.clicked.connect(self.register)
        self.layout.addWidget(self.button_register)

        # Button to go back to the login window
        self.button_back = QPushButton('Back', self)
        self.button_back.clicked.connect(self.go_back)
        self.layout.addWidget(self.button_back)

        self.setLayout(self.layout)

    # Function called when attempting to register
    def register(self):
        username = self.input_username.text()
        password = self.input_password.text()
        confirm_password = self.input_confirm_password.text()

        if password != confirm_password:
            QMessageBox.warning(self, 'Error', 'Passwords do not match')
            return
        
        if len(password)<8:
            QMessageBox.warning(self, 'Error', 'Password must be at least 8 characters long')
            return
        
        if not(re.findall("[0-9]",password)) or not(re.findall("[a-zA-Z]",password)) or not(re.findall("[&é(è_çà)=~#{|^@}°+^$*ù!:;,?.§%¨£µ¤-]",password)):
            QMessageBox.warning(self, 'Error', 'Password must contain number, upper and lower case letter and special characters')
            return
        
        hashed_password, salt = hash_password(password)

        # Send registration request to server
        self.client_socket.send(f"REGISTER:{username}:{hashed_password}:{salt}".encode('utf-8'))
        response = self.client_socket.recv(1024).decode('utf-8')

        if response == "REGISTER_SUCCESS":
            QMessageBox.information(self, 'Success', 'Registration successful')
            self.stacked_widget.setCurrentIndex(0)  # Return to the login window
        else:
            QMessageBox.warning(self, 'Error', 'Username already exists')

    # Function to go back to the login window
    def go_back(self):
        self.stacked_widget.setCurrentIndex(0)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    stacked_widget = QStackedWidget()

    login_window = LoginWindow(stacked_widget, client_socket)
    register_window = RegisterWindow(stacked_widget, client_socket)

    stacked_widget.addWidget(login_window)
    stacked_widget.addWidget(register_window)

    stacked_widget.setCurrentIndex(0)  # Start with the login window
    stacked_widget.setWindowTitle('Secure Sphere')
    stacked_widget.setGeometry(100, 100, 500, 400)
    stacked_widget.show()

    sys.exit(app.exec_())