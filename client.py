import sys
import re
import subprocess
import sqlite3
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget
import secrets  # For generating secure random salts
import pyargon2


# Function to load the pepper
def load_pepper(filename='pepper.txt'):
    with open(filename, 'r') as file:
        return file.read()


# Function to hash passwords with Argon2, salt, and pepper
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)  # Generate a random salt
    pepper = load_pepper()
    hashed_password = pyargon2.hash(password + pepper, salt)
    return hashed_password, salt


# Class for handling user registration and authentication
class UserManager:
    def __init__(self, db_filename='users.db'):
        self.conn = sqlite3.connect(db_filename)
        self.create_users_table()

    def create_users_table(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hashed_password TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            ''')

    def register_user(self, username, password):
        if self.user_exists(username):
            return False  # User already exists
        hashed_password, salt = hash_password(password)
        with self.conn:
            self.conn.execute('''
                INSERT INTO users (username, hashed_password, salt)
                VALUES (?, ?, ?)
            ''', (username, hashed_password, salt))
        return True

    def user_exists(self, username):
        cursor = self.conn.execute('''
            SELECT 1 FROM users WHERE username = ?
        ''', (username,))
        return cursor.fetchone() is not None

    def authenticate_user(self, username, password):
        cursor = self.conn.execute('''
            SELECT hashed_password, salt FROM users WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row is None:
            return False  # User does not exist
        stored_password, salt = row
        pepper = load_pepper()
        hashed_password, _ = hash_password(password, salt)
        return hashed_password == stored_password


# Definition of the login window
class LoginWindow(QWidget):
    def __init__(self, stacked_widget, user_manager):
        super().__init__()

        self.stacked_widget = stacked_widget
        self.user_manager = user_manager

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

        # Check user credentials
        if self.user_manager.authenticate_user(username, password):
            QMessageBox.information(self, 'Success', 'Login successful')
            self.launch_chat(username)  # Launch chat after successful login
        else:
            QMessageBox.warning(self, 'Error', 'Bad username or password')

    # Function to open the registration window
    def open_register(self):
        self.stacked_widget.setCurrentIndex(1)

    # Function to launch the chat (commented for now)
    def launch_chat(self, username):
        subprocess.Popen([sys.executable, '<chat.py>', username])
        app.quit()


# Definition of the registration window
class RegisterWindow(QWidget):
    def __init__(self, stacked_widget, user_manager):
        super().__init__()

        self.stacked_widget = stacked_widget
        self.user_manager = user_manager

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

        # Check if the user already exists
        if self.user_manager.register_user(username, password):
            QMessageBox.information(self, 'Success', 'Registration successful')
            self.stacked_widget.setCurrentIndex(0)  # Return to the login window
        else:
            QMessageBox.warning(self, 'Error', 'Username already exists')

    # Function to go back to the login window
    def go_back(self):
        self.stacked_widget.setCurrentIndex(0)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    stacked_widget = QStackedWidget()

    user_manager = UserManager()

    login_window = LoginWindow(stacked_widget, user_manager)
    register_window = RegisterWindow(stacked_widget, user_manager)

    stacked_widget.addWidget(login_window)
    stacked_widget.addWidget(register_window)

    stacked_widget.setCurrentIndex(0)  # Start with the login window
    stacked_widget.setWindowTitle('Secure Sphere')
    stacked_widget.setGeometry(100, 100, 500, 400)
    stacked_widget.show()

    sys.exit(app.exec_())
