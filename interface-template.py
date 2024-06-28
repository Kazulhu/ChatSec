from PyQt5 import QtWidgets, QtCore

class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()

        # Set the minimum size of the window
        self.setMinimumSize(QtCore.QSize(1200, 675))
        # Set the current size of the window
        self.resize(1600, 900)

        # Create a QWidget as the central widget to hold the layout
        self.central_widget = QtWidgets.QWidget(self)
        self.central_widget.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(self.central_widget)

        # Create a QHBoxLayout
        self.layout = QtWidgets.QHBoxLayout(self.central_widget)

        #self.setup_menu_bar()
        self.setup_chat()

    def setup_chat(self):
        # Create the main_chat frame and add it to the layout
        self.main_chat = QtWidgets.QFrame()
        self.main_chat.setMinimumWidth(770)
        self.main_chat.setMinimumHeight(self.central_widget.height())
        self.layout.addWidget(self.main_chat, stretch=3)

        self.vlayout = QtWidgets.QVBoxLayout(self.main_chat)

        # Create the first frame and add it to the QVBoxLayout
        self.frame1 = QtWidgets.QFrame()
        self.frame1.setMinimumHeight(50)
        self.vlayout.addWidget(self.frame1, stretch=0)

        # Create the QTextEdit and add it to the QVBoxLayout
        self.text_chat = QtWidgets.QTextEdit()
        self.text_chat.setReadOnly(True)
        self.vlayout.addWidget(self.text_chat, stretch=2)

        # Create the third frame and add it to the QVBoxLayout
        self.frame3 = QtWidgets.QFrame()
        self.frame3.setMinimumHeight(80)
        self.frame3.setMaximumHeight(80)
        self.vlayout.addWidget(self.frame3, stretch=0)

        # Create a QHBoxLayout in the third frame
        self.hlayout = QtWidgets.QHBoxLayout(self.frame3)

        # Create a QTextEdit and a QPushButton and add them to the QHBoxLayout
        self.send_button = QtWidgets.QPushButton("Send")
        self.input_text = EnterToSubmitTextEdit()
        self.input_text.enterPressed.connect(self.sendMessage)

        self.hlayout.addWidget(self.input_text)
        self.hlayout.addWidget(self.send_button)
        self.send_button.clicked.connect(self.sendMessage)

    def setup_chat_info(self):
        # Create the chat_info frame and add it to the layout
        self.chat_info = QtWidgets.QFrame()
        self.chat_info.setMinimumWidth(350)
        self.layout.addWidget(self.chat_info, stretch=1)

    def setup_menu_bar(self):
        # Create the menu_bar frame and add it to the layout
        self.menu_bar = QtWidgets.QFrame()
        self.menu_bar.setMinimumWidth(80)
        self.menu_bar.setMaximumWidth(80)
        self.menu_bar.setMinimumHeight(self.central_widget.height())
        self.menu_bar.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.layout.addWidget(self.menu_bar, stretch=0)

        # Create three buttons and add them to the layout
        self.button1 = QtWidgets.QPushButton(self.menu_bar)
        self.button1.setGeometry(QtCore.QRect(15, 15, 50, 50))

        self.button2 = QtWidgets.QPushButton(self.menu_bar)
        self.button2.setGeometry(QtCore.QRect(15, 115, 50, 50))

        self.button3 = QtWidgets.QPushButton(self.menu_bar)
        self.setGeometry(QtCore.QRect(15, 215, 50, 50))

    def sendMessage(self):
        #self.text_edit.setAlignment(QtCore.Qt.AlignRight)
        message = self.input_text.toPlainText()
        self.text_chat.append(message)
        self.input_text.clear()

    def receiveMessage(self, message):
        self.text_edit.setAlignment(QtCore.Qt.AlignLeft)
        self.text_chat.append(message)
        self.input_text.clear()

class EnterToSubmitTextEdit(QtWidgets.QTextEdit):
    # Define a new signal that will be emitted when the Enter key is pressed
    enterPressed = QtCore.pyqtSignal()

    def keyPressEvent(self, event):
        # If the Enter key is pressed, emit the enterPressed signal
        if (event.key() == QtCore.Qt.Key_Return or event.key() == QtCore.Qt.Key_Enter) and not event.modifiers() & QtCore.Qt.ShiftModifier:
            self.enterPressed.emit()
        else:
            # Otherwise, call the parent class's keyPressEvent method
            super().keyPressEvent(event)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())

