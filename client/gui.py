import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QTextEdit, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from helper import *

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat")
        self.resize(600, 400)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        
        self.message_input = QLineEdit()
        self.message_input.returnPressed.connect(self.send_message)

        layout = QVBoxLayout()
        layout.addWidget(self.chat_display)
        layout.addWidget(self.message_input)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.shared_key = None  # will be set after ECCDH
        self.ecc_private_key = None
        self.ecc_public_key = None
        self.partner_public_key = None
        self.ready_for_chat = False

        # Message types and colors
        self.msg_colors = {
            "text": "black",
            "ecc_key": "blue",
            "ecc_confirm": "green",
            "system": "red",
            "ecc_step": "purple"
        }

    def display_message(self, msg_type, text):
        color = self.msg_colors.get(msg_type, "black")
        # Preserve chat history and allow scrolling
        self.chat_display.append(f'<span style="color:{color};">{text}</span>')

    def send_message(self):
        if self.shared_key is None:
            self.display_message("system", "Not connected yet!")
            return
        text = self.message_input.text().strip()
        if text:
            encrypted = encrypt_message(self.shared_key, text)
            msg = {
                "type": "text",
                "data": encrypted
            }
            self.message_input.clear()
            self.thread.send_json(msg)
            # Show the sent message in chat
            self.display_message("text", f"You: {text}")

    def start_ecc_exchange(self):
        # Indicate we are starting ECC exchange
        self.display_message("ecc_step", "Starting ECC key exchange...")
        self.display_message("ecc_step", "Generating ECC key pair...")
        
        self.ecc_private_key, self.ecc_public_key = generate_ecc_key()
        pub_hex = serialize_public_key(self.ecc_public_key)
        
        self.display_message("ecc_step", "Sending ECC public key to partner...")
        msg = {"type": "ecc_key", "data": pub_hex}
        self.thread.send_json(msg)
        self.display_message("ecc_step", "ECC public key sent. Waiting for partner's key...")

    def finalize_ecc_key(self):
        if self.ecc_private_key and self.partner_public_key:
            self.display_message("ecc_step", "Deriving shared secret...")
            self.shared_key = derive_shared_key(self.ecc_private_key, self.partner_public_key)
            self.display_message("ecc_step", "Shared secret established!")
            
            # Confirm the ECC handshake
            confirm_msg = {"type":"ecc_confirm","data":"ready"}
            self.display_message("ecc_step", "Sending ECC confirmation to partner...")
            self.thread.send_json(confirm_msg)
            
            self.ready_for_chat = True
            self.display_message("system", "You can now chat securely!")


class NetworkThread(QThread):
    message_received = pyqtSignal(dict)

    def __init__(self, sock, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.running = True

    def send_json(self, msg):
        data = json.dumps(msg).encode('utf-8')
        self.sock.sendall(data)

    def run(self):
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                msgs = data.split(b'}')
                for part in msgs:
                    part = part.strip()
                    if part:
                        # Add '}' back since we split by it
                        message = (part + b'}')
                        try:
                            parsed = json.loads(message.decode('utf-8'))
                            self.message_received.emit(parsed)
                        except:
                            # If decoding fails, ignore
                            pass
            except:
                break
        self.sock.close()

    def stop(self):
        self.running = False
        self.sock.close()