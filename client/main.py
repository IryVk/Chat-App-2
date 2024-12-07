import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys
from helper import *
from gui import *

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000

def get_server_public_key(sock):
    # Server sends its public key first
    data = sock.recv(4096)
    server_key = RSA.importKey(data)
    return server_key

def send_credentials(sock, action, username, password, server_public_key):
    request = {
        "action": action,
        "username": username,
        "password": password
    }
    plaintext = json.dumps(request).encode('utf-8')
    cipher = PKCS1_OAEP.new(server_public_key)
    encrypted = cipher.encrypt(plaintext)
    sock.sendall(encrypted)
    response = sock.recv(4096)
    return response

def authenticate_user():
    while True:
        action = input("Do you want to 'login' or 'register'? ").strip().lower()
        if action not in ['login', 'register']:
            print("Invalid choice.")
            continue
        username = input("Username: ")
        password = input("Password: ")

        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((SERVER_HOST, SERVER_PORT))
        except:
            print("Could not connect to server.")
            sys.exit(1)

        server_key = get_server_public_key(sock)
        print(f"Server public key received.")
        print(f"Server key: {server_key.export_key().decode('utf-8')}")
        resp = send_credentials(sock, action, username, password, server_key)

        try:
            resp_json = json.loads(resp.decode('utf-8'))
        except:
            print("Invalid response from server.")
            sock.close()
            continue

        if "error" in resp_json:
            print("Error:", resp_json["error"])
            sock.close()
            continue

        if resp_json.get("status") in ["Registered", "Authenticated"]:
            print("Success:", resp_json["status"])
            # We are now authenticated and have an open socket
            return sock
        else:
            print("Unexpected response:", resp_json)
            sock.close()


def main():
    # First authenticate user via CLI
    sock = authenticate_user()  # returns a connected socket upon success

    app = QApplication(sys.argv)
    window = ChatWindow()

    def on_message(msg):
        msg_type = msg.get("type")
        if msg_type is None:
            # Probably a system or status message from the server
            if "status" in msg and msg["status"] == "ChatRoomReady":
                window.display_message("system", "You have been connected to a chatroom. Initiating ECC key exchange...")
                # Start ECC key exchange
                window.start_ecc_exchange()
            else:
                window.display_message("system", str(msg))
            return

        if msg_type == "ecc_key":
            # Received partner's ECC public key
            window.display_message("ecc_step", "Received partner's ECC public key.")
            partner_pub = deserialize_public_key(msg["data"])
            window.partner_public_key = partner_pub
            window.finalize_ecc_key()

        elif msg_type == "ecc_confirm":
            # Partner confirmed ECC handshake
            window.display_message("ecc_step", "Received ECC confirmation from partner.")
            if not window.ready_for_chat:
                window.finalize_ecc_key()

        elif msg_type == "text":
            # Decrypt message if possible
            if window.shared_key is not None:
                decrypted = decrypt_message(window.shared_key, msg["data"])
                window.display_message("text", f"Partner: {decrypted}")
            else:
                window.display_message("system", "Received encrypted message before handshake complete.")
        else:
            # Unknown type
            window.display_message("system", f"Unknown message type: {msg_type}")

    network_thread = NetworkThread(sock)
    network_thread.message_received.connect(on_message)
    window.thread = network_thread
    network_thread.start()

    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
