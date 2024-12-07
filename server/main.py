import socket
import threading
import json
import hashlib
import csv
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'
PORT = 5000

# Global lists to keep track of authenticated clients
authenticated_clients = []
chat_rooms = []

def load_keys():
    with open("server/keys/server_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("server/keys/server_public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def load_users():
    if not os.path.exists("server/users.csv"):
        # Create file if doesn't exist
        with open("server/users.csv", "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["username", "hashed_password"])
    users = {}
    with open("server/users.csv", "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row["username"]] = row["hashed_password"]
    return users

def save_user(username, hashed_password):
    with open("server/users.csv", "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([username, hashed_password])

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def handle_client(conn, addr, private_key, public_key):
    # Step 1: Send server public key
    conn.sendall(public_key.exportKey('PEM'))
    
    # Step 2: Receive client request (encrypted JSON)
    try:
        encrypted_data = conn.recv(4096)
        if not encrypted_data:
            conn.close()
            return
    except:
        conn.close()
        return

    # Decrypt the data
    cipher = PKCS1_OAEP.new(private_key)
    try:
        decrypted_msg = cipher.decrypt(encrypted_data)
    except:
        # Decryption failed
        conn.sendall(b'{"error":"DecryptionFailed"}')
        conn.close()
        return
    
    # Parse JSON
    try:
        request = json.loads(decrypted_msg.decode('utf-8'))
    except json.JSONDecodeError:
        conn.sendall(b'{"error":"InvalidJSON"}')
        conn.close()
        return

    # request format expected:
    # { "action": "register" or "login", "username": "...", "password": "..." }

    users = load_users()
    action = request.get("action")
    username = request.get("username")
    password = request.get("password")

    if not username or not password or action not in ["register", "login"]:
        conn.sendall(b'{"error":"InvalidRequest"}')
        conn.close()
        return

    hashed_pw = hash_password(password)

    if action == "register":
        # Check if user exists
        if username in users:
            conn.sendall(b'{"error":"UserExists"}')
            conn.close()
            return
        else:
            # Save user
            save_user(username, hashed_pw)
            conn.sendall(b'{"status":"Registered"}')
    elif action == "login":
        # Check if user exists and password matches
        if username not in users or users[username] != hashed_pw:
            conn.sendall(b'{"error":"InvalidCredentials"}')
            conn.close()
            return
        else:
            conn.sendall(b'{"status":"Authenticated"}')

    # If we reach here, user is authenticated
    authenticated_clients.append(conn)

    # Wait for a partner to chat with
    while True:
        if len(authenticated_clients) >= 2:
            # Pair up the first two in the list (if not already in a room)
            if conn in authenticated_clients:
                partner_conn = None
                for c in authenticated_clients:
                    if c != conn:
                        partner_conn = c
                        # Notify both clients that chatroom is ready
                        conn.sendall(b'{"status":"ChatRoomReady"}')
                        partner_conn.sendall(b'{"status":"ChatRoomReady"}')
                        break
                if partner_conn:
                    # Remove them from the waiting list
                    authenticated_clients.remove(conn)
                    authenticated_clients.remove(partner_conn)
                    # Create a chatroom
                    chat_rooms.append((conn, partner_conn))
                    break

        # Prevent busy waiting
        import time
        time.sleep(1)

    # Now in a chatroom
    # Relay messages between the two clients
    partner_conn = [pair[1] if pair[0] == conn else pair[0] for pair in chat_rooms if conn in pair][0]

    # We’ll start a thread to listen from partner_conn and forward to conn as well
    def relay_messages(from_conn, to_conn):
        while True:
            try:
                data = from_conn.recv(4096)
                if not data:
                    break
                to_conn.sendall(data)
            except:
                break
        # On exit, close both
        from_conn.close()
        to_conn.close()

    # Start threads for bidirectional communication
    t1 = threading.Thread(target=relay_messages, args=(conn, partner_conn), daemon=True)
    t2 = threading.Thread(target=relay_messages, args=(partner_conn, conn), daemon=True)
    t1.start()
    t2.start()

    # Threads handle communication, just wait for them to finish
    t1.join()
    t2.join()

def main():
    private_key, public_key = load_keys()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        print(f"New connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(conn, addr, private_key, public_key), daemon=True)
        thread.start()

if __name__ == "__main__":
    main()
