# Chat-App-2
# Secure Chat Application
A Python-based chat application that focuses on secure end-to-end encryption. It enables secure communication between two clients using RSA and ECC-DH for key exchange, and AES-256 encryption for messages.
<a name="readme-top"></a>

## Description
This project is a chat application developed as part of coursework to explore cryptography concepts. The server and clients exchange messages using RSA for initial authentication and secure credential exchange. Once a secure channel is established, clients use an Elliptic Curve Diffie-Hellman (ECC-DH) key exchange to derive a shared secret. This shared secret is then used as an AES-256 key to encrypt messages end-to-end. PyQt5 is used on the client side to provide a graphical user interface.

<!-- TABLE OF CONTENTS --> 
<details> 
  <summary>Table of Contents</summary> 
  <ol> 
    <li><a href="#installation">Installation</a></li> 
    <ul> 
      <li><a href="#dependencies">Dependencies</a></li> 
      <li><a href="#setup">Setup</a></li> 
    </ul> 
    <li><a href="#usage">Usage</a></li> 
    <li> <a href="#about-the-project">About The Project</a> 
      <ul> 
        <li><a href="#built-with">Built With</a></li> <li><a href="#file-structure">File Structure</a></li> 
        <li><a href="#features">Features</a></li> </ul> </li> <li><a href="#contact">Contact</a></li> 
  </ol> </details> 
  <p align="right">(<a href="#readme-top">back to top</a>)</p>


## Installation

### Dependencies
   ```bash
   pip3 install pycryptodome cryptography PyQt5
   ```

### Setup
1. Clone the repository
    ```bash
    git clone https://github.com/IryVk/Chat-App-2
    ```
2. Navigate to the project directory
    ```bash
    cd Chat-App-2
    ```
3. Generate RSA Keys 
    ```bash
    python3 server/gen_keys.py
    ```
4. Run the server
    ```bash
    python3 server/main.py
    ```
5. Run the client (repeat this step twice :D)
    ```bash
    python3 client/main.py
    ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage


1. Start the Server:
   
    Run `server/main.p`. It will listen for incoming connections and handle user authentication.
2. Run the Clients:
   
    Run `client/main.py` twice (or on two separate machines). The client will prompt you to either register or login. Upon successful authentication, the PyQt5 GUI launches. The client will wait until the server pairs it with another client.
3. Chat :D
   
    Once paired, the clients perform an ECC-DH key exchange. After establishing a shared secret, all messages are encrypted end-to-end using AES-256. Messages are color-coded by type, and the chat window allows scrolling to view the entire conversation history.




<p align="right">(<a href="#readme-top">back to top</a>)</p>

## About The Project

### Built With

+ <img src="https://img.shields.io/badge/-Python 3-pink?logo=python">
+ `PyQt5` for GUI
+ `pycryptodome` & `cryptography` libraries for RSA, ECC-DH, and AES

### File Structure

```bash
Chat-App-2/  # project root
├── server/
│   └── keys/  # server RSA kys
│   └── gen_keys.py  # RSA key generation
│   └── main.py  # main server code
│   └── users.csv  # users file
├── client/
│   └── helpers.py  # helper functions
│   └── gui.py  # gui code
│   └── main.py  # main client code
├── .gitignore
├── LICENSE
└── README.md
```

### Features

+ Secure Client-Server Communication:
    Uses RSA to securely exchange credentials and authenticate users. Passwords are hashed and stored on the server.
+ Dynamic Chatrooms:
    Once two clients are authenticated, the server pairs them into a secure chatroom.
+ ECC-DH Key Exchange:
    Clients use Elliptic Curve Diffie-Hellman to derive a shared secret for subsequent AES encryption.
+ End-to-End Encryption with AES-256:
    All messages exchanged between clients are encrypted using the shared secret, ensuring end-to-end confidentiality.
+ PyQt5 Graphical Interface:
    Provides a user-friendly GUI with scrollable chat history and color-coded message types (system messages, ECC exchange steps, and chat messages).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contact

Arwa Essam Abdelaziz

aa2101585@tkh.edu.eg - arwa.abdelaziz.03@gmail.com

<p align="right">(<a href="#readme-top">back to top</a>)</p>

