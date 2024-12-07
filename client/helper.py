import os
import json
import binascii
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_ecc_key():
    # Generate a private key for use in the exchange.
    private_key = ec.generate_private_key(ec.SECP256R1())  # NIST P-256
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(key):
    # Compressed point format or uncompressed
    pem = key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return binascii.hexlify(pem).decode('utf-8')

def deserialize_public_key(pub_hex):
    pub_bytes = binascii.unhexlify(pub_hex.encode('utf-8'))
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
    return public_key

def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # Derive a key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived_key

def encrypt_message(key, plaintext):
    # Using AES-256 CTR
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    # Return iv + ciphertext as hex
    combined = iv + ciphertext
    return binascii.hexlify(combined).decode('utf-8')

def decrypt_message(key, hex_message):
    data = binascii.unhexlify(hex_message.encode('utf-8'))
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')
