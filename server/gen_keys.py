from Crypto.PublicKey import RSA

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("keys/server_private.pem", "wb") as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open("keys/server_public.pem", "wb") as f:
        f.write(public_key)

if __name__ == "__main__":
    generate_rsa_keypair()
