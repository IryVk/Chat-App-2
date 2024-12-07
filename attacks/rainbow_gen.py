import hashlib

def generate_rainbow_table(wordlist_file, output_file="attacks/rainbow_table.txt"):
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as infile:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for line in infile:
                password = line.strip()
                if not password:
                    continue
                # Compute SHA-256 hash of the password
                hash_val = hashlib.sha256(password.encode('utf-8')).hexdigest()
                # Write plaintext:hash to output file
                outfile.write(f"{password}:{hash_val}\n")

if __name__ == "__main__":
    # python3 rainbow_gen.py
    wordlist = "attacks/wordlist.txt"
    generate_rainbow_table(wordlist)
