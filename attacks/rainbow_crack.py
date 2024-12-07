import csv

def load_rainbow_table(filename="attacks/rainbow_table.txt"):
    table = {}
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
            plain, hashval = line.split(':', 1)
            table[hashval.strip()] = plain.strip()
    return table

def crack_hashes_from_csv(users_file="users.csv", rainbow_file="rainbow_table.txt"):
    # Load rainbow table
    rainbow = load_rainbow_table(rainbow_file)

    # Load users and attempt to crack hashes
    with open(users_file, 'r', encoding='utf-8', errors='ignore') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            username = row.get("username")
            hashed_pw = row.get("hashed_password")

            if not username or not hashed_pw:
                continue
            
            if hashed_pw in rainbow:
                print(f"[+] Found match for {username}! Hash: {hashed_pw} -> Password: {rainbow[hashed_pw]}")
            else:
                print(f"[-] No match found for {username} ({hashed_pw})")

if __name__ == "__main__":
    crack_hashes_from_csv("server/users.csv", "attacks/rainbow_table.txt")
