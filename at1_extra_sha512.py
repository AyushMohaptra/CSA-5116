import hashlib

def run_sha512():
    message = "Data Security is important"
    print(f"Original Message: '{message}'")
    
    # Generate SHA-512 hash
    sha512_hash = hashlib.sha512(message.encode()).hexdigest()
    
    print(f"SHA-512 Hash Value: {sha512_hash}")
    print(f"Hash Length: {len(sha512_hash) * 4} bits")

if __name__ == "__main__":
    run_sha512()
