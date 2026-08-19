import hashlib

def run_sha1():
    message = "Data Security is important"
    print(f"Original Message: '{message}'")
    
    # Generate SHA-1 hash
    sha1_hash = hashlib.sha1(message.encode()).hexdigest()
    
    print(f"SHA-1 Hash Value: {sha1_hash}")
    print(f"Hash Length: {len(sha1_hash) * 4} bits")

if __name__ == "__main__":
    run_sha1()
