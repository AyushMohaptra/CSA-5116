import hashlib

def run_md5():
    message = "Data Security is important"
    print(f"Original Message: '{message}'")
    
    # Generate MD5 hash
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    
    print(f"MD5 Hash Value: {md5_hash}")
    print(f"Hash Length: {len(md5_hash) * 4} bits")

if __name__ == "__main__":
    run_md5()
