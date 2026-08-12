import hashlib
import hmac
import secrets

def manual_hmac_sha256(key: bytes, message: bytes) -> bytes:
    # SHA-256 block size is 64 bytes
    block_size = 64
    
    # 1. If key is longer than block size, hash it first
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
        
    # 2. Pad the key with trailing zeros so it is exactly block_size
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
        
    # 3. Create ipad and opad
    # ipad = 0x36 repeated 64 times
    # opad = 0x5C repeated 64 times
    ipad = bytes([x ^ 0x36 for x in key])
    opad = bytes([x ^ 0x5C for x in key])
    
    # 4. Perform inner hash: SHA256(ipad || message)
    inner_hash = hashlib.sha256(ipad + message).digest()
    
    # 5. Perform outer hash: SHA256(opad || inner_hash)
    outer_hash = hashlib.sha256(opad + inner_hash).digest()
    
    return outer_hash

def verify_hmac(key: bytes, message: bytes, received_hmac: bytes) -> bool:
    # Compute HMAC using our manual implementation
    computed_hmac = manual_hmac_sha256(key, message)
    # Use constant-time comparison
    return hmac.compare_digest(computed_hmac, received_hmac)

def run_experiment():
    print("======================================================================")
    print("Experiment 2: Implementation of HMAC for Message Integrity")
    print("======================================================================\n")
    
    # Shared secret key
    secret_key = b"MySuperSecureSharedSecretKey123"
    message = b"Sender: Alice; Receiver: Bob; Amount: $1000.00; Date: 2026-08-12"
    
    print(f"[*] Original Message: '{message.decode()}'")
    print(f"[*] Secret Key (Shared): '{secret_key.decode()}'\n")
    
    # 1. Generate HMAC
    print("[*] Generating HMAC-SHA256 (Manual Implementation vs Standard Library)...")
    manual_hmac = manual_hmac_sha256(secret_key, message)
    stdlib_hmac = hmac.new(secret_key, message, hashlib.sha256).digest()
    
    print(f"    Manual HMAC (Hex): {manual_hmac.hex()}")
    print(f"    Stdlib HMAC (Hex): {stdlib_hmac.hex()}")
    print(f"    Verification match: {manual_hmac == stdlib_hmac}")
    print()
    
    # 2. Verify Valid Message
    print("[*] Verifying unmodified message with correct key...")
    is_valid = verify_hmac(secret_key, message, manual_hmac)
    print(f"    Result: {'VALID' if is_valid else 'INVALID'} (Expected: VALID)")
    print()
    
    # 3. Simulate Tampering - Message Altered
    print("[*] Simulating Message Tampering (Attacker changes amount to $9000.00)...")
    tampered_message = b"Sender: Alice; Receiver: Bob; Amount: $9000.00; Date: 2026-08-12"
    is_valid_tampered = verify_hmac(secret_key, tampered_message, manual_hmac)
    print(f"    Result: {'VALID' if is_valid_tampered else 'INVALID'} (Expected: INVALID)")
    print()
    
    # 4. Simulate Tampering - Key Mismatch
    print("[*] Simulating Verification with Wrong Key...")
    wrong_key = b"MySuperSecureSharedSecretKey124"
    is_valid_wrong_key = verify_hmac(wrong_key, message, manual_hmac)
    print(f"    Result: {'VALID' if is_valid_wrong_key else 'INVALID'} (Expected: INVALID)")
    print()
    
    # 5. Length Extension Attack Demonstration / Discussion
    print("[*] Analyzing HMAC resistance vs Simple Hashing H(K || M):")
    # Simple hash H(K || M)
    simple_hash = hashlib.sha256(secret_key + message).hexdigest()
    print(f"    Simple Hash H(K || M): {simple_hash}")
    print("    Note: H(K || M) is vulnerable to Length Extension Attacks (e.g., HashPump),")
    print("          where an attacker can append data to the message and compute a valid hash")
    print("          without knowing the key. HMAC's nested structure SHA256(opad || SHA256(ipad || message))")
    print("          prevents this entirely by hiding the inner state.")
    print("\n======================================================================\n")

if __name__ == "__main__":
    run_experiment()
