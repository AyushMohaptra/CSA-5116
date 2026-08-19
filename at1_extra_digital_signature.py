import hashlib
import base64

def simulate_digital_signature():
    message = "Authorize transfer of $10,000"
    print(f"--- Sender Side ---")
    print(f"Message: '{message}'")
    
    # 1. Hash the message
    msg_hash = hashlib.sha256(message.encode()).hexdigest()
    print(f"Message Hash (SHA-256): {msg_hash}")
    
    # 2. Sign the hash (Simulating Private Key Encryption)
    signature = base64.b64encode(f"ENCRYPTED_WITH_PRIVATE_KEY_{msg_hash}".encode()).decode()
    print(f"Digital Signature: {signature}")
    
    print(f"\n--- Transmission ---")
    print(f"Sending Message + Signature to Receiver...")
    
    print(f"\n--- Receiver Side ---")
    # 3. Verify Signature (Simulating Public Key Decryption)
    decrypted_sig = base64.b64decode(signature.encode()).decode()
    extracted_hash = decrypted_sig.replace("ENCRYPTED_WITH_PRIVATE_KEY_", "")
    
    # 4. Independent Hash Check
    calculated_hash = hashlib.sha256(message.encode()).hexdigest()
    
    if extracted_hash == calculated_hash:
        print("Verification SUCCESS: The signature is valid.")
        print("Integrity and Non-repudiation are guaranteed.")
    else:
        print("Verification FAILED: The message or signature was altered.")

if __name__ == "__main__":
    simulate_digital_signature()
