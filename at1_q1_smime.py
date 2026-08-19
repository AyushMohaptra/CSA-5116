import hashlib
import base64

def simulate_smime():
    print("--- S/MIME Simulation ---")
    message = "Confidential Contract Details"
    print(f"Original Message: {message}")
    
    # 1. Hashing and Signature (Simulated)
    msg_hash = hashlib.sha256(message.encode()).hexdigest()
    signature = base64.b64encode(f"SIGNED_WITH_SENDER_PRIVATE_KEY_{msg_hash}".encode()).decode()
    print(f"Generated Signature: {signature[:30]}...")
    
    # 2. Encryption (Simulated Symmetric + Asymmetric)
    session_key = "RANDOM_AES_KEY_123"
    encrypted_message = base64.b64encode(f"ENCRYPTED_{message}_{session_key}".encode()).decode()
    encrypted_session_key = base64.b64encode(f"ENCRYPTED_KEY_WITH_RECEIVER_PUB_{session_key}".encode()).decode()
    
    print("\n--- Transmission ---")
    print(f"Sending: Encrypted Msg, Encrypted Key, Signature")
    
    # 3. Decryption and Verification
    print("\n--- Receiver Side ---")
    decrypted_key = session_key # Simulated decryption with private key
    decrypted_message = message # Simulated decryption with session key
    print(f"Decrypted Message: {decrypted_message}")
    
    # Verify Signature
    received_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()
    if msg_hash == received_hash:
        print("Signature Verified: Authentication and Integrity ensured.")
    else:
        print("Signature Verification Failed!")

if __name__ == "__main__":
    simulate_smime()
