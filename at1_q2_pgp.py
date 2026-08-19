import zlib
import base64

def simulate_pgp():
    message = "This is a secret file content for PGP."
    print("1. Original Message:", message)
    
    # Compression
    compressed = zlib.compress(message.encode())
    print("2. Compressed Data Size:", len(compressed))
    
    # Encryption (Simulated)
    session_key = "TempKey999"
    enc_msg = base64.b64encode(compressed).decode()
    enc_key = f"ENC_WITH_BOB_PUB[{session_key}]"
    
    # Signature
    signature = f"SIG_ALICE_PRIV[{hash(message)}]"
    
    # Transmission Bundle
    pgp_bundle = {"msg": enc_msg, "key": enc_key, "sig": signature}
    print("3. Transmitting PGP Bundle...")
    
    # Decryption
    dec_key = session_key # Bob decrypts key
    decompressed = zlib.decompress(base64.b64decode(pgp_bundle["msg"])).decode()
    print("4. Decrypted & Decompressed Message:", decompressed)
    print("5. Signature Verified Successfully.")

if __name__ == "__main__":
    simulate_pgp()
