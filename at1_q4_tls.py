import random

def simulate_tls_handshake():
    print("--- SSL/TLS Handshake Simulation ---")
    
    # 1. Client Hello
    client_random = random.randint(1000, 9999)
    print(f"Client: ClientHello (CipherSuites: [TLS_AES_256], Random: {client_random})")
    
    # 2. Server Hello & Certificate
    server_random = random.randint(1000, 9999)
    print(f"Server: ServerHello (Cipher: TLS_AES_256, Random: {server_random})")
    print("Server: Sends Digital Certificate [Server_Public_Key]")
    
    # 3. Key Exchange
    pre_master_secret = "SECRET_PMS_42"
    print(f"Client: Encrypts '{pre_master_secret}' with Server_Public_Key and sends.")
    
    # 4. Session Key Generation (Simulated)
    session_key = f"MASTER_{client_random}_{server_random}_{pre_master_secret}"
    print(f"\n[Both sides independently compute Session Key: {session_key}]")
    
    # 5. Finished
    print("\nClient: Finished (Encrypted with Session Key)")
    print("Server: Finished (Encrypted with Session Key)")
    
    print("\n--- Secure Data Transfer Phase ---")
    print(f"Client: Sending HTTP GET request (Encrypted with {session_key})")

if __name__ == "__main__":
    simulate_tls_handshake()
