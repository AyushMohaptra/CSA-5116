def simulate_ipsec_tunnel():
    # Original IP Packet (Internal Network)
    original_src = "192.168.1.10"
    original_dst = "10.0.0.50"
    payload = "TOP SECRET COMPANY DATA"
    original_packet = f"[IP:{original_src}->{original_dst} | Data:{payload}]"
    
    print(f"Original Packet: {original_packet}")
    
    # Gateway Processing (Tunnel Mode)
    gateway_A_ip = "203.0.113.1"
    gateway_B_ip = "198.51.100.1"
    
    # Encrypt the ENTIRE original packet
    encrypted_payload = f"ENCRYPTED({original_packet})"
    print(f"Encrypted Inner Packet: {encrypted_payload}")
    
    # Create new outer IP header
    tunnel_packet = f"[IP:{gateway_A_ip}->{gateway_B_ip} | Payload:{encrypted_payload}]"
    print(f"\nTransmitting over Public Internet:\n{tunnel_packet}")
    
    # Receiving Gateway Processing
    print("\nReceiving at Gateway B...")
    # Strip outer header and decrypt
    decrypted_packet = original_packet
    print(f"Decrypted Original Packet: {decrypted_packet}")
    print("Routing to final destination:", original_dst)

if __name__ == "__main__":
    simulate_ipsec_tunnel()
