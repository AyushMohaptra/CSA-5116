import hmac
import hashlib
import time
import uuid

class Server:
    def __init__(self, secret_key, allowed_skew_seconds=5):
        self.secret_key = secret_key
        self.allowed_skew = allowed_skew_seconds
        # Memory-efficient nonce cache: store (nonce, expiry_timestamp)
        self.nonce_cache = {}

    def clean_expired_nonces(self, current_time):
        # Remove nonces that are older than the allowed clock skew
        expired = [nonce for nonce, expiry in self.nonce_cache.items() if current_time > expiry]
        for nonce in expired:
            del self.nonce_cache[nonce]

    def verify_request_without_prevention(self, username, data, signature):
        # A simple server that only checks the HMAC signature (vulnerable to replay)
        message = f"{username}:{data}".encode('utf-8')
        computed_sig = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed_sig, signature)

    def verify_request_with_prevention(self, username, data, timestamp, nonce, signature, current_time=None):
        if current_time is None:
            current_time = time.time()
            
        self.clean_expired_nonces(current_time)

        # 1. Verify cryptographic signature first (integrity and authenticity)
        # Message includes timestamp and nonce to prevent editing them
        message = f"{username}:{data}:{timestamp}:{nonce}".encode('utf-8')
        computed_sig = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(computed_sig, signature):
            return False, "Invalid Signature (Message Tampering detected)"

        # 2. Check Timestamp (Window of Acceptance)
        time_diff = abs(current_time - timestamp)
        if time_diff > self.allowed_skew:
            return False, f"Request Expired (Time skew is {time_diff:.2f}s, max allowed: {self.allowed_skew}s)"

        # 3. Check Nonce (Duplication Check)
        if nonce in self.nonce_cache:
            return False, f"Replay Detected (Nonce '{nonce}' already used)"

        # Save nonce with expiry time (current_time + allowed_skew)
        self.nonce_cache[nonce] = current_time + self.allowed_skew
        
        return True, "Request Authorized"

class Client:
    def __init__(self, username, secret_key):
        self.username = username
        self.secret_key = secret_key

    def create_request_without_prevention(self, data):
        message = f"{self.username}:{data}".encode('utf-8')
        signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return {
            "username": self.username,
            "data": data,
            "signature": signature
        }

    def create_request_with_prevention(self, data, timestamp=None, nonce=None):
        if timestamp is None:
            timestamp = time.time()
        if nonce is None:
            nonce = str(uuid.uuid4())
            
        message = f"{self.username}:{data}:{timestamp}:{nonce}".encode('utf-8')
        signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        
        return {
            "username": self.username,
            "data": data,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature
        }

def run_experiment():
    print("======================================================================")
    print("Experiment 4: Replay Attack Simulation and Prevention")
    print("======================================================================\n")
    
    secret_key = b"ClientServerSharedSecretKey123"
    server = Server(secret_key, allowed_skew_seconds=5)
    client = Client("alice", secret_key)
    
    print("--- SCENARIO 1: Authentication WITHOUT Prevention ---")
    # Client creates and sends request
    req1 = client.create_request_without_prevention("Withdraw $100")
    print(f"[*] Client sends: {req1}")
    
    # Server processes it
    res1 = server.verify_request_without_prevention(req1["username"], req1["data"], req1["signature"])
    print(f"    Server verification: {'AUTHORIZED' if res1 else 'REJECTED'}")
    
    # Attacker intercepts and replays the exact same request
    print("[!] Attacker replays the exact same intercepted packet...")
    res_replay1 = server.verify_request_without_prevention(req1["username"], req1["data"], req1["signature"])
    print(f"    Server verification: {'AUTHORIZED' if res_replay1 else 'REJECTED'}")
    print("    WARNING: Server executed the transaction twice! (Vulnerable to Replay Attack)\n")
    
    print("--- SCENARIO 2: Authentication WITH Prevention (Nonces + Timestamps) ---")
    server = Server(secret_key, allowed_skew_seconds=5) # Reset server cache
    t_now = time.time()
    
    # Client sends request
    req2 = client.create_request_with_prevention("Withdraw $100", timestamp=t_now)
    print(f"[*] Client sends: {req2}")
    
    # Server processes it
    ok, msg = server.verify_request_with_prevention(
        req2["username"], req2["data"], req2["timestamp"], req2["nonce"], req2["signature"], current_time=t_now
    )
    print(f"    Server verification: {'SUCCESS' if ok else 'FAILED'} | Message: {msg}")
    
    # Attacker replays the exact same request immediately
    print("\n[!] Attacker replays the exact same request immediately (Time difference = 0)...")
    ok_replay, msg_replay = server.verify_request_with_prevention(
        req2["username"], req2["data"], req2["timestamp"], req2["nonce"], req2["signature"], current_time=t_now
    )
    print(f"    Server verification: {'SUCCESS' if ok_replay else 'FAILED'} | Message: {msg_replay}")
    
    # Attacker waits 10 seconds and tries to replay the request
    print("\n[!] Attacker replays the request after 10 seconds...")
    ok_late, msg_late = server.verify_request_with_prevention(
        req2["username"], req2["data"], req2["timestamp"], req2["nonce"], req2["signature"], current_time=t_now + 10
    )
    print(f"    Server verification: {'SUCCESS' if ok_late else 'FAILED'} | Message: {msg_late}")
    
    # Attacker attempts to modify the timestamp to bypass expiry, keeping the signature
    print("\n[!] Attacker attempts to update the timestamp to bypass expiry (t + 10s) but doesn't know the HMAC key...")
    ok_mod, msg_mod = server.verify_request_with_prevention(
        req2["username"], req2["data"], t_now + 10, req2["nonce"], req2["signature"], current_time=t_now + 10
    )
    print(f"    Server verification: {'SUCCESS' if ok_mod else 'FAILED'} | Message: {msg_mod}")
    
    print("\n======================================================================\n")

if __name__ == "__main__":
    run_experiment()
