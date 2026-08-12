import hashlib
import os
import time
import secrets
import hmac

class PasswordManager:
    def __init__(self):
        # Simulated database: username -> {salt, hash, iterations}
        self.db = {}

    def register(self, username, password, iterations=100000):
        # Generate a secure random 16-byte salt
        salt = secrets.token_bytes(16)
        
        # Key stretching using PBKDF2-HMAC-SHA256
        start_time = time.perf_counter()
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        end_time = time.perf_counter()
        
        self.db[username] = {
            'salt': salt,
            'hash': hashed,
            'iterations': iterations
        }
        
        return end_time - start_time

    def verify(self, username, password):
        if username not in self.db:
            return False
        
        stored_data = self.db[username]
        salt = stored_data['salt']
        stored_hash = stored_data['hash']
        iterations = stored_data['iterations']
        
        # Recompute hash with the same salt and iterations
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, computed_hash)

def run_experiment():
    print("======================================================================")
    print("Experiment 1: Password Hashing with Salting and Key Stretching")
    print("======================================================================\n")
    
    pm = PasswordManager()
    
    # 1. Register users
    print("[*] Registering users...")
    reg_time_alice = pm.register("alice", "SuperSecretP@ss123", iterations=100000)
    print(f"    User 'alice' registered successfully. Hash time: {reg_time_alice:.4f} seconds.")
    
    reg_time_bob = pm.register("bob", "password123", iterations=100000)
    print(f"    User 'bob' registered successfully. Hash time: {reg_time_bob:.4f} seconds.")
    print()
    
    # 2. Verify passwords
    print("[*] Verifying passwords...")
    tests = [
        ("alice", "SuperSecretP@ss123", True), # Correct password
        ("alice", "WrongPassword", False),       # Incorrect password
        ("bob", "password123", True),          # Correct password
        ("bob", "password1234", False),        # Incorrect password
        ("charlie", "any_password", False),     # Non-existent user
    ]
    
    for username, password, expected in tests:
        start = time.perf_counter()
        verified = pm.verify(username, password)
        elapsed = time.perf_counter() - start
        status = "PASSED" if verified == expected else "FAILED"
        print(f"    Verify '{username}' with password '{password}': {'Success' if verified else 'Failure'} (Expected: {'Success' if expected else 'Failure'}) | Time: {elapsed:.4f}s | Status: {status}")
    print()
    
    # 3. Performance overhead analysis (Benchmarking iterations vs time)
    print("[*] Benchmarking Key Stretching (PBKDF2-HMAC-SHA256 iterations vs execution time)...")
    password = "BenchmarkPassword@123"
    iterations_list = [1, 1000, 10000, 50000, 100000, 200000, 500000]
    
    print(f"{'Iterations':<12} | {'Time Taken (seconds)':<22}")
    print("-" * 38)
    for iters in iterations_list:
        # Run 3 trials and average
        trials = []
        for _ in range(3):
            salt = secrets.token_bytes(16)
            start = time.perf_counter()
            hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
            trials.append(time.perf_counter() - start)
        avg_time = sum(trials) / len(trials)
        print(f"{iters:<12,} | {avg_time:.6f} s")
    print("\n======================================================================\n")

if __name__ == "__main__":
    run_experiment()
