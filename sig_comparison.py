import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15, DSS

def benchmark_rsa(message, trials=50):
    print("[*] Benchmarking RSA (2048-bit)...")
    
    # 1. Key Generation
    start = time.perf_counter()
    rsa_key = RSA.generate(2048)
    keygen_time = time.perf_counter() - start
    
    pub_key = rsa_key.publickey()
    h = SHA256.new(message)
    
    # 2. Signing
    signing_times = []
    for _ in range(trials):
        start = time.perf_counter()
        signature = pkcs1_15.new(rsa_key).sign(h)
        signing_times.append(time.perf_counter() - start)
    avg_signing_time = sum(signing_times) / trials
    sig_size = len(signature)
    
    # 3. Verification
    verification_times = []
    for _ in range(trials):
        start = time.perf_counter()
        try:
            pkcs1_15.new(pub_key).verify(h, signature)
            success = True
        except (ValueError, TypeError):
            success = False
        verification_times.append(time.perf_counter() - start)
    avg_verification_time = sum(verification_times) / trials
    
    return {
        "keygen": keygen_time,
        "signing": avg_signing_time,
        "verification": avg_verification_time,
        "sig_size": sig_size,
        "verified": success
    }

def benchmark_ecdsa(message, trials=50):
    print("[*] Benchmarking ECDSA (NIST P-256)...")
    
    # 1. Key Generation
    start = time.perf_counter()
    ecc_key = ECC.generate(curve='P-256')
    keygen_time = time.perf_counter() - start
    
    pub_key = ecc_key.public_key() # Call as a method
    h = SHA256.new(message)
    
    # 2. Signing
    signing_times = []
    for _ in range(trials):
        start = time.perf_counter()
        signer = DSS.new(ecc_key, 'fips-186-3')
        signature = signer.sign(h)
        signing_times.append(time.perf_counter() - start)
    avg_signing_time = sum(signing_times) / trials
    sig_size = len(signature)
    
    # 3. Verification
    verification_times = []
    for _ in range(trials):
        start = time.perf_counter()
        verifier = DSS.new(pub_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            success = True
        except (ValueError, TypeError):
            success = False
        verification_times.append(time.perf_counter() - start)
    avg_verification_time = sum(verification_times) / trials
    
    return {
        "keygen": keygen_time,
        "signing": avg_signing_time,
        "verification": avg_verification_time,
        "sig_size": sig_size,
        "verified": success
    }

def run_experiment():
    print("======================================================================")
    print("Experiment 5: Performance Comparison of Digital Signature Algorithms")
    print("======================================================================\n")
    
    message = b"This is a sample document for cryptographic signing. We will measure speed performance."
    trials = 100
    
    print(f"[*] Message length: {len(message)} bytes")
    print(f"[*] Running {trials} trials for signing and verification...\n")
    
    rsa_results = benchmark_rsa(message, trials)
    print(f"    RSA Key Generation: {rsa_results['keygen']:.4f} s")
    print(f"    RSA Avg Signing:    {rsa_results['signing']*1000:.4f} ms")
    print(f"    RSA Avg Verify:     {rsa_results['verification']*1000:.4f} ms")
    print(f"    RSA Signature Size: {rsa_results['sig_size']} bytes")
    print(f"    RSA Verification:   {'SUCCESS' if rsa_results['verified'] else 'FAILED'}\n")
    
    ecdsa_results = benchmark_ecdsa(message, trials)
    print(f"    ECDSA Key Gen:      {ecdsa_results['keygen']:.4f} s")
    print(f"    ECDSA Avg Signing:  {ecdsa_results['signing']*1000:.4f} ms")
    print(f"    ECDSA Avg Verify:   {ecdsa_results['verification']*1000:.4f} ms")
    print(f"    ECDSA Sig Size:     {ecdsa_results['sig_size']} bytes")
    print(f"    ECDSA Verification: {'SUCCESS' if ecdsa_results['verified'] else 'FAILED'}\n")
    
    # Printing Comparison Table
    print("----------------------------------------------------------------------")
    print("PERFORMANCE COMPARISON SUMMARY")
    print("----------------------------------------------------------------------")
    print(f"{'Metric':<25} | {'RSA (2048-bit)':<18} | {'ECDSA (P-256)':<18}")
    print("-" * 67)
    print(f"{'Key Gen Time':<25} | {rsa_results['keygen']:.4f} s | {ecdsa_results['keygen']:.4f} s")
    print(f"{'Avg Signing Time':<25} | {rsa_results['signing']*1000:.2f} ms | {ecdsa_results['signing']*1000:.2f} ms")
    print(f"{'Avg Verification Time':<25} | {rsa_results['verification']*1000:.2f} ms | {ecdsa_results['verification']*1000:.2f} ms")
    print(f"{'Signature Size':<25} | {rsa_results['sig_size']} bytes | {ecdsa_results['sig_size']} bytes")
    print("----------------------------------------------------------------------\n")
    print("Analysis:")
    print("1. Key Generation: ECDSA is significantly faster than RSA at key generation")
    print("   because RSA requires searching for two large prime numbers.")
    print("2. Signing: ECDSA is generally faster at signing than RSA.")
    print("3. Verification: RSA verification is extremely fast (using small e=65537),")
    print("   making it faster than ECDSA verification, which requires complex elliptic curve arithmetic.")
    print("4. Size: ECDSA signatures are much smaller (64 bytes vs 256 bytes), saving bandwidth.")
    print("======================================================================\n")

if __name__ == "__main__":
    run_experiment()
