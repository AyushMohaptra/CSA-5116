import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    gcd_val, x, y = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def generate_keypair(bits=64):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)
        while gcd(e, phi) != 1:
            e += 2
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    e, n = pk
    m = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')
    if m >= n:
        raise ValueError("Message too large for key size")
    return pow(m, e, n)

def decrypt(sk, ciphertext):
    d, n = sk
    m = pow(ciphertext, d, n)
    num_bytes = (m.bit_length() + 7) // 8
    return m.to_bytes(num_bytes, byteorder='big').decode('utf-8')

# Setup keys and execute
random.seed(42)
public_key, private_key = generate_keypair(64)
msg = "RSA Lab"
ct = encrypt(public_key, msg)
pt = decrypt(private_key, ct)

print("Public Key (e, n):", public_key)
print("Private Key (d, n):", private_key)
print("Plaintext:", msg)
print("Encrypted (int):", ct)
print("Decrypted Message:", pt)
