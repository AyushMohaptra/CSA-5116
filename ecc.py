def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

def mod_inverse(val, mod):
    g, x, y = extended_gcd(val, mod)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % mod

class Point:
    def __init__(self, x, y, is_infinity=False):
        self.x = x
        self.y = y
        self.is_infinity = is_infinity

    def __str__(self):
        if self.is_infinity: return "O"
        return f"({self.x}, {self.y})"

    def __eq__(self, other):
        if self.is_infinity and other.is_infinity: return True
        if self.is_infinity != other.is_infinity: return False
        return self.x == other.x and self.y == other.y

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def point_add(self, P, Q):
        if P.is_infinity: return Q
        if Q.is_infinity: return P
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return Point(0, 0, is_infinity=True)
        if P == Q:
            num = (3 * (P.x ** 2) + self.a) % self.p
            den = (2 * P.y) % self.p
        else:
            num = (Q.y - P.y) % self.p
            den = (Q.x - P.x) % self.p
        try:
            slope = (num * mod_inverse(den, self.p)) % self.p
        except ValueError:
            return Point(0, 0, is_infinity=True)
        x_r = (slope ** 2 - P.x - Q.x) % self.p
        y_r = (slope * (P.x - x_r) - P.y) % self.p
        return Point(x_r, y_r)

    def scalar_mul(self, k, P):
        result = Point(0, 0, is_infinity=True)
        temp = P
        while k > 0:
            if k & 1:
                result = self.point_add(result, temp)
            temp = self.point_add(temp, temp)
            k >>= 1
        return result

# Define curve: y^2 = x^3 + 2x + 3 mod 97
curve = EllipticCurve(2, 3, 97)
G = Point(1, 43)  # Base point G of order 50

# Alice's keypair
alice_priv = 15
alice_pub = curve.scalar_mul(alice_priv, G)

# Bob's keypair
bob_priv = 23
bob_pub = curve.scalar_mul(bob_priv, G)

# Shared secret derivation
alice_secret = curve.scalar_mul(alice_priv, bob_pub)
bob_secret = curve.scalar_mul(bob_priv, alice_pub)

print("ECC Curve: y^2 = x^3 + 2x + 3 mod 97")
print("Base Point G:", G)
print("Alice Private Key:", alice_priv)
print("Alice Public Key P_A:", alice_pub)
print("Bob Private Key:", bob_priv)
print("Bob Public Key P_B:", bob_pub)
print("Alice Shared Secret:", alice_secret)
print("Bob Shared Secret:", bob_secret)
print("Secrets Match?", alice_secret == bob_secret)
