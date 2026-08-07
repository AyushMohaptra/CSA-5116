import random

# Define global parameters: a prime p and a generator g
p = 104729
g = 2

class Participant:
    def __init__(self, name, p, g):
        self.name = name
        self.p = p
        self.g = g
        # Random private key generation
        self._private_key = random.randint(2, p - 2)
        # Compute public key
        self.public_key = pow(g, self._private_key, p)

    def generate_shared_secret(self, peer_public_key):
        # Compute shared secret
        return pow(peer_public_key, self._private_key, self.p)

# Execution
random.seed(123)
alice = Participant("Alice", p, g)
bob = Participant("Bob", p, g)

alice_pub = alice.public_key
bob_pub = bob.public_key

alice_secret = alice.generate_shared_secret(bob_pub)
bob_secret = bob.generate_shared_secret(alice_pub)

print("Prime (p):", p)
print("Generator (g):", g)
print("Alice Private Key (x_A):", alice._private_key)
print("Alice Public Key (y_A):", alice_pub)
print("Bob Private Key (x_B):", bob._private_key)
print("Bob Public Key (y_B):", bob_pub)
print("Alice's Shared Secret:", alice_secret)
print("Bob's Shared Secret:", bob_secret)
print("Secrets Match?", alice_secret == bob_secret)
