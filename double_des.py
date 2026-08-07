from Crypto.Cipher import DES
import binascii

class DoubleDES:
    def __init__(self, key1: bytes, key2: bytes):
        if len(key1) != 8 or len(key2) != 8:
            raise ValueError("Keys must be 8 bytes each.")
        self.key1 = key1
        self.key2 = key2

    def pad(self, text: str) -> bytes:
        pad_len = 8 - (len(text) % 8)
        return text.encode('utf-8') + bytes([pad_len] * pad_len)

    def unpad(self, padded_data: bytes) -> str:
        pad_len = padded_data[-1]
        return padded_data[:-pad_len].decode('utf-8')

    def encrypt(self, plaintext: str) -> bytes:
        data = self.pad(plaintext)
        # Stage 1: DES Encryption using Key 1
        cipher1 = DES.new(self.key1, DES.MODE_ECB)
        intermediate = cipher1.encrypt(data)
        # Stage 2: DES Encryption using Key 2
        cipher2 = DES.new(self.key2, DES.MODE_ECB)
        ciphertext = cipher2.encrypt(intermediate)
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        # Stage 1: DES Decryption using Key 2
        cipher2 = DES.new(self.key2, DES.MODE_ECB)
        intermediate = cipher2.decrypt(ciphertext)
        # Stage 2: DES Decryption using Key 1
        cipher1 = DES.new(self.key1, DES.MODE_ECB)
        decrypted_padded = cipher1.decrypt(intermediate)
        return self.unpad(decrypted_padded)

# Main execution
key1 = b'firstkey'
key2 = b'secdkey2'
d_des = DoubleDES(key1, key2)
msg = "Double DES Test!"
ct = d_des.encrypt(msg)
pt = d_des.decrypt(ct)

print("Plaintext:", msg)
print("Ciphertext (hex):", binascii.hexlify(ct).decode())
print("Decrypted:", pt)
