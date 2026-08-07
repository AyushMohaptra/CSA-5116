from Crypto.Cipher import DES
import binascii

def pad(text):
    # Pad the text to be a multiple of 8 bytes
    while len(text) % 8 != 0:
        text += ' '
    return text.encode('utf-8')

# Define 8-byte key and plaintext
key = b'8bytekey'
plaintext = "HelloDES"

# Encrypt
cipher = DES.new(key, DES.MODE_ECB)
padded_text = pad(plaintext)
ciphertext = cipher.encrypt(padded_text)

# Decrypt
decrypted_padded = cipher.decrypt(ciphertext)
decrypted = decrypted_padded.decode('utf-8').rstrip()

print("Original Text:", plaintext)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())
print("Decrypted Text:", decrypted)
