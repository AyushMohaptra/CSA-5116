from Crypto.Cipher import DES3
import binascii

def pad(text):
    pad_len = 8 - (len(text) % 8)
    return text.encode('utf-8') + bytes([pad_len] * pad_len)

def unpad(padded_data):
    pad_len = padded_data[-1]
    return padded_data[:-pad_len].decode('utf-8')

# Define 24-byte key (Option 1 with three independent 8-byte keys)
key = b'thisisaverylong16bytekey'  # 24-byte key
msg = "Triple DES Test Message!"

# Encrypt
cipher_encrypt = DES3.new(key, DES3.MODE_ECB)
ct = cipher_encrypt.encrypt(pad(msg))

# Decrypt
cipher_decrypt = DES3.new(key, DES3.MODE_ECB)
pt = unpad(cipher_decrypt.decrypt(ct))

print("Plaintext:", msg)
print("Ciphertext (hex):", binascii.hexlify(ct).decode())
print("Decrypted:", pt)
