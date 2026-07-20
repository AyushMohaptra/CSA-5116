from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_cipher(data, key, mode='encrypt'):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    cipher = DES.new(key, DES.MODE_ECB)

    if mode == 'encrypt':
        padded_data = pad(data, DES.block_size)
        return cipher.encrypt(padded_data)
    elif mode == 'decrypt':
        decrypted_data = cipher.decrypt(data)
        return unpad(decrypted_data, DES.block_size).decode('utf-8')

key = "8charKey"
message = "Hello, World!"

encrypted = des_cipher(message, key, mode='encrypt')
print(f"Encrypted (hex): {encrypted.hex()}")

decrypted = des_cipher(encrypted, key, mode='decrypt')
print(f"Decrypted: {decrypted}")
