def vigenere_cipher(text, key, mode='encrypt'):
    result = []
    key = key.upper()
    key_indices = [ord(char) - 65 for char in key if char.isalpha()]
    
    if not key_indices:
        return text

    key_length = len(key_indices)
    key_index = 0

    for char in text:
        if char.isupper():
            shift = key_indices[key_index % key_length]
            if mode == 'decrypt':
                shift = -shift
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
            key_index += 1
        elif char.islower():
            shift = key_indices[key_index % key_length]
            if mode == 'decrypt':
                shift = -shift
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
            key_index += 1
        else:
            result.append(char)

    return "".join(result)

key = "KEY"
message = "Hello, World!"

encrypted = vigenere_cipher(message, key, mode='encrypt')
print(f"Encrypted: {encrypted}")

decrypted = vigenere_cipher(encrypted, key, mode='decrypt')
print(f"Decrypted: {decrypted}")
