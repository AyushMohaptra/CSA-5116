def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    
    # If decrypting, we just reverse the shift direction
    if mode == 'decrypt':
        shift = -shift
        
    for char in text:
        # Process uppercase letters
        if char.isupper():
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        # Process lowercase letters
        elif char.islower():
            result += chr((ord(char) - 97 + shift) % 26 + 97)
        # Leave spaces and punctuation exactly as they are
        else:
            result += char
            
    return result

# --- Quick Test ---
message = "Hello, World!"
secret_shift = 4

# 1. Encrypt the message
encrypted = caesar_cipher(message, secret_shift, mode='encrypt')
print(f"Encrypted: {encrypted}") 
# Output: Lipps, Asvph!

# 2. Decrypt it back
decrypted = caesar_cipher(encrypted, secret_shift, mode='decrypt')
print(f"Decrypted: {decrypted}") 
# Output: Hello, World!
