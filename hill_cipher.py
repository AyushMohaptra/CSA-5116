import numpy as np

def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = -1
    for i in range(1, modulus):
        if (det * i) % modulus == 1:
            det_inv = i
            break
    if det_inv == -1:
        raise ValueError("Matrix is not invertible under the given modulus.")
    
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int)
    return (det_inv * adjugate) % modulus

def prepare_text(text):
    text = "".join([c.upper() for c in text if c.isalpha()])
    if len(text) % 2 != 0:
        text += 'X'
    return text

def hill_cipher(text, key_matrix, mode='encrypt'):
    text = prepare_text(text)
    key_matrix = np.array(key_matrix)
    
    if mode == 'decrypt':
        key_matrix = matrix_mod_inv(key_matrix, 26)
        
    result = []
    for i in range(0, len(text), 2):
        vector = np.array([ord(text[i]) - 65, ord(text[i+1]) - 65])
        transformed = np.dot(key_matrix, vector) % 26
        result.append(chr(int(transformed[0]) + 65))
        result.append(chr(int(transformed[1]) + 65))
        
    return "".join(result)

key = [[5, 8], [17, 3]]
message = "HELP"

encrypted = hill_cipher(message, key, mode='encrypt')
print(f"Encrypted: {encrypted}")

decrypted = hill_cipher(encrypted, key, mode='decrypt')
print(f"Decrypted: {decrypted}")
