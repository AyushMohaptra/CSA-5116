def prepare_key(keyword):
    keyword = keyword.upper().replace('J', 'I')
    matrix = []
    seen = set()
    
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in keyword + alphabet:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)
            
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def prepare_text(text):
    text = text.upper().replace('J', 'I')
    cleaned = "".join([c for c in text if c.isalpha()])
    
    prepared = []
    i = 0
    while i < len(cleaned):
        char1 = cleaned[i]
        if i + 1 == len(cleaned):
            char2 = 'X'
            i += 1
        elif cleaned[i] == cleaned[i+1]:
            char2 = 'X'
            i += 1
        else:
            char2 = cleaned[i+1]
            i += 2
        prepared.append((char1, char2))
    return prepared

def playfair_cipher(text, keyword, mode='encrypt'):
    matrix = prepare_key(keyword)
    pairs = prepare_text(text)
    result = []
    
    shift = 1 if mode == 'encrypt' else -1
    
    for char1, char2 in pairs:
        r1, c1 = find_position(matrix, char1)
        r2, c2 = find_position(matrix, char2)
        
        if r1 == r2:
            result.append(matrix[r1][(c1 + shift) % 5])
            result.append(matrix[r2][(c2 + shift) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + shift) % 5][c1])
            result.append(matrix[(r2 + shift) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])
            
    return "".join(result)

key = "MONARCHY"
message = "instruments"

encrypted = playfair_cipher(message, key, mode='encrypt')
print(f"Encrypted: {encrypted}") 

decrypted = playfair_cipher(encrypted, key, mode='decrypt')
print(f"Decrypted: {decrypted}")
