def rail_fence_cipher(text, rails, mode='encrypt'):
    if rails <= 1:
        return text

    if mode == 'encrypt':
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1

        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction

        return "".join("".join(r) for r in fence)

    elif mode == 'decrypt':
        pattern = [[] for _ in range(rails)]
        rail = 0
        direction = 1

        for i in range(len(text)):
            pattern[rail].append(i)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction

        flat_pattern = []
        for r in pattern:
            flat_pattern.extend(r)

        result = [None] * len(text)
        for text_index, fence_index in enumerate(flat_pattern):
            result[fence_index] = text[text_index]

        return "".join(result)

rails = 3
message = "WEAREDISCOVEREDFLEEATONCE"

encrypted = rail_fence_cipher(message, rails, mode='encrypt')
print(f"Encrypted: {encrypted}")

decrypted = rail_fence_cipher(encrypted, rails, mode='decrypt')
print(f"Decrypted: {decrypted}")
