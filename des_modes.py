from Crypto.Cipher import DES
from Crypto.Util import Counter
import binascii

key = b'8bytekey'
plaintext = "This is a secret message that needs padding."
iv = b'initvect'  # 8-byte IV

def pad(text):
    pad_len = 8 - (len(text) % 8)
    return text.encode('utf-8') + bytes([pad_len] * pad_len)

def unpad(padded_data):
    pad_len = padded_data[-1]
    return padded_data[:-pad_len].decode('utf-8')

padded_pt = pad(plaintext)
print("--- DES Modes of Operation ---")

# 1. ECB Mode
c_ecb = DES.new(key, DES.MODE_ECB)
ct_ecb = c_ecb.encrypt(padded_pt)
dec_ecb = unpad(DES.new(key, DES.MODE_ECB).decrypt(ct_ecb))
print("ECB Ciphertext (hex):", binascii.hexlify(ct_ecb).decode())
print("ECB Decrypted:", dec_ecb)

# 2. CBC Mode
c_cbc = DES.new(key, DES.MODE_CBC, iv=iv)
ct_cbc = c_cbc.encrypt(padded_pt)
dec_cbc = unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ct_cbc))
print("CBC Ciphertext (hex):", binascii.hexlify(ct_cbc).decode())
print("CBC Decrypted:", dec_cbc)

# 3. CFB Mode
c_cfb = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=8)
ct_cfb = c_cfb.encrypt(padded_pt)
dec_cfb = unpad(DES.new(key, DES.MODE_CFB, iv=iv, segment_size=8).decrypt(ct_cfb))
print("CFB Ciphertext (hex):", binascii.hexlify(ct_cfb).decode())
print("CFB Decrypted:", dec_cfb)

# 4. OFB Mode
c_ofb = DES.new(key, DES.MODE_OFB, iv=iv)
ct_ofb = c_ofb.encrypt(padded_pt)
dec_ofb = unpad(DES.new(key, DES.MODE_OFB, iv=iv).decrypt(ct_ofb))
print("OFB Ciphertext (hex):", binascii.hexlify(ct_ofb).decode())
print("OFB Decrypted:", dec_ofb)

# 5. CTR Mode
ctr_obj = Counter.new(64, initial_value=0)
c_ctr = DES.new(key, DES.MODE_CTR, counter=ctr_obj)
ct_ctr = c_ctr.encrypt(padded_pt)
ctr_obj_dec = Counter.new(64, initial_value=0)
dec_ctr = unpad(DES.new(key, DES.MODE_CTR, counter=ctr_obj_dec).decrypt(ct_ctr))
print("CTR Ciphertext (hex):", binascii.hexlify(ct_ctr).decode())
print("CTR Decrypted:", dec_ctr)
