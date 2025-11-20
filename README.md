# EX-8-ADVANCED-ENCRYPTION-STANDARD ALGORITHM
# Aim:
To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

# ALGORITHM:
AES is based on a design principle known as a substitution–permutation.
AES does not use a Feistel network like DES, it uses variant of Rijndael.
It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
AES operates on a 4 × 4 column-major order array of bytes, termed the state
# PROGRAM:
```
!pip install pycryptodome
from Crypto.Cipher import AES
import base64
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)
def unpad(text):
    return text[:-ord(text[-1])]
key = b'ThisIsA16ByteKey'
plain = "HELLO WORLD"
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(pad(plain).encode())
encrypted_b64 = base64.b64encode(encrypted).decode()
decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_b64)).decode())
print("Plaintext  :", plain)
print("Encrypted  :", encrypted_b64)
print("Decrypted  :", decrypted)
```
# OUTPUT:
<img width="427" height="76" alt="image" src="https://github.com/user-attachments/assets/7f510f6c-6300-43c1-a3b6-01fbc16ee1f1" />

# RESULT:
The program is executed Successfully.


