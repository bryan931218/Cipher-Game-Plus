from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import os
import random


def decrypt_password(data: dict):
    try:
        key = base64.b64decode(data['key'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        return None
    
data = {'ciphertext': 'xxx', 'key': 'yyy', 'nonce': 'zzz' }
ciphertext = input("input ciphertext: ")
data['ciphertext'] = ciphertext
key = input('input key: ')
data['key'] = key
nonce = input('input nonce: ')
data['nonce'] = nonce
result = decrypt_password(data)
print(result)
    
