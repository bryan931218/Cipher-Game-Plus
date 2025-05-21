import socket
import json
import os
import base64
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def encrypt_password(plaintext: str):
    key = os.urandom(32)     # 256-bit AES key
    nonce = os.urandom(12)   # 96-bit nonce (GCM standard)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'key': base64.b64encode(key).decode(),      # You must store/transmit this!
        'nonce': base64.b64encode(nonce).decode()
    }

def encrypt_message(password: str, plaintext: str):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode()
    }

def sign_message(private_key, message: str) -> str:
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# === Initialization ===
year = random.randint(1965, 2005)
month = random.randint(1, 12)
day = random.randint(1, 29 if month == 2 else 30 if month in [4, 6, 9, 11] else 31)
date = f"{year:04}{month:02}{day:02}"

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

encrypted_date = encrypt_password(date)
encrypted_pubkey = encrypt_message(date, public_pem)
message = "這是來自密碼導師的訊息，請驗證其真實性。"
signature_b64 = sign_message(private_key, message)

# === Server Socket ===
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("localhost", 12347))
    s.listen(1)
    print("等待玩家連線...")
    conn, addr = s.accept()
    with conn:
        print(f"🧑‍💻 玩家連線自 {addr}")

        # Step 1: 傳送挑戰（加密的公鑰）
        conn.sendall(json.dumps(encrypted_date).encode())
        check = conn.recv(1024).decode()
        print(check)
        if check == "player recieved the plaintext":
            conn.sendall(json.dumps(encrypted_pubkey).encode())

        # Step 2: 等待 client 回覆是否解密成功
        ack = conn.recv(1024).decode()
        if ack != "OK":
            print("玩家解密失敗。")
            conn.close()
        else:
            # Step 3: 傳送訊息與簽章
            payload = json.dumps({
                "message": message,
                "signature": signature_b64
            }).encode()
            conn.sendall(payload)

            print("資料傳送完成，斷線。")
