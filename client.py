import socket
import json
import base64
import sys
import time
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# === Helper Functions ===
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.03):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def decrypt_message(password: str, data: dict):
    try:
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=None
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        return None

def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# === Game Start ===
clear()
slow_print("🔐 歡迎來到《密碼挑戰：解鎖真相》", 0.05)
slow_print("你是一名特工，收到一則神秘訊息，內含加密挑戰與機密資訊。", 0.04)
input("\n請按下 Enter 鍵以開始任務...")

# === Client Socket ===
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("localhost", 12347))
    clear()

    # Step 1: 接收 challenge（加密公鑰）
    slow_print("📡 正在接收密文任務資料...")
    data1 = s.recv(2048)
    plain = json.loads(data1.decode())
    slow_print("📝 任務提示內容如下：")
    print(json.dumps(plain, indent=2, ensure_ascii=False))
    
    s.sendall(b"player recieved the plaintext")
    data2 = s.recv(2048)
    challenge = json.loads(data2.decode())
    slow_print("\n🧩 解密挑戰已收到，準備解碼關鍵訊息...\n")

    # Step 2: 玩家輸入密碼解密
    while True:
        pwd = input("🔑 請輸入密碼以解密關鍵內容：")
        decrypted = decrypt_message(pwd, challenge)
        if decrypted:
            slow_print("\n✅ 成功解密！取得公開金鑰如下：\n")
            print(decrypted)
            s.sendall(b"OK")
            break
        else:
            slow_print("❌ 解密失敗，請重試。")

    # Step 3: 接收簽章與訊息
    slow_print("\n📨 正在接收簽章與訊息...")
    signed_data = s.recv(2048)
    info = json.loads(signed_data.decode())
    slow_print("\n📬 收到的訊息內容如下：")
    print(info["message"])

    slow_print("\n🔎 驗證簽章中... 請輸入訊息簽章的公鑰（PEM 格式）後按 Ctrl+D 結束輸入：\n")
    player_pem = sys.stdin.read()

    if verify_signature(player_pem, info["message"], info["signature"]):
        slow_print("\n🛡️ 驗證成功！訊息可信。任務完成，你成功揭露了真相！ 🎉")
    else:
        slow_print("\n⚠️ 驗證失敗，訊息可能被竄改。任務失敗... 💀")

    slow_print("\n🔚 遊戲結束，感謝你的參與。")
