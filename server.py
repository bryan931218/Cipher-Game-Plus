# server.py
import socket
import json
import os
import base64
import random
import threading
import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

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

def generate_root_ca():
    """生成根CA證書和私鑰"""
    # 生成私鑰
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 設定根CA憑證資訊
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberSec Trust Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CyberSec Root CA"),
    ])
    
    # 設定憑證有效期
    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=3650)  # 10年有效期
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # 序列化憑證和私鑰
    cert_pem = cert.public_bytes(encoding=Encoding.PEM).decode()
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode()
    
    return {
        "cert": cert,
        "cert_pem": cert_pem,
        "private_key": private_key,
        "private_key_pem": private_key_pem
    }

def verify_certificate_chain(cert_chain, root_cert):
    """驗證憑證鏈"""
    try:
        # 解析憑證鏈
        user_cert = x509.load_pem_x509_certificate(cert_chain["user_cert"].encode(), default_backend())
        intermediate_cert = x509.load_pem_x509_certificate(cert_chain["intermediate_cert"].encode(), default_backend())
        root_cert_from_chain = x509.load_pem_x509_certificate(cert_chain["root_cert"].encode(), default_backend())
        
        # 驗證根憑證是否匹配
        if root_cert.fingerprint(hashes.SHA256()) != root_cert_from_chain.fingerprint(hashes.SHA256()):
            print("根憑證不匹配")
            return False
        
        # 驗證中繼憑證是否由根憑證簽發
        root_public_key = root_cert.public_key()
        try:
            root_public_key.verify(
                intermediate_cert.signature,
                intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                intermediate_cert.signature_hash_algorithm,
            )
            print("中繼憑證驗證成功")
        except Exception as e:
            print(f"中繼憑證驗證失敗: {e}")
            return False
        
        # 驗證用戶憑證是否由中繼憑證簽發
        intermediate_public_key = intermediate_cert.public_key()
        try:
            intermediate_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm,
            )
            print("用戶憑證驗證成功")
        except Exception as e:
            print(f"用戶憑證驗證失敗: {e}")
            return False
        
        # 檢查憑證有效期
        now = datetime.datetime.utcnow()
        for cert, name in [(user_cert, "用戶憑證"), (intermediate_cert, "中繼憑證"), (root_cert, "根憑證")]:
            if now < cert.not_valid_before or now > cert.not_valid_after:
                print(f"{name}已過期或尚未生效")
                return False
        
        # 檢查中繼憑證是否有CA權限
        for extension in intermediate_cert.extensions:
            if isinstance(extension.value, x509.BasicConstraints):
                if not extension.value.ca:
                    print("中繼憑證沒有CA權限")
                    return False
        
        return True
    except Exception as e:
        print(f"憑證鏈驗證過程發生錯誤: {e}")
        return False

# 處理客戶端連接的函數
def handle_client(conn, addr, game_data):
    try:
        print(f"🧑‍💻 玩家連線自 {addr}")

        # 接收客戶端的第一個訊息
        initial_request = conn.recv(1024).decode()
        
        # 檢查是否是第四關請求
        if initial_request == "START_LEVEL_4":
            # 第四關：憑證鏈偽造挑戰
            print(f"玩家 {addr} 請求進入第四關")
            
            # 發送根CA憑證和私鑰
            level4_data = {
                "root_cert": game_data["root_ca"]["cert_pem"],
                "root_private_key": game_data["root_ca"]["private_key_pem"],
                "challenge": "請使用提供的根CA私鑰創建一個中繼CA憑證，再用該中繼CA簽發一個用戶憑證，構成完整的憑證鏈。"
            }
            conn.sendall(json.dumps(level4_data).encode())
            print(f"已發送第四關數據給玩家 {addr}")
            
        elif initial_request == "VERIFY_CERT_CHAIN":
            # 接收憑證鏈
            cert_chain_data = conn.recv(16384).decode()  # 增加緩衝區大小以接收較大的憑證鏈
            cert_chain = json.loads(cert_chain_data)
            
            # 驗證憑證鏈
            print(f"玩家 {addr} 提交了憑證鏈，正在驗證...")
            is_valid = verify_certificate_chain(cert_chain, game_data["root_ca"]["cert"])
            
            if is_valid:
                print(f"玩家 {addr} 的憑證鏈驗證成功")
                # 發送最終獎勵
                final_reward = {
                    "status": "success",
                    "message": "恭喜！你已成功完成所有挑戰，包括憑證鏈偽造！",
                    "final_secret": game_data["final_secret"]
                }
                conn.sendall(json.dumps(final_reward).encode())
            else:
                print(f"玩家 {addr} 的憑證鏈驗證失敗")
                conn.sendall(json.dumps({
                    "status": "error",
                    "message": "憑證鏈驗證失敗，請檢查你的憑證是否符合要求。"
                }).encode())
        
        # 檢查是否是KMS直接訪問請求
        elif initial_request == "DIRECT_KMS_ACCESS":
            # 第三關：KMS服務
            print(f"玩家 {addr} 請求KMS服務")
            conn.sendall(b"KMS_READY")
            
            # 接收身份驗證請求
            auth_data = conn.recv(1024)
            auth_req = json.loads(auth_data.decode())
            
            username = auth_req.get("username", "")
            token = auth_req.get("token", "")
            
            print(f"收到身份驗證請求 - 用戶名: {username}, 令牌: {token}")
            
            # 驗證用戶身份
            if username in game_data["valid_users"] and game_data["valid_users"][username] == token:
                # 身份驗證成功，返回AES金鑰
                print(f"玩家 {addr} 身份驗證成功")
                response = {
                    "status": "success",
                    "message": "身份驗證成功，已獲取解密金鑰。",
                    "aes_key": base64.b64encode(game_data["aes_key"]).decode(),
                    "nonce": base64.b64encode(game_data["aes_nonce"]).decode(),
                    "ciphertext": base64.b64encode(game_data["final_ciphertext"]).decode()
                }
            else:
                # 身份驗證失敗
                print(f"玩家 {addr} 身份驗證失敗")
                response = {
                    "status": "error",
                    "message": "身份驗證失敗，用戶名或令牌無效。"
                }
            
            conn.sendall(json.dumps(response).encode())
            print(f"玩家 {addr} KMS服務請求處理完成。")
            
        elif initial_request == "START_LEVEL_3":
            # 第三關：發送加密數據但不發送金鑰
            print(f"玩家 {addr} 請求進入第三關")
            # 發送第三關所需的數據，但不包括 AES 金鑰
            level3_data = {
                "encrypted_aes_key": game_data["encrypted_aes_key"],
                "nonce": base64.b64encode(game_data["aes_nonce"]).decode(),
                "ciphertext": base64.b64encode(game_data["final_ciphertext"]).decode()
            }
            conn.sendall(json.dumps(level3_data).encode())
            print(f"已發送第三關數據給玩家 {addr}，玩家需要使用 KMS 客戶端工具獲取金鑰。")
            
        elif initial_request == "VERIFY_FINAL_SOLUTION":
            # 接收客戶端提交的最終解密訊息
            solution_data = conn.recv(4096).decode()
            solution = json.loads(solution_data)
            
            submitted_message = solution.get("message", "")
            
            # 驗證解密結果是否正確
            if submitted_message == game_data["final_message"]:
                print(f"玩家 {addr} 成功解密最終訊息")
                conn.sendall(json.dumps({
                    "status": "success",
                    "message": "恭喜！你已成功完成所有挑戰！",
                    "next_level": "第四關：憑證鏈偽造挑戰"
                }).encode())
            else:
                print(f"玩家 {addr} 解密訊息不正確")
                conn.sendall(json.dumps({
                    "status": "error",
                    "message": "解密訊息不正確，請重試。"
                }).encode())
        
        elif initial_request == "START_GAME":
            # 正常流程 (第一關和第二關)
            print(f"玩家 {addr} 開始正常遊戲流程")
            
            # Step 1: 傳送挑戰（加密的公鑰）
            conn.sendall(json.dumps(game_data["encrypted_date"]).encode())
            check = conn.recv(1024).decode()
            print(f"玩家 {addr}: {check}")
            if check == "player recieved the plaintext":
                conn.sendall(json.dumps(game_data["encrypted_pubkey"]).encode())

            # Step 2: 等待 client 回覆是否解密成功
            ack = conn.recv(1024).decode()
            if ack != "OK":
                print(f"玩家 {addr} 解密失敗。")
            else:
                # Step 3: 傳送訊息與簽章
                payload = json.dumps({
                    "message": game_data["message"],
                    "signature": game_data["signature_b64"]
                }).encode()
                conn.sendall(payload)

                print(f"資料傳送完成給玩家 {addr}，等待玩家進入第三關...")
        
        else:
            print(f"玩家 {addr} 發送了未知請求: {initial_request}")
            conn.sendall(b"Unknown request")
    except Exception as e:
        print(f"處理玩家 {addr} 連接時發生錯誤: {str(e)}")
    finally:
        conn.close()
        print(f"玩家 {addr} 的連接已關閉")

# === 主程式 ===
def main():
    # === 初始化遊戲數據 ===
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

    # 模擬的 OAuth 驗證資訊 (第三關)
    valid_users = {
        "agent007": "token_agent007",
        "agent42": "token_agent42", 
    }

    # 生成一個隨機的AES金鑰用於第三關
    aes_key = os.urandom(32)
    aes_nonce = os.urandom(12)
    final_message = "恭喜你完成了所有挑戰！你已經掌握了現代密碼學的三個核心概念：對稱加密、非對稱加密與數位簽章、以及混合加密與金鑰管理。這些技術是保護數位世界安全的基石。"

    # 使用AES-GCM加密最終訊息
    aesgcm = AESGCM(aes_key)
    final_ciphertext = aesgcm.encrypt(aes_nonce, final_message.encode(), None)

    # 為第三關準備加密的 AES 金鑰（模擬 RSA 加密）
    encrypted_aes_key = base64.b64encode(os.urandom(128)).decode()  # 模擬 RSA 加密後的 AES 金鑰

    # 生成第四關所需的根CA憑證
    root_ca = generate_root_ca()
    
    # 第四關的最終獎勵
    final_secret = "你已經成功掌握了PKI和憑證鏈的概念，這是現代安全通訊的基礎。恭喜你完成了所有挑戰！"

    # 將所有遊戲數據打包到一個字典中
    game_data = {
        "date": date,
        "private_key": private_key,
        "public_key": public_key,
        "public_pem": public_pem,
        "encrypted_date": encrypted_date,
        "encrypted_pubkey": encrypted_pubkey,
        "message": message,
        "signature_b64": signature_b64,
        "valid_users": valid_users,
        "aes_key": aes_key,
        "aes_nonce": aes_nonce,
        "final_message": final_message,
        "final_ciphertext": final_ciphertext,
        "encrypted_aes_key": encrypted_aes_key,
        "root_ca": root_ca,
        "final_secret": final_secret
    }

    # 輸出一些有用的調試信息
    print("伺服器初始化完成")
    print(f"生成的日期密碼: {date}")
    print(f"AES 金鑰 (Base64): {base64.b64encode(aes_key).decode()}")
    print(f"有效的用戶名和令牌: {valid_users}")
    print("根CA憑證已生成")

    # === 啟動伺服器 ===
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 12347))
        s.listen(5)  # 允許最多5個連接排隊
        print("伺服器已啟動，等待玩家連線...")
        
        while True:
            conn, addr = s.accept()
            # 為每個客戶端創建一個新線程
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, game_data))
            client_thread.daemon = True  # 設置為守護線程，這樣主線程結束時它們也會結束
            client_thread.start()
            print(f"為玩家 {addr} 創建了新線程")

if __name__ == "__main__":
    main()