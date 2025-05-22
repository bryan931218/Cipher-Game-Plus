from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import json
import socket
import time
import os

def slow_print(text, delay=0.02):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def print_title(text):
    print("\n\033[104m\033[97m " + text + " \033[0m\n")

def print_subtitle(text):
    print(f"\n\033[93m\033[4m{text}\033[0m")

def print_explanation(text):
    print("\033[93m" + text + "\033[0m")

def print_success(text):
    print("\033[92m" + text + "\033[0m")

def print_error(text):
    print("\033[91m" + text + "\033[0m")

def print_info(text):
    print("\033[96m" + text + "\033[0m")

def authenticate_with_kms():
    print_title("KMS 金鑰管理服務客戶端")
    
    print_explanation("這個工具可以幫助你連接到 KMS (金鑰管理服務)，獲取解密後的 AES 金鑰。")
    print_explanation("KMS 使用 OAuth 2.0 身份驗證模型，需要提供有效的用戶名和驗證 Token。")
    
    while True:
        print_subtitle("OAuth 2.0 身份驗證")
        print_info("請提供以下資訊以連接 KMS 服務：")
        
        username = input("\n👤 用戶名稱: ")
        token = input("🔑 驗證 Token: ")
        
        print_subtitle("連接到 KMS 服務")
        print_info("正在建立連接...")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("localhost", 12347))
                
                # 跳過前兩關，直接進入第三關
                s.sendall(b"DIRECT_KMS_ACCESS")
                response = s.recv(1024).decode()
                
                if response != "KMS_READY":
                    print_error(f"無法連接到 KMS 服務：{response}")
                    break
                
                # 發送身份驗證請求
                auth_request = {
                    "username": username,
                    "token": token
                }
                s.sendall(json.dumps(auth_request).encode())
                
                # 接收 KMS 回應
                kms_response_raw = s.recv(2048)
                kms_response = json.loads(kms_response_raw.decode())
                
                print_subtitle("身份驗證結果")
                
                if kms_response["status"] == "success":
                    print_success("✅ 身份驗證成功！")
                    print_success(f"訊息：{kms_response['message']}")
                    
                    if "aes_key" in kms_response:
                        print_subtitle("獲取的 AES 金鑰")
                        aes_key_b64 = kms_response["aes_key"]
                        print_info(f"AES 金鑰 (Base64): {aes_key_b64}")
                        
                        # 解碼 Base64 以顯示十六進位格式
                        aes_key = base64.b64decode(aes_key_b64)
                        print_info(f"AES 金鑰 (十六進位): {aes_key.hex()}")
                        
                        # 顯示nonce和密文（如果有）
                        if "nonce" in kms_response:
                            print_subtitle("獲取的 Nonce")
                            nonce_b64 = kms_response["nonce"]
                            print_info(f"Nonce (Base64): {nonce_b64}")
                        
                        if "ciphertext" in kms_response:
                            print_subtitle("獲取的密文")
                            ciphertext_b64 = kms_response["ciphertext"]
                            print_info(f"密文 (Base64): {ciphertext_b64}")
                    else:
                        print_error("KMS 回應中沒有包含 AES 金鑰")
                    
                    # 身份驗證成功，退出循環
                    break
                else:
                    print_error(f"❌ 身份驗證失敗：{kms_response['message']}")
                    print_explanation("請檢查你的用戶名和驗證 Token 是否正確。")
                    os.system("pause")
                    os.system("cls")
                    
        except ConnectionRefusedError:
            print_error("\n無法連接到 KMS 服務，請確認伺服器已啟動。")
            break
        except Exception as e:
            print_error(f"\n發生錯誤：{str(e)}")
            retry = input("\n是否重試？(y/n): ")
            if retry.lower() != 'y':
                break

# 主程式
authenticate_with_kms()

print("\n程式結束")
os.system("pause" if os.name == "nt" else "read -p '按下 Enter 繼續...' var")