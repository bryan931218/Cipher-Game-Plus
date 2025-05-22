from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import json
import socket
import time
import os

def clear():
    """清除終端螢幕"""
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.02):
    """逐字印出文字，產生打字機效果"""
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def print_title(text):
    """印出主標題 - 藍色背景白色文字"""
    print("\n\033[104m\033[97m " + text + " \033[0m\n")

def print_subtitle(text):
    """印出副標題 - 黃色加底線"""
    print(f"\n\033[93m\033[4m{text}\033[0m")

def print_explanation(text):
    """印出說明文字 - 黃色"""
    print("\033[93m" + text + "\033[0m")

def print_success(text):
    """印出成功訊息 - 綠色"""
    print("\033[92m" + text + "\033[0m")

def print_error(text):
    """印出錯誤訊息 - 紅色"""
    print("\033[91m" + text + "\033[0m")

def print_info(text):
    """印出資訊 - 淺藍色"""
    print("\033[96m" + text + "\033[0m")

def print_step(step_num, text):
    """印出步驟 - 藍色粗體步驟號 + 文字"""
    print(f"\n\033[1m\033[94m[步驟 {step_num}]\033[0m {text}")

def print_progress_bar(percent, width=40):
    """印出進度條"""
    filled_width = int(width * percent / 100)
    bar = "█" * filled_width + "░" * (width - filled_width)
    print(f"\r\033[96m[{bar}] {percent}%\033[0m", end='', flush=True)

def animate_progress(duration=1.0):
    """顯示動畫進度條"""
    for i in range(101):
        print_progress_bar(i)
        time.sleep(duration/100)
    print()

def print_hex_dump(data, prefix="", bytes_per_line=16):
    """以十六進位格式顯示數據"""
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_values = " ".join(f"{b:02x}" for b in chunk)
        ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        padding = " " * (bytes_per_line * 3 - len(hex_values))
        print(f"{prefix}{i:04x}: {hex_values}{padding}  |{ascii_values}|")

def print_key_info(key_name, key_value_b64):
    """美化顯示金鑰資訊"""
    print_subtitle(f"獲取的 {key_name}")
    print_info(f"{key_name} (Base64): {key_value_b64}")
    
    # 解碼 Base64 以顯示十六進位格式
    key_bytes = base64.b64decode(key_value_b64)
    print_info(f"{key_name} (十六進位): {key_bytes.hex()}")
    print_info(f"{key_name} (長度): {len(key_bytes)} 位元組")
    
    print_info(f"\n{key_name} 十六進位詳細內容:")
    print_hex_dump(key_bytes, "  ")

def authenticate_with_kms():
    """KMS 身份驗證主函數"""
    clear()
    print_title("KMS 金鑰管理服務客戶端")
    
    print_explanation("這個工具可以幫助你連接到 KMS (金鑰管理服務)，獲取解密後的 AES 金鑰。")
    print_explanation("KMS 使用 OAuth 2.0 身份驗證模型，需要提供有效的用戶名和驗證 Token。")
    
    print_subtitle("KMS 服務架構")
    print_info("🔐 KMS (金鑰管理服務) 是一種安全的密鑰存儲和管理系統")
    print_info("  • 存儲加密金鑰，避免直接在應用程序中硬編碼")
    print_info("  • 提供訪問控制，只有授權用戶才能獲取金鑰")
    print_info("  • 支持金鑰輪換和版本控制")
    print_info("  • 記錄所有金鑰訪問和使用的審計日誌")
    
    print_subtitle("OAuth 2.0 身份驗證流程")
    print_info("1. 客戶端提供用戶名和令牌")
    print_info("2. 服務器驗證這些憑據")
    print_info("3. 如果有效，服務器返回請求的金鑰")
    print_info("4. 如果無效，服務器拒絕請求")
    
    while True:
        print_subtitle("OAuth 2.0 身份驗證")
        print_info("請提供以下資訊以連接 KMS 服務：")
        
        username = input("\n👤 用戶名稱: ")
        token = input("🔑 驗證 Token: ")
        
        print_step(1, "準備連接請求")
        print_info("  • 構建 OAuth 2.0 身份驗證請求...")
        time.sleep(0.3)
        
        auth_request = {
            "username": username,
            "token": token
        }
        
        print_info(f"  • 用戶名: {username}")
        print_info(f"  • Token: {'*' * len(token)}")
        
        print_step(2, "建立連接到 KMS 服務")
        print_info("  • 初始化 TCP 套接字...")
        time.sleep(0.2)
        print_info("  • 連接到 localhost:12347...")
        time.sleep(0.5)
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("localhost", 12347))
                print_success("  • 連接成功！")
                
                print_step(3, "發送 KMS 訪問請求")
                print_info("  • 發送 DIRECT_KMS_ACCESS 命令...")
                time.sleep(0.3)
                
                # 跳過前兩關，直接進入第三關
                s.sendall(b"DIRECT_KMS_ACCESS")
                response = s.recv(1024).decode()
                
                if response != "KMS_READY":
                    print_error(f"  • 錯誤: 服務器回應 '{response}'，預期 'KMS_READY'")
                    break
                
                print_success("  • 服務器回應: KMS_READY")
                
                print_step(4, "發送身份驗證資訊")
                print_info("  • 序列化身份驗證請求...")
                time.sleep(0.2)
                auth_json = json.dumps(auth_request).encode()
                
                print_info("  • 發送身份驗證資訊...")
                time.sleep(0.3)
                s.sendall(auth_json)
                
                print_step(5, "接收 KMS 回應")
                print_info("  • 等待服務器回應...")
                
                # 顯示等待動畫
                for _ in range(3):
                    for c in "|/-\\":
                        print(f"\r  • 等待服務器回應... {c}", end='', flush=True)
                        time.sleep(0.1)
                
                kms_response_raw = s.recv(2048)
                print(f"\r  • 收到 {len(kms_response_raw)} 位元組的回應      ")
                time.sleep(0.2)
                
                print_info("  • 解析 JSON 回應...")
                kms_response = json.loads(kms_response_raw.decode())
                
                print_subtitle("身份驗證結果")
                
                if kms_response["status"] == "success":
                    print_success("✅ 身份驗證成功！")
                    print_success(f"訊息：{kms_response['message']}")
                    
                    if "aes_key" in kms_response:
                        # 顯示 AES 金鑰
                        print_key_info("AES 金鑰", kms_response["aes_key"])
                        
                        # 顯示 nonce（如果有）
                        if "nonce" in kms_response:
                            print_key_info("Nonce", kms_response["nonce"])
                        
                        # 顯示密文（如果有）
                        if "ciphertext" in kms_response:
                            print_subtitle("獲取的密文")
                            ciphertext_b64 = kms_response["ciphertext"]
                            print_info(f"密文 (Base64, 前50字符): {ciphertext_b64[:50]}...")
                            ciphertext = base64.b64decode(ciphertext_b64)
                            print_info(f"密文長度: {len(ciphertext)} 位元組")
                            
                            print_subtitle("密文前 64 位元組預覽")
                            preview_length = min(64, len(ciphertext))
                            print_hex_dump(ciphertext[:preview_length], "  ")
                    
                    # 身份驗證成功，退出循環
                    break
                else:
                    print_error(f"❌ 身份驗證失敗：{kms_response['message']}")
                    print_explanation("請檢查你的用戶名和驗證 Token 是否正確。")
                    
                    if os.name == "nt":
                        os.system("pause")
                    else:
                        input("按下 Enter 繼續...")
                    
                    clear()
                    
        except ConnectionRefusedError:
            print_error("\n❌ 無法連接到 KMS 服務，請確認伺服器已啟動。")
            break
        except Exception as e:
            print_error(f"\n❌ 發生錯誤：{str(e)}")
            retry = input("\n是否重試？(y/n): ")
            if retry.lower() != 'y':
                break

# 主程式
if __name__ == "__main__":
    authenticate_with_kms()
    print("\n🔚 程式結束")
    
    if os.name == "nt":
        os.system("pause")
    else:
        input("按下 Enter 繼續...")