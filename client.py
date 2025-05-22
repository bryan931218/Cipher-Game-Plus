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

# === 顯示效果函數 ===
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.03):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def print_title(text):
    # 淺藍色背景，白色文字
    print("\n\033[104m\033[97m " + text + " \033[0m\n")

def print_subtitle(text):
    # 黃色文字，底線
    print(f"\n\033[93m\033[4m{text}\033[0m")

def print_success(text):
    # 綠色文字
    print("\033[92m" + text + "\033[0m")

def print_error(text):
    # 紅色文字
    print("\033[91m" + text + "\033[0m")

def print_tool_info(text):
    # 淺藍色文字
    print("\033[96m" + text + "\033[0m")

def print_hint(text):
    # 黃色文字
    print("\033[93m" + text + "\033[0m")

def print_progress_bar(percent, width=40):
    filled_width = int(width * percent / 100)
    bar = "█" * filled_width + "░" * (width - filled_width)
    print(f"\r\033[96m[{bar}] {percent}%\033[0m", end='', flush=True)

def animate_progress(duration=1.0):
    for i in range(101):
        print_progress_bar(i)
        time.sleep(duration/100)
    print()

def display_available_tools():
    print_subtitle("可用工具列表")
    try:
        # 檢查 tools 資料夾是否存在
        if os.path.exists("tools"):
            tools = os.listdir("tools")
            if tools:
                for i, tool in enumerate(tools, 1):
                    if tool.endswith(".py"):
                        print_tool_info(f"  {i}. {tool} - Python 工具")
                        if tool == "decrypt.py":
                            print_hint(f"     - 用於解密第一關提示，獲取密碼")
                    elif tool.endswith(".sh"):
                        print_tool_info(f"  {i}. {tool} - Shell 腳本")
                    else:
                        print_tool_info(f"  {i}. {tool}")
            else:
                print_tool_info("  目前沒有可用的工具。")
        else:
            print_tool_info("  找不到 tools 資料夾，請確認遊戲安裝完整。")
    except Exception as e:
        print_tool_info(f"  讀取工具列表時發生錯誤: {str(e)}")

def decrypt_message(password: str, data: dict):
    try:
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])

        print("\n[步驟1] 密碼輸入：", password)
        
        print("\n[步驟2] 解碼 salt")
        print("  Base64 格式：", data['salt'])
        print("  十六進位格式：", salt.hex())
        
        print("\n[步驟3] 解碼 nonce")
        print("  Base64 格式：", data['nonce'])
        print("  十六進位格式：", nonce.hex())
        
        print("\n[步驟4] 解碼密文")
        print("  Base64 格式：", data['ciphertext'])
        print("  十六進位格式：", ciphertext.hex())

        print("\n[步驟5] 使用 PBKDF2 衍生金鑰")
        print("  演算法：SHA256")
        print("  迭代次數：100,000")
        print("  正在衍生金鑰...")
        time.sleep(0.5)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=None
        )
        key = kdf.derive(password.encode())
        print("  衍生完成！")
        print("  金鑰 (十六進位)：", key.hex())
        print("  金鑰 (Base64)：", base64.b64encode(key).decode())

        print("\n[步驟6] 使用 AES-GCM 解密")
        print("  正在初始化 AES-GCM 引擎...")
        time.sleep(0.3)
        print("  正在解密...")
        time.sleep(0.5)
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        result = plaintext.decode()
        print("  解密成功！")
        
        return result
    except Exception as e:
        print("\n[錯誤] 解密失敗：", str(e))
        return None

def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    try:
        print_subtitle("簽章驗證過程")
        print("\033[1m\033[96m[步驟1]\033[0m 載入公鑰")
        print("  正在解析 PEM 格式公鑰...")
        time.sleep(0.5)
        
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        print("  公鑰載入成功！")
        
        print("\033[1m\033[96m[步驟2]\033[0m 解碼簽章")
        print("  Base64 格式簽章：\033[96m" + signature_b64[:20] + "...\033[0m")
        signature = base64.b64decode(signature_b64)
        print("  解碼完成！")
        
        print("\033[1m\033[96m[步驟3]\033[0m 驗證訊息簽章")
        print("  使用演算法：PKCS1v15 + SHA256")
        print("  正在驗證...")
        time.sleep(0.8)
        
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print_error(f"\n[錯誤] 驗證過程發生錯誤：{str(e)}")
        return False

# === Game Start ===
clear()
print_title("密碼挑戰：解鎖真相")

slow_print("🔐 歡迎來到《密碼挑戰：解鎖真相》", 0.05)
slow_print("你是一名特工，收到一則神秘訊息，內含加密挑戰與機密資訊。", 0.04)

# 顯示工具使用說明
print_hint("\n💡 任務提示：")
print_hint("  在遊戲過程中，你可以使用 tools 資料夾中的工具來協助完成任務。")
print_hint("  這些工具能幫助你解密訊息、分析數據。")

# 顯示可用工具
display_available_tools()

input("\n請按下 Enter 鍵以開始任務...")

# === Client Socket ===
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        clear()
        print_title("任務進行中")
        
        print("正在連接到伺服器...")
        s.connect(("localhost", 12347))
        print_success("連接成功！")

        slow_print("\n📡 正在接收密文任務資料...")
        data1 = s.recv(2048)
        plain = json.loads(data1.decode())
        
        print_subtitle("任務提示內容")
        print(json.dumps(plain, indent=2, ensure_ascii=False))

        s.sendall(b"player recieved the plaintext")
        data2 = s.recv(2048)
        challenge = json.loads(data2.decode())
        slow_print("\n🧩 解密挑戰已收到，準備解碼關鍵訊息...\n")
        
        # 第二關解密挑戰
        while True:
            print_subtitle("第一關：密碼解密")
            pwd = input("\n🔑 請輸入密碼以解密關鍵內容：")
            decrypted = decrypt_message(pwd, challenge)
            if decrypted:
                print_success("\n✅ 成功解密！取得公開金鑰如下：")
                print("\n" + decrypted)
                s.sendall(b"OK")
                break
            else:
                print_error("\n❌ 解密失敗，請重試。")

        # 第三關簽章驗證
        print_subtitle("第二關：簽章驗證")
        slow_print("\n📨 正在接收簽章與訊息...")
        signed_data = s.recv(2048)
        info = json.loads(signed_data.decode())
        
        print_subtitle("收到的訊息")
        print(info["message"])
        print("\n簽章 (Base64)：\033[90m" + info["signature"][:20] + "...\033[0m")

        print("\n🔎 驗證簽章中...")
        print_hint("💡 提示：使用你在上一步解密獲得的公鑰來驗證簽章。")
        print_hint("請輸入訊息簽章的公鑰（PEM 格式）後按 Ctrl+D 或 Ctrl+Z(Windows) 結束輸入：\n")
        
        player_pem = sys.stdin.read()

        if verify_signature(player_pem, info["message"], info["signature"]):
            print_title("任務完成")
            print_success("\n🛡️ 驗證成功！訊息可信。")
            print_success("任務完成，你成功揭露了真相！ 🎉")
        else:
            print_title("任務失敗")
            print_error("\n⚠️ 驗證失敗，訊息可能被竄改。")
            print_hint("\n💡 提示：確保你輸入的是完整的公鑰，包括開頭的 '-----BEGIN PUBLIC KEY-----' 和結尾的 '-----END PUBLIC KEY-----'。")

        print("\n🔚 遊戲結束，感謝你的參與。")
        
except ConnectionRefusedError:
    print_error("\n無法連接到伺服器，請確認伺服器已啟動。")
except Exception as e:
    print_error(f"\n發生錯誤：{str(e)}")
finally:
    print("\n按下 Enter 鍵結束遊戲...")
    input()