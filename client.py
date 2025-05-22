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
                        elif tool == "kms_client.py":
                            print_hint(f"     - 用於連接 KMS 服務，獲取解密金鑰")
                        elif tool == "cert_forge.py":
                            print_hint(f"     - 用於創建和偽造 X.509 憑證鏈")
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

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """使用 AES-GCM 解密數據"""
    try:
        print_subtitle("AES-GCM 解密過程")
        print("\033[1m\033[96m[步驟1]\033[0m 初始化 AES-GCM")
        print("  金鑰長度：", len(key) * 8, "位元")
        print("  Nonce 長度：", len(nonce) * 8, "位元")
        print("  正在初始化...")
        time.sleep(0.3)
        
        aesgcm = AESGCM(key)
        print("  初始化完成！")
        
        print("\033[1m\033[96m[步驟2]\033[0m 解密數據")
        print("  密文長度：", len(ciphertext), "位元組")
        print("  正在解密...")
        time.sleep(0.5)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        result = plaintext.decode()
        print("  解密成功！")
        
        return result
    except Exception as e:
        print_error(f"\n[錯誤] AES-GCM 解密失敗：{str(e)}")
        return None

def run_kms_client():
    """執行 KMS 客戶端工具"""
    print_subtitle("執行 KMS 客戶端工具")
    print_hint("請使用另一個終端視窗執行以下命令：")
    print_tool_info(f"  python tools/kms_client.py")
    print_hint("\n執行後，請提供有效的用戶名和令牌。")
    print_hint("獲取 AES 金鑰後，請記下金鑰的 Base64 值，以便在這裡輸入。")

def run_cert_forge_tool():
    """執行憑證鏈偽造工具"""
    print_subtitle("執行憑證鏈偽造工具")
    print_hint("請使用另一個終端視窗執行以下命令：")
    print_tool_info(f"  python tools/cert_forge.py")
    print_hint("\n執行後，工具將幫助你：")
    print_hint("1. 獲取根CA憑證和私鑰")
    print_hint("2. 創建中繼CA憑證")
    print_hint("3. 創建用戶憑證")
    print_hint("4. 提交完整的憑證鏈給服務器驗證")

# === Game Start ===
clear()
print_title("密碼挑戰：解鎖真相")

slow_print("🔐 歡迎來到《密碼挑戰：解鎖真相》", 0.05)
slow_print("你是一名特工，收到一則神秘訊息，內含加密挑戰與機密資訊。", 0.04)
slow_print("你的任務是解開這個多層加密的訊息，揭露隱藏的真相。", 0.04)

# 顯示工具使用說明
print_hint("\n💡 任務提示：")
print_hint("  在遊戲過程中，你可以使用 tools 資料夾中的工具來協助完成任務。")
print_hint("  這些工具能幫助你解密訊息、分析數據。")

# 顯示可用工具
display_available_tools()

input("\n請按下 Enter 鍵以開始任務...")

# === Client Socket ===
try:
    # 創建套接字
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    clear()
    print_title("任務進行中")
    
    print("正在連接到伺服器...")
    s.connect(("localhost", 12347))
    s.sendall(b"START_GAME")
    print_success("連接成功！")

    # === 第一關：密碼解密 ===
    slow_print("\n📡 正在接收加密任務資料...", 0.03)
    data1 = s.recv(2048)
    plain = json.loads(data1.decode())
    
    print_subtitle("任務提示內容")
    print(json.dumps(plain, indent=2, ensure_ascii=False))
    print_hint("\n這看起來像是一個加密的任務簡報。根據提示，日期似乎是解密的關鍵。")

    s.sendall(b"player recieved the plaintext")
    data2 = s.recv(2048)
    challenge = json.loads(data2.decode())
    slow_print("\n🧩 收到加密的公鑰數據，需要使用正確的密碼解密...\n", 0.03)
    
    while True:
        print_subtitle("第一關：密碼解密")
        print_hint("根據任務提示，密碼似乎是一個特定的日期。")
        print_hint("格式可能是 YYYYMMDD (年月日)，例如 20230101。")
        pwd = input("\n🔑 請輸入密碼以解密公鑰：")
        
        decrypted = decrypt_message(pwd, challenge)
        if decrypted:
            print_success("\n✅ 成功解密！獲得了一個 RSA 公鑰：")
            print("\n" + decrypted)
            print_hint("\n這個公鑰看起來可以用於驗證數位簽章。")
            print_hint("請保存這個公鑰，我們將在下一關使用它。")
            s.sendall(b"OK")
            
            # 保存公鑰到變數，方便下一關使用
            public_key_pem = decrypted
            break
        else:
            print_error("\n❌ 解密失敗，請嘗試不同的日期格式。")

    # === 第二關：簽章驗證 ===
    print_subtitle("第二關：簽章驗證")
    slow_print("\n📨 正在接收簽章與訊息...", 0.03)
    signed_data = s.recv(2048)
    info = json.loads(signed_data.decode())
    
    print_subtitle("收到的訊息")
    print(info["message"])
    print("\n簽章 (Base64)：\033[90m" + info["signature"][:20] + "...\033[0m")

    print("\n🔎 需要驗證這個訊息的真實性...")
    print_hint("💡 提示：使用你在上一步解密獲得的公鑰來驗證簽章。")
    print_hint("這可以確認訊息確實來自擁有對應私鑰的發送者，且未被篡改。")
    print_hint("請輸入訊息簽章的公鑰（PEM 格式）後按 Ctrl+D 或 Ctrl+Z(Windows) 結束輸入：\n")
    
    player_pem = sys.stdin.read()

    if verify_signature(public_key_pem, info["message"], info["signature"]):
        print_success("\n🛡️ 驗證成功！訊息確實來自可信的發送者，且未被篡改。")
        print_hint("\n訊息中提到了一個「混合加密系統」和「KMS服務」，這可能是下一關的線索。")
        
        # === 第三關：混合加密與金鑰管理 ===
        print_title("進入第三關")
        slow_print("\n🔐 恭喜你通過前兩關挑戰！解密線索指向了第三關：混合加密與金鑰管理。", 0.03)
        slow_print("根據解密的訊息，我們需要連接到 KMS (金鑰管理服務) 來獲取解密金鑰。", 0.03)
        slow_print("這是一個典型的混合加密系統：訊息用 AES 加密，而 AES 金鑰則用 RSA 加密並存儲在 KMS 中。", 0.03)
        
        input("\n按下 Enter 鍵連接到 KMS 服務...")
        
        # 關閉舊連接並創建新連接，確保連接不會中斷
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 12347))
        
        # 請求第三關數據
        s.sendall(b"START_LEVEL_3")
        level3_data_raw = s.recv(4096)
        level3_data = json.loads(level3_data_raw.decode())
        
        print_subtitle("第三關：混合加密與金鑰管理")
        print("\n📦 從服務器獲取了加密資料：")
        print(f"  • 加密的 AES 金鑰：{level3_data['encrypted_aes_key'][:20]}...")
        print(f"  • 加密的最終訊息：{level3_data['ciphertext'][:20]}...")
        print(f"  • 使用的 Nonce：{level3_data['nonce'][:20]}...")
        
        print_hint("\n💡 分析：")
        print_hint("  1. 最終訊息使用 AES-GCM 加密，這是一種對稱加密")
        print_hint("  2. AES 金鑰被 RSA 公鑰加密，存儲在 KMS 服務中")
        print_hint("  3. 我們需要從 KMS 獲取解密後的 AES 金鑰")
        print_hint("  4. 然後用這個 AES 金鑰解密最終訊息")
        
        # 提示玩家使用 KMS 客戶端工具
        print_subtitle("連接 KMS 服務")
        print_hint("根據訊息提示，KMS 服務需要 OAuth 2.0 身份驗證。")
        print_hint("訊息中暗示了可能的用戶名和令牌格式。")
        run_kms_client()
        
        print_subtitle("輸入從 KMS 獲取的金鑰")
        print_hint("成功連接 KMS 服務後，你應該獲得了解密後的 AES 金鑰。")
        print_hint("請輸入 KMS 服務提供的 AES 金鑰：")
        
        aes_key_b64 = input("\nAES 金鑰 (Base64 格式): ")
        
        # 從第三關數據中獲取 nonce 和 ciphertext
        nonce_b64 = level3_data["nonce"]
        ciphertext_b64 = level3_data["ciphertext"]
        
        try:
            # 解碼 Base64 數據
            aes_key = base64.b64decode(aes_key_b64)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # 使用 AES 金鑰解密最終訊息
            print_subtitle("解密最終訊息")
            print("正在使用獲取的 AES 金鑰解密最終訊息...")
            animate_progress(1.5)  # 動畫效果
            
            final_message = decrypt_aes_gcm(aes_key, nonce, ciphertext)
            
            if final_message:
                print_title("任務完成")
                print_success("\n🎉 恭喜！你成功解密了最終訊息：")
                print("\n" + final_message)
                
                # 關閉舊連接並創建新連接，確保連接不會中斷
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("localhost", 12347))
                
                # 向服務器驗證解密結果
                print("\n正在向總部確認解密結果...")
                
                # 修正：先發送命令，然後等待服務器回應，再發送解密結果
                s.sendall(b"VERIFY_FINAL_SOLUTION")
                
                # 等待一小段時間，確保服務器已準備好接收解密結果
                time.sleep(0.5)
                
                # 發送解密結果
                solution_data = json.dumps({"message": final_message})
                s.sendall(solution_data.encode())
                
                # 接收服務器回應
                verification_response = s.recv(1024)
                verification_result = json.loads(verification_response.decode())
                
                if verification_result["status"] == "success":
                    print_success("\n✅ " + verification_result["message"])
                    print_success("\n你已成功完成所有挑戰，解鎖了隱藏的真相！")
                    print_hint("\n這次任務展示了現代密碼學的三個核心概念：")
                    print_hint("1. 對稱加密 (AES-GCM) - 高效加密大量數據")
                    print_hint("2. 非對稱加密與數位簽章 (RSA) - 安全的身份驗證")
                    print_hint("3. 混合加密與金鑰管理 - 結合兩者優勢的實用系統")
                    
                    # 詢問是否進入第四關
                    print_subtitle("進階挑戰")
                    print_hint("恭喜你完成了基本挑戰！你想要挑戰更高難度的第四關嗎？")
                    print_hint("第四關將測試你對 PKI (公鑰基礎設施) 和憑證鏈的理解。")
                    
                    next_level = input("\n是否進入第四關？(y/n): ")
                    
                    if next_level.lower() == 'y':
                        # === 第四關：憑證鏈偽造 ===
                        print_title("第四關：憑證鏈偽造")
                        slow_print("\n🔒 歡迎來到最終挑戰：PKI 與憑證鏈偽造", 0.03)
                        slow_print("在這一關，你將需要理解 X.509 憑證鏈的工作原理，並創建一個有效的憑證鏈。", 0.03)
                        slow_print("這是現代 TLS/SSL 安全通訊的基礎技術。", 0.03)
                        
                        print_hint("\n💡 任務說明：")
                        print_hint("1. 你將獲得一個根 CA 憑證和私鑰")
                        print_hint("2. 你需要使用根 CA 私鑰創建一個中繼 CA 憑證")
                        print_hint("3. 再使用中繼 CA 私鑰創建一個用戶憑證")
                        print_hint("4. 最後將完整的憑證鏈提交給服務器驗證")
                        
                        # 提示玩家使用憑證鏈偽造工具
                        print_subtitle("憑證鏈偽造工具")
                        print_hint("我們提供了一個工具來幫助你完成這個任務。")
                        run_cert_forge_tool()
                        
                        print_subtitle("完成第四關")
                        print_hint("使用 cert_forge.py 工具完成憑證鏈創建後，你將獲得最終獎勵。")
                        print_hint("這個工具會幫助你理解 PKI 的核心概念：信任鏈和憑證授權。")
                        
                        input("\n按下 Enter 鍵結束任務...")
                    else:
                        print_success("\n感謝你完成基本挑戰！你已經掌握了現代密碼學的核心概念。")
                else:
                    print_error("\n❌ " + verification_result["message"])
            else:
                print_error("\n❌ 解密最終訊息失敗")
                print_hint("請確認你輸入的 AES 金鑰是否正確。")
        except Exception as e:
            print_error(f"\n解密過程發生錯誤：{str(e)}")
            print_hint("請確認你輸入的 AES 金鑰格式正確，並重新嘗試。")
    else:
        print_title("任務失敗")
        print_error("\n⚠️ 驗證失敗，訊息可能被竄改或不是來自可信的發送者。")
        print_hint("\n💡 提示：確保你使用的是完整的公鑰，包括開頭的 '-----BEGIN PUBLIC KEY-----' 和結尾的 '-----END PUBLIC KEY-----'。")

    print("\n🔚 任務結束，感謝你的參與。")
    
except ConnectionRefusedError:
    print_error("\n無法連接到伺服器，請確認伺服器已啟動。")
except Exception as e:
    print_error(f"\n發生錯誤：{str(e)}")
finally:
    # 確保在程式結束時關閉連接
    try:
        s.close()
    except:
        pass
    print("\n按下 Enter 鍵結束遊戲...")
    input()