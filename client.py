import socket
import json
import base64
import sys
import time
import os
import shutil
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# === 評分系統變數 ===
player_score = 100  # 初始分數為100分
score_deductions = []  # 用於記錄扣分原因

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

def clean_cert_directory():
    cert_dir = "tools/certs"
    if os.path.exists(cert_dir):
        for file in os.listdir(cert_dir):
            file_path = os.path.join(cert_dir, file)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"無法刪除文件 {file_path}: {e}")
    else:
        os.makedirs(cert_dir)

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
                        elif tool == "cert_creator.py":
                            print_hint(f"     - 用於創建和管理 X.509 憑證")
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
    global player_score, score_deductions
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
        # 第一關密碼解密失敗時扣分
        player_score -= 5
        score_deductions.append("第一關密碼解密失敗 (-5)")
        return None

def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    global player_score, score_deductions
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
        # 第二關簽章驗證失敗時扣分
        player_score -= 5
        score_deductions.append("第二關簽章驗證失敗 (-5)")
        return False
    except Exception as e:
        print_error(f"\n[錯誤] 驗證過程發生錯誤：{str(e)}")
        # 其他錯誤也扣分
        player_score -= 5
        score_deductions.append("第二關驗證過程發生錯誤 (-5)")
        return False

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """使用 AES-GCM 解密數據"""
    global player_score, score_deductions
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
        # 第三關 AES 金鑰解密失敗時扣分
        player_score -= 5
        score_deductions.append("第三關 AES 解密失敗 (-5)")
        return None

def run_kms_client():
    """執行 KMS 客戶端工具"""
    print_subtitle("執行 KMS 客戶端工具")
    print_hint("請使用kms_client.py並提供有效的用戶名和token來獲取AES金鑰：")
    print_hint("獲取金鑰後，請記下金鑰的 Base64 值，以便在這裡輸入。")

def run_cert_creator():
    """執行憑證創建工具"""
    print_subtitle("執行憑證創建工具")
    print_hint("請使用cert_creator.py來創建憑證鏈：")
    print_hint("完成後，工具會在 tools/certs 資料夾中生成三個 PEM 文件：根 CA、中繼 CA 和用戶憑證。")

def ensure_cert_directory():
    cert_dir = "tools/certs"
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    return cert_dir

# === Game Start ===
clear()
clean_cert_directory()
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
    print_hint("\n這看起來像是一個加密的任務簡報，密碼似乎是一個特定的日期。。")

    s.sendall(b"player recieved the plaintext")
    data2 = s.recv(2048)
    challenge = json.loads(data2.decode())
    slow_print("\n🧩 收到加密的公鑰數據，需要使用正確的密碼解密...\n", 0.03)
    
    while True:
        print_subtitle("第一關：密碼解密")
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
            print_error("\n❌ 解密失敗，請嘗試不同的密碼。")

    # === 第二關：簽章驗證 ===
    print_subtitle("第二關：簽章驗證")
    slow_print("\n📨 正在接收簽章與訊息...", 0.03)
    signed_data = s.recv(2048)
    info = json.loads(signed_data.decode())
    
    while True:
        print_subtitle("收到的訊息")
        print(info["message"])
        print("\n簽章 (Base64)：\033[90m" + info["signature"][:20] + "...\033[0m")

        print("\n🔎 需要驗證這個訊息的真實性...")
        print_hint("💡 提示：使用你在上一步解密獲得的公鑰來驗證簽章。")
        print_hint("這可以確認訊息確實來自擁有對應私鑰的發送者，且未被篡改。")
        print_hint("請輸入訊息簽章的公鑰（PEM 格式）後按 Ctrl+D 或 Ctrl+Z(Windows) 結束輸入：\n")
        
        player_pem = sys.stdin.read()

        if verify_signature(player_pem, info["message"], info["signature"]):
            print_success("\n🛡️ 驗證成功！訊息確實來自可信的發送者，且未被篡改。")
            print_hint("\n訊息中提到了一個「混合加密系統」和「KMS服務」，這可能是下一關的線索。")
            break 
        else:
            print_error("\n⚠️ 驗證失敗，訊息可能被竄改或不是來自可信的發送者。")
            print_hint("\n💡 提示：確保你使用的是完整的公鑰，包括開頭的 '-----BEGIN PUBLIC KEY-----' 和結尾的 '-----END PUBLIC KEY-----'。")
            os.system("pause")

    # 驗證成功後繼續進入第三關
    print_title("進入第三關")
    slow_print("\n🔐 恭喜你通過前兩關挑戰！解密線索指向了第三關：混合加密與金鑰管理。", 0.03)
    slow_print("根據解密的訊息，我們需要連接到 KMS (金鑰管理服務) 來獲取解密金鑰。", 0.03)
    slow_print("這是一個典型的混合加密系統：訊息用 AES 加密，而 AES 金鑰則用 RSA 加密並存儲在 KMS 中。", 0.03)
    
    input("\n按下 Enter 鍵連接到 KMS 服務...")
    
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
    
    # 從第三關數據中獲取 nonce 和 ciphertext
    nonce_b64 = level3_data["nonce"]
    ciphertext_b64 = level3_data["ciphertext"]
    
    # 添加循環，允許多次嘗試輸入AES金鑰
    while True:
        print_subtitle("輸入從 KMS 獲取的金鑰")
        print_hint("成功連接 KMS 服務後，你應該獲得了解密後的 AES 金鑰。")
        print_hint("請輸入 KMS 服務提供的 AES 金鑰：")
        
        aes_key_b64 = input("\nAES 金鑰 (Base64 格式): ")
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
                print_success("\n✅ 成功解密訊息！")
                print("\n" + final_message)
                
                # 關閉舊連接並創建新連接，確保連接不會中斷
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("localhost", 12347))
                
                # 向服務器驗證解密結果
                print("\n正在向總部確認解密結果...")
                
                # 修改這裡：先發送命令，然後等待服務器準備好接收數據的確認
                s.sendall(b"VERIFY_FINAL_SOLUTION")
                
                # 在發送 JSON 數據之前添加一個短暫的延遲
                time.sleep(0.5)
                
                # 發送解密後的訊息
                solution_data = json.dumps({
                    "message": final_message
                }).encode()
                s.sendall(solution_data)
                
                try:
                    # 接收服務器回應
                    verification_response = s.recv(1024).decode()
                    verification_result = json.loads(verification_response)
                    
                    if verification_result["status"] == "success":
                        print_success("\n✅ " + verification_result["message"])
                        
                        # === 第四關：憑證鏈偽造 ===
                        print_title("進入最終關卡")
                        slow_print("\n🔒 恭喜你解開了第三關的謎題！但這還不是最終挑戰...", 0.03)
                        slow_print("根據解密的訊息，最後一道防線是 PKI 系統 - 公鑰基礎設施。", 0.03)
                        slow_print("你需要偽造一條完整的憑證鏈，以獲取最終的機密資料。", 0.03)
                        
                        print_subtitle("第四關：憑證鏈偽造")
                        print_hint("\n這是最後的挑戰，需要你理解 X.509 憑證和信任鏈的概念。")
                        print_hint("在 PKI 系統中，信任是通過憑證鏈建立的：")
                        print_hint("  根 CA (最高信任) → 中繼 CA → 使用者憑證")
                        
                        input("\n按下 Enter 鍵開始最終挑戰...")
                        
                        while True:  # 添加循環，允許多次嘗試
                            try:
                                # 關閉舊連接並創建新連接
                                s.close()
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.connect(("localhost", 12347))
                                
                                # 請求第四關數據
                                s.sendall(b"START_LEVEL_4")
                                level4_data_raw = s.recv(16384)  # 增大緩衝區以接收較大的憑證數據
                                level4_data = json.loads(level4_data_raw.decode())
                                
                                print_subtitle("收到的憑證挑戰")
                                print("\n📜 從服務器獲取了根 CA 憑證和私鑰：")
                                print_hint("\n你的任務是：")
                                print_hint("1. 使用提供的根 CA 私鑰創建一個中繼 CA 憑證")
                                print_hint("2. 使用中繼 CA 創建一個用戶憑證")
                                print_hint("3. 提交完整的憑證鏈給服務器驗證")
                                
                                # 確保 tools/certs 目錄存在
                                cert_dir = ensure_cert_directory()
                                
                                # 保存根 CA 憑證和私鑰到 tools/certs 目錄
                                with open(os.path.join(cert_dir, "root_ca.pem"), "w") as f:
                                    f.write(level4_data["root_cert"])
                                with open(os.path.join(cert_dir, "root_private_key.pem"), "w") as f:
                                    f.write(level4_data["root_private_key"])
                                
                                print_success("\n✅ 已將根 CA 憑證和私鑰保存到 tools/certs 目錄")
                                print_hint("現在你可以使用憑證創建工具來完成這個挑戰")
                                
                                run_cert_creator()
                                
                                print_subtitle("提交憑證鏈")
                                print_hint("完成憑證鏈創建後，請確認你有以下三個文件：")
                                print_hint("1. tools/certs/root_ca.pem - 根 CA 憑證")
                                print_hint("2. tools/certs/intermediate_ca.pem - 中繼 CA 憑證")
                                print_hint("3. tools/certs/user_cert.pem - 用戶憑證")
                                print_hint("或者在當前目錄中的相同文件")
                                
                                ready = input("\n確認要提交憑證請按Enter")
                                
                                try:
                                    # 嘗試從 tools/certs 目錄讀取
                                    cert_paths = {
                                        "root_ca": os.path.join(cert_dir, "root_ca.pem"),
                                        "intermediate_ca": os.path.join(cert_dir, "intermediate_ca.pem"),
                                        "user_cert": os.path.join(cert_dir, "user_cert.pem")
                                    }
                                    
                                    # 如果 tools/certs 目錄中的文件不存在，則嘗試從當前目錄讀取
                                    if not os.path.exists(cert_paths["intermediate_ca"]):
                                        cert_paths["intermediate_ca"] = "intermediate_ca.pem"
                                    if not os.path.exists(cert_paths["user_cert"]):
                                        cert_paths["user_cert"] = "user_cert.pem"
                                    
                                    # 讀取憑證文件
                                    with open(cert_paths["root_ca"], "r") as f:
                                        root_cert = f.read()
                                    with open(cert_paths["intermediate_ca"], "r") as f:
                                        intermediate_cert = f.read()
                                    with open(cert_paths["user_cert"], "r") as f:
                                        user_cert = f.read()
                                    
                                    # 構建憑證鏈數據
                                    cert_chain = {
                                        "root_cert": root_cert,
                                        "intermediate_cert": intermediate_cert,
                                        "user_cert": user_cert
                                    }
                                    
                                    # 發送憑證鏈到服務器
                                    print("正在提交憑證鏈到服務器...")

                                    try:
                                        s.close()
                                    except:
                                        pass

                                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    s.connect(("localhost", 12347))

                                    s.sendall(b"VERIFY_CERT_CHAIN")

                                    
                                    # 添加短暫延遲，確保服務器準備好接收數據
                                    time.sleep(0.5)
                                    
                                    s.sendall(json.dumps(cert_chain).encode())
                                    
                                    # 接收驗證結果
                                    verification_result = json.loads(s.recv(4096).decode())
                                    if verification_result["status"] == "success":
                                        print_title("任務完成")
                                        print_success("\n🎉 恭喜！你成功偽造了有效的憑證鏈並通過了最終挑戰！")
                                        print_success("\n" + verification_result["message"])
                                        if "final_secret" in verification_result:
                                            print_subtitle("最終機密")
                                            print("\n" + verification_result["final_secret"])
                                            print_hint("\n這次任務展示了現代密碼學和網路安全的四個重要概念：")
                                            print_hint("1. 對稱加密 (AES-GCM) - 高效加密大量數據")
                                            print_hint("2. 非對稱加密與數位簽章 (RSA) - 安全的身份驗證")
                                            print_hint("3. 混合加密與金鑰管理 - 結合兩者優勢的實用系統")
                                            print_hint("4. PKI 與憑證鏈 - 建立網路信任的基礎")
                                        break 
                                    else:
                                        print_error("\n❌ " + verification_result["message"])
                                        print_hint("請檢查你的憑證鏈是否符合要求。")
                                        # 第四關憑證鏈驗證失敗時扣分
                                        player_score -= 5
                                        score_deductions.append("第四關憑證鏈驗證失敗 (-5)")
                                        os.system("pause")
                                except FileNotFoundError as e:
                                    print_error(f"\n❌ 找不到必要的憑證文件：{str(e)}")
                                    print_hint("請確保你已經使用憑證創建工具生成了所有必要的憑證文件。")
                                    print_hint(f"工具應該在 tools/certs 目錄或當前目錄中生成這些文件。")
                                    # 第四關憑證文件找不到時扣分
                                    player_score -= 5
                                    score_deductions.append("第四關找不到必要的憑證文件 (-5)")
                                    os.system("pause")
                                except Exception as e:
                                    print_error(f"\n❌ 提交憑證鏈時發生錯誤：{str(e)}")
                                    # 其他錯誤也扣分
                                    player_score -= 3
                                    score_deductions.append("第四關提交憑證鏈時發生錯誤 (-3)")
                                    os.system("pause")
                            except ConnectionError as e:
                                print_error(f"\n❌ 連接服務器時發生錯誤：{str(e)}")
                                # 連接錯誤扣分
                                player_score -= 2
                                score_deductions.append("連接服務器時發生錯誤 (-2)")
                                os.system("pause")
                            except Exception as e:
                                print_error(f"\n❌ 發生未知錯誤：{str(e)}")
                                # 未知錯誤扣分
                                player_score -= 2
                                score_deductions.append("發生未知錯誤 (-2)")
                                os.system("pause")
                        # 成功完成第四關，跳出第三關的循環
                        break
                    else:
                        print_error("\n❌ " + verification_result["message"])
                        print_hint("請確認你輸入的解密訊息是否正確，並重新嘗試。")
                        # 第三關驗證解密結果失敗時扣分
                        player_score -= 5
                        score_deductions.append("第三關解密訊息驗證失敗 (-5)")
                        # 驗證失敗，但不跳出循環，讓用戶可以重新嘗試
                except json.JSONDecodeError:
                    print_error("\n❌ 無法解析服務器回應，可能是通信協議問題。")
                    print_hint("嘗試重新連接服務器...")
                    
                    # 嘗試直接進入第四關
                    print_subtitle("嘗試直接進入第四關")
                    print_hint("由於第三關驗證出現問題，我們將直接嘗試進入第四關...")
                    
                    # 關閉舊連接並創建新連接
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(("localhost", 12347))
                    
                    # 請求第四關數據
                    s.sendall(b"START_LEVEL_4")
                    try:
                        level4_data_raw = s.recv(16384) 
                        level4_data = json.loads(level4_data_raw.decode())
                        
                        cert_dir = ensure_cert_directory()
                        
                        with open(os.path.join(cert_dir, "root_ca.pem"), "w") as f:
                            f.write(level4_data["root_cert"])
                        with open(os.path.join(cert_dir, "root_private_key.pem"), "w") as f:
                            f.write(level4_data["root_private_key"])
                        
                        
                        print_subtitle("收到的憑證挑戰")
                        print("\n📜 從服務器獲取了根 CA 憑證和私鑰：")
                        print_hint("\n你的任務是：")
                        print_hint("1. 使用提供的根 CA 私鑰創建一個中繼 CA 憑證")
                        print_hint("2. 使用中繼 CA 創建一個用戶憑證")
                        print_hint("3. 提交完整的憑證鏈給服務器驗證")
                        # 成功進入第四關，跳出第三關循環
                        break

                    except Exception as e:
                        print_error(f"\n❌ 無法進入第四關：{str(e)}")
                        print_hint("請重新嘗試輸入正確的 AES 金鑰。")
                        # 不跳出循環，讓用戶重新嘗試
            else:
                print_error("\n❌ 解密最終訊息失敗")
                print_hint("請確認你輸入的 AES 金鑰是否正確，並重新嘗試。")
                # 解密失敗，但不跳出循環，讓用戶可以重新嘗試
        except Exception as e:
            print_error(f"\n解密過程發生錯誤：{str(e)}")
            print_hint("請確認你輸入的 AES 金鑰格式正確，並重新嘗試。")
            # 發生錯誤，但不跳出循環，讓用戶可以重新嘗試

    # 在遊戲結束時顯示最終分數
    print_title("最終評分")
    print(f"你的最終分數是: {player_score}/100")

    if len(score_deductions) > 0:
        print_subtitle("扣分項目:")
        for deduction in score_deductions:
            print_error(f"• {deduction}")

    if player_score >= 90:
        print_success("\n🏆 傑出的表現！你是密碼學專家！")
    elif player_score >= 80:
        print_success("\n👍 很好的表現！你對密碼學有很好的理解。")
    elif player_score >= 70:
        print_hint("\n👌 不錯的表現，但還有提升空間。")
    else:
        print_hint("\n🔄 建議再多練習密碼學的基本概念。")

    print("\n🔚 任務結束，感謝你的參與。")
    
except ConnectionRefusedError:
    print_error("\n無法連接到伺服器，請確認伺服器已啟動。")
    os.system("pause")

except Exception as e:
    print_error(f"\n發生錯誤：{str(e)}")
    os.system("pause")

finally:
    try:
        s.close()
    except:
        pass

    for temp_file in ["root_ca.pem", "root_private_key.pem"]:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
    print("\n按下 Enter 鍵結束遊戲...")
    input()