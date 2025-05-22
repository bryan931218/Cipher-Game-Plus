from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import time

def slow_print(text, delay=0.02):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def print_explanation(text):
    print("\033[93m" + text + "\033[0m")

# 以綠色顯示成功訊息
def print_success(text):
    print("\033[92m" + text + "\033[0m")

def decrypt_password(data: dict):
    try:
        print_explanation("\n===== Start decrypt =====")
        slow_print("解密是將加密的訊息轉換回原始內容的過程。")
            
        key = base64.b64decode(data['key'])
        print_explanation("\n[Step 1] Parse Key（金鑰）")
        slow_print(f"Base64 編碼的金鑰: {data['key']}")
        slow_print(f"解碼後的金鑰 (16進位): {key.hex()}")
        print_explanation("金鑰就像是開鎖的鑰匙，只有正確的金鑰才能解開加密的訊息。")
        
        nonce = base64.b64decode(data['nonce'])
        print_explanation("\n[Step 2] Parse Nonce（隨機數）")
        slow_print(f"Base64 編碼的隨機數: {data['nonce']}")
        slow_print(f"解碼後的隨機數 (16進位): {nonce.hex()}")
        print_explanation("隨機數確保即使使用相同的金鑰和相同的訊息，每次加密的結果也會不同。")
        
        ciphertext = base64.b64decode(data['ciphertext'])
        print_explanation("\n[Step 3] Parse Ciphertext（密文）")
        slow_print(f"Base64 編碼的密文: {data['ciphertext']}")
        slow_print(f"解碼後的密文 (16進位): {ciphertext.hex()}")
        print_explanation("密文是經過加密的訊息，看起來像亂碼，需要用正確的金鑰解密。")

        print_explanation("\n[Step 4] Decrypt with AES-GCM（使用 AES-GCM 解密）")
        print_explanation("AES-GCM 是一種強大的加密算法，能同時提供機密性和完整性保護。")
        slow_print("正在解密中...")
        time.sleep(1)

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        print_success("\n[Step 5] Decrypt Success!（解密成功）")
        slow_print(f"解密結果: {plaintext.decode()}")
        
        return plaintext.decode()
    except Exception as e:
        print("\033[91m" + f"\n解密失敗: {str(e)}" + "\033[0m")
        print_explanation("可能是提供的金鑰、隨機數或密文不正確。")
        return None

# 主程式
print_explanation("這個工具可以幫助你解密第一關的提示，獲取進入第二關的密碼。")

data = {'ciphertext': '', 'key': '', 'nonce': ''}

print("\n請輸入以下資訊:")
ciphertext = input("密文 (ciphertext): ")
data['ciphertext'] = ciphertext

key = input('金鑰 (key): ')
data['key'] = key

nonce = input('隨機數 (nonce): ')
data['nonce'] = nonce

result = decrypt_password(data)

if not(result):
    print("\033[91m" + "\n解密失敗，請檢查輸入是否正確。" + "\033[0m")
os.system("pause")
