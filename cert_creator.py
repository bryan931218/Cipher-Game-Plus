#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# === 顯示效果函數 ===
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

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

def print_info(text):
    # 淺藍色文字
    print("\033[96m" + text + "\033[0m")

def print_hint(text):
    # 黃色文字
    print("\033[93m" + text + "\033[0m")

def print_step(step_num, text):
    # 藍色粗體步驟號 + 文字
    print(f"\n\033[1m\033[94m[步驟 {step_num}]\033[0m {text}")

def print_progress_bar(percent, width=40):
    filled_width = int(width * percent / 100)
    bar = "█" * filled_width + "░" * (width - filled_width)
    print(f"\r\033[96m[{bar}] {percent}%\033[0m", end='', flush=True)

def animate_progress(duration=1.0):
    for i in range(101):
        print_progress_bar(i)
        time.sleep(duration/100)
    print()

def load_root_ca():
    """載入根 CA 憑證和私鑰"""
    try:
        # 檢查文件是否存在
        if not os.path.exists("root_ca.pem") or not os.path.exists("root_private_key.pem"):
            print_error("找不到根 CA 憑證或私鑰文件！")
            print_hint("請確保 'root_ca.pem' 和 'root_private_key.pem' 文件存在於當前目錄。")
            return None, None
        
        # 載入根 CA 憑證
        with open("root_ca.pem", "rb") as f:
            root_cert_data = f.read()
            root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())
        
        # 載入根 CA 私鑰
        with open("root_private_key.pem", "rb") as f:
            private_key_data = f.read()
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
        
        return root_cert, private_key
    except Exception as e:
        print_error(f"載入根 CA 時發生錯誤：{str(e)}")
        return None, None

def create_intermediate_ca(root_cert, root_private_key):
    """創建中繼 CA 憑證"""
    try:
        print_step(1, "生成中繼 CA 私鑰")
        print_info("  正在生成 2048 位元 RSA 私鑰...")
        time.sleep(0.5)
        
        # 生成中繼 CA 私鑰
        intermediate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        print_success("  私鑰生成成功！")
        
        print_step(2, "設定中繼 CA 憑證資訊")
        print_info("  請輸入中繼 CA 的基本資訊：")
        
        country = input("  國家代碼 (例如：TW): ").strip() or "TW"
        state = input("  州/省 (例如：Taiwan): ").strip() or "Taiwan"
        locality = input("  城市 (例如：Taipei): ").strip() or "Taipei"
        organization = input("  組織名稱 (例如：Cyber Security Inc): ").strip() or "Cyber Security Inc"
        common_name = input("  通用名稱 (例如：Intermediate CA): ").strip() or "Intermediate CA"
        
        # 設定中繼 CA 的主體資訊
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        print_step(3, "設定憑證有效期")
        print_info("  憑證有效期預設為 5 年")
        
        # 設定憑證有效期
        now = datetime.datetime.utcnow()
        validity_years = 5
        
        print_step(4, "創建中繼 CA 憑證")
        print_info("  正在使用根 CA 簽發中繼 CA 憑證...")
        time.sleep(0.8)
        
        # 創建憑證建構器
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            intermediate_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=validity_years*365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
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
        )
        
        # 使用根 CA 私鑰簽署中繼 CA 憑證
        intermediate_cert = builder.sign(
            private_key=root_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        print_success("  中繼 CA 憑證創建成功！")
        
        # 保存中繼 CA 憑證和私鑰
        with open("intermediate_ca.pem", "wb") as f:
            f.write(intermediate_cert.public_bytes(encoding=serialization.Encoding.PEM))
        
        with open("intermediate_private_key.pem", "wb") as f:
            f.write(intermediate_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print_success("  已保存中繼 CA 憑證到 'intermediate_ca.pem'")
        print_success("  已保存中繼 CA 私鑰到 'intermediate_private_key.pem'")
        
        return intermediate_cert, intermediate_key
    except Exception as e:
        print_error(f"創建中繼 CA 時發生錯誤：{str(e)}")
        return None, None

def create_user_certificate(intermediate_cert, intermediate_key):
    """創建用戶憑證"""
    try:
        print_step(1, "生成用戶私鑰")
        print_info("  正在生成 2048 位元 RSA 私鑰...")
        time.sleep(0.5)
        
        # 生成用戶私鑰
        user_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        print_success("  私鑰生成成功！")
        
        print_step(2, "設定用戶憑證資訊")
        print_info("  請輸入用戶憑證的基本資訊：")
        
        country = input("  國家代碼 (例如：TW): ").strip() or "TW"
        state = input("  州/省 (例如：Taiwan): ").strip() or "Taiwan"
        locality = input("  城市 (例如：Taipei): ").strip() or "Taipei"
        organization = input("  組織名稱 (例如：Secret Agent): ").strip() or "Secret Agent"
        common_name = input("  通用名稱 (例如：Agent 007): ").strip() or "Agent 007"
        
        # 設定用戶憑證的主體資訊
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        print_step(3, "設定憑證有效期")
        print_info("  憑證有效期預設為 1 年")
        
        # 設定憑證有效期
        now = datetime.datetime.utcnow()
        validity_years = 1
        
        print_step(4, "創建用戶憑證")
        print_info("  正在使用中繼 CA 簽發用戶憑證...")
        time.sleep(0.8)
        
        # 創建憑證建構器
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            intermediate_cert.subject
        ).public_key(
            user_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=validity_years*365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # 使用中繼 CA 私鑰簽署用戶憑證
        user_cert = builder.sign(
            private_key=intermediate_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        print_success("  用戶憑證創建成功！")
        
        # 保存用戶憑證和私鑰
        with open("user_cert.pem", "wb") as f:
            f.write(user_cert.public_bytes(encoding=serialization.Encoding.PEM))
        
        with open("user_private_key.pem", "wb") as f:
            f.write(user_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print_success("  已保存用戶憑證到 'user_cert.pem'")
        print_success("  已保存用戶私鑰到 'user_private_key.pem'")
        
        return user_cert, user_key
    except Exception as e:
        print_error(f"創建用戶憑證時發生錯誤：{str(e)}")
        return None, None

def verify_certificate_chain():
    """驗證憑證鏈"""
    try:
        print_step(1, "載入憑證鏈")
        print_info("  正在載入根 CA 憑證...")
        with open("root_ca.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        print_info("  正在載入中繼 CA 憑證...")
        with open("intermediate_ca.pem", "rb") as f:
            intermediate_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        print_info("  正在載入用戶憑證...")
        with open("user_cert.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        print_step(2, "驗證中繼 CA 是否由根 CA 簽發")
        print_info("  正在驗證中繼 CA 的簽章...")
        time.sleep(0.8)
        
        # 驗證中繼 CA 是否由根 CA 簽發
        root_public_key = root_cert.public_key()
        try:
            root_public_key.verify(
                intermediate_cert.signature,
                intermediate_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                intermediate_cert.signature_hash_algorithm,
            )
            print_success("  中繼 CA 簽章驗證成功！")
        except Exception as e:
            print_error(f"  中繼 CA 簽章驗證失敗：{str(e)}")
            return False
        
        print_step(3, "驗證用戶憑證是否由中繼 CA 簽發")
        print_info("  正在驗證用戶憑證的簽章...")
        time.sleep(0.8)
        
        # 驗證用戶憑證是否由中繼 CA 簽發
        intermediate_public_key = intermediate_cert.public_key()
        try:
            intermediate_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm,
            )
            print_success("  用戶憑證簽章驗證成功！")
        except Exception as e:
            print_error(f"  用戶憑證簽章驗證失敗：{str(e)}")
            return False
        
        print_step(4, "檢查憑證有效期")
        now = datetime.datetime.utcnow()
        
        # 檢查根 CA 有效期
        if now < root_cert.not_valid_before or now > root_cert.not_valid_after:
            print_error("  根 CA 憑證已過期或尚未生效")
            return False
        
        # 檢查中繼 CA 有效期
        if now < intermediate_cert.not_valid_before or now > intermediate_cert.not_valid_after:
            print_error("  中繼 CA 憑證已過期或尚未生效")
            return False
        
        # 檢查用戶憑證有效期
        if now < user_cert.not_valid_before or now > user_cert.not_valid_after:
            print_error("  用戶憑證已過期或尚未生效")
            return False
        
        print_success("  所有憑證的有效期檢查通過！")
        
        print_step(5, "檢查憑證用途")
        
        # 檢查中繼 CA 是否有 CA 權限
        for extension in intermediate_cert.extensions:
            if isinstance(extension.value, x509.BasicConstraints):
                if not extension.value.ca:
                    print_error("  中繼 CA 憑證沒有 CA 權限")
                    return False
        
        # 檢查用戶憑證是否沒有 CA 權限
        for extension in user_cert.extensions:
            if isinstance(extension.value, x509.BasicConstraints):
                if extension.value.ca:
                    print_error("  用戶憑證不應該有 CA 權限")
                    return False
        
        print_success("  憑證用途檢查通過！")
        
        print_success("\n✅ 憑證鏈驗證成功！你已經成功構建了一個有效的憑證鏈。")
        return True
    except FileNotFoundError as e:
        print_error(f"找不到必要的憑證文件：{str(e)}")
        return False
    except Exception as e:
        print_error(f"驗證憑證鏈時發生錯誤：{str(e)}")
        return False

def show_main_menu():
    """顯示主選單"""
    clear()
    print_title("X.509 憑證創建工具")
    print("這個工具可以幫助你創建和管理 X.509 憑證鏈。")
    print("用於第四關：憑證鏈偽造挑戰。")
    
    print_subtitle("選項")
    print("1. 創建中繼 CA 憑證")
    print("2. 創建用戶憑證")
    print("3. 驗證憑證鏈")
    print("4. 顯示憑證資訊")
    print("5. 退出")
    
    choice = input("\n請選擇操作 (1-5): ")
    return choice

def show_certificate_info():
    """顯示憑證資訊"""
    clear()
    print_title("憑證資訊")
    
    print_subtitle("可用憑證")
    cert_files = []
    if os.path.exists("root_ca.pem"):
        cert_files.append(("root_ca.pem", "根 CA 憑證"))
    if os.path.exists("intermediate_ca.pem"):
        cert_files.append(("intermediate_ca.pem", "中繼 CA 憑證"))
    if os.path.exists("user_cert.pem"):
        cert_files.append(("user_cert.pem", "用戶憑證"))
    
    if not cert_files:
        print_error("找不到任何憑證文件！")
        input("\n按下 Enter 返回主選單...")
        return
    
    for i, (file, desc) in enumerate(cert_files, 1):
        print(f"{i}. {file} - {desc}")
    
    try:
        choice = int(input("\n請選擇要查看的憑證 (1-{0}): ".format(len(cert_files))))
        if choice < 1 or choice > len(cert_files):
            print_error("無效的選擇！")
            input("\n按下 Enter 返回主選單...")
            return
        
        file_path = cert_files[choice-1][0]
        
        with open(file_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        print_subtitle(f"{file_path} 的詳細資訊")
        
        # 顯示主體資訊
        print_info("主體資訊:")
        for attr in cert.subject:
            print(f"  {attr.oid._name}: {attr.value}")
        
        # 顯示發行者資訊
        print_info("\n發行者資訊:")
        for attr in cert.issuer:
            print(f"  {attr.oid._name}: {attr.value}")
        
        # 顯示有效期
        print_info("\n有效期:")
        print(f"  開始時間: {cert.not_valid_before}")
        print(f"  結束時間: {cert.not_valid_after}")
        
        # 顯示序號
        print_info("\n序號:")
        print(f"  {cert.serial_number}")
        
        # 顯示簽章演算法
        print_info("\n簽章演算法:")
        print(f"  {cert.signature_algorithm_oid._name}")
        
        # 顯示擴展
        print_info("\n擴展:")
        for extension in cert.extensions:
            print(f"  {extension.oid._name}:")
            if isinstance(extension.value, x509.BasicConstraints):
                print(f"    CA: {extension.value.ca}")
                if extension.value.path_length is not None:
                    print(f"    Path Length: {extension.value.path_length}")
            elif isinstance(extension.value, x509.KeyUsage):
                print(f"    Digital Signature: {extension.value.digital_signature}")
                print(f"    Content Commitment: {extension.value.content_commitment}")
                print(f"    Key Encipherment: {extension.value.key_encipherment}")
                print(f"    Data Encipherment: {extension.value.data_encipherment}")
                print(f"    Key Agreement: {extension.value.key_agreement}")
                print(f"    Key Cert Sign: {extension.value.key_cert_sign}")
                print(f"    CRL Sign: {extension.value.crl_sign}")
            else:
                print(f"    {extension.value}")
    except Exception as e:
        print_error(f"顯示憑證資訊時發生錯誤：{str(e)}")
    
    input("\n按下 Enter 返回主選單...")

def main():
    """主程式"""
    while True:
        choice = show_main_menu()
        
        if choice == "1":
            clear()
            print_title("創建中繼 CA 憑證")
            
            # 載入根 CA 憑證和私鑰
            print_info("正在載入根 CA 憑證和私鑰...")
            root_cert, root_private_key = load_root_ca()
            
            if root_cert and root_private_key:
                print_success("根 CA 憑證和私鑰載入成功！")
                
                # 創建中繼 CA 憑證
                intermediate_cert, intermediate_key = create_intermediate_ca(root_cert, root_private_key)
                
                if intermediate_cert and intermediate_key:
                    print_success("\n✅ 中繼 CA 憑證創建成功！")
                    print_hint("\n接下來，你可以使用這個中繼 CA 來創建用戶憑證。")
            
            input("\n按下 Enter 返回主選單...")
        
        elif choice == "2":
            clear()
            print_title("創建用戶憑證")
            
            # 檢查中繼 CA 憑證和私鑰是否存在
            if not os.path.exists("intermediate_ca.pem") or not os.path.exists("intermediate_private_key.pem"):
                print_error("找不到中繼 CA 憑證或私鑰！")
                print_hint("請先創建中繼 CA 憑證。")
                input("\n按下 Enter 返回主選單...")
                continue
            
            # 載入中繼 CA 憑證和私鑰
            print_info("正在載入中繼 CA 憑證和私鑰...")
            try:
                with open("intermediate_ca.pem", "rb") as f:
                    intermediate_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                with open("intermediate_private_key.pem", "rb") as f:
                    intermediate_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                
                print_success("中繼 CA 憑證和私鑰載入成功！")
                
                # 創建用戶憑證
                user_cert, user_key = create_user_certificate(intermediate_cert, intermediate_key)
                
                if user_cert and user_key:
                    print_success("\n✅ 用戶憑證創建成功！")
                    print_hint("\n現在你已經構建了完整的憑證鏈：")
                    print_hint("  根 CA → 中繼 CA → 用戶憑證")
                    print_hint("\n你可以使用「驗證憑證鏈」選項來確認憑證鏈的有效性。")
            except Exception as e:
                print_error(f"載入中繼 CA 時發生錯誤：{str(e)}")
            
            input("\n按下 Enter 返回主選單...")
        
        elif choice == "3":
            clear()
            print_title("驗證憑證鏈")
            
            # 驗證憑證鏈
            verify_certificate_chain()
            
            input("\n按下 Enter 返回主選單...")
        
        elif choice == "4":
            show_certificate_info()
        
        elif choice == "5":
            print("\n感謝使用 X.509 憑證創建工具！")
            break
        
        else:
            print_error("\n無效的選擇，請重新輸入！")
            time.sleep(1)

if __name__ == "__main__":
    main()