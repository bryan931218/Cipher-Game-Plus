from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import datetime
import socket
import json
import base64
import os
import time

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_title(text):
    print("\n\033[104m\033[97m " + text + " \033[0m\n")

def print_subtitle(text):
    print(f"\n\033[93m\033[4m{text}\033[0m")

def print_success(text):
    print("\033[92m" + text + "\033[0m")

def print_error(text):
    print("\033[91m" + text + "\033[0m")

def print_info(text):
    print("\033[96m" + text + "\033[0m")

def print_warning(text):
    print("\033[93m" + text + "\033[0m")

def slow_print(text, delay=0.02):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def load_pem_certificate(cert_pem):
    """從PEM格式載入憑證"""
    return x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

def load_pem_private_key(key_pem):
    """從PEM格式載入私鑰"""
    return serialization.load_pem_private_key(
        key_pem.encode(),
        password=None,
        backend=default_backend()
    )

def create_intermediate_ca(root_cert_pem, root_key_pem):
    """創建中繼CA憑證"""
    # 載入根CA憑證和私鑰
    root_cert = load_pem_certificate(root_cert_pem)
    root_key = load_pem_private_key(root_key_pem)
    
    # 生成中繼CA私鑰
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 設定中繼CA憑證資訊
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Fake Intermediate CA"),
    ])
    
    # 設定憑證有效期
    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
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
        now + datetime.timedelta(days=365)  # 1年有效期
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
    ).sign(root_key, hashes.SHA256(), default_backend())
    
    # 序列化憑證和私鑰
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
    private_key_pem = intermediate_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    return {
        "cert": cert,
        "cert_pem": cert_pem,
        "private_key": intermediate_key,
        "private_key_pem": private_key_pem
    }

def create_user_certificate(intermediate_cert_pem, intermediate_key_pem, common_name):
    """創建用戶憑證"""
    # 載入中繼CA憑證和私鑰
    intermediate_cert = load_pem_certificate(intermediate_cert_pem)
    intermediate_key = load_pem_private_key(intermediate_key_pem)
    
    # 生成用戶私鑰
    user_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 設定用戶憑證資訊
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake User Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # 設定憑證有效期
    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
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
        now + datetime.timedelta(days=365)  # 1年有效期
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
    ).sign(intermediate_key, hashes.SHA256(), default_backend())
    
    # 序列化憑證和私鑰
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
    private_key_pem = user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    return {
        "cert": cert,
        "cert_pem": cert_pem,
        "private_key": user_key,
        "private_key_pem": private_key_pem
    }

def main():
    clear_screen()
    print_title("憑證鏈偽造工具")
    
    print_info("這個工具將幫助你創建一個完整的憑證鏈，包括：")
    print_info("1. 使用根CA私鑰創建一個中繼CA憑證")
    print_info("2. 使用中繼CA私鑰創建一個用戶憑證")
    print_info("3. 將完整的憑證鏈提交給服務器進行驗證")
    
    print_subtitle("步驟1: 連接服務器獲取根CA憑證")
    print_info("正在連接到服務器...")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("localhost", 12347))
            s.sendall(b"START_LEVEL_4")
            
            # 接收根CA憑證和私鑰
            data = s.recv(16384).decode()
            level4_data = json.loads(data)
            
            root_cert_pem = level4_data["root_cert"]
            root_key_pem = level4_data["root_private_key"]
            challenge = level4_data["challenge"]
            
            print_success("成功獲取根CA憑證和私鑰！")
            print_info(f"挑戰說明: {challenge}")
            
            print_subtitle("根CA憑證")
            print(root_cert_pem[:500] + "...")
            
            print_subtitle("根CA私鑰")
            print(root_key_pem[:500] + "...")
            
            # 創建中繼CA憑證
            print_subtitle("步驟2: 創建中繼CA憑證")
            print_info("正在使用根CA私鑰創建中繼CA憑證...")
            
            intermediate_ca = create_intermediate_ca(root_cert_pem, root_key_pem)
            print_success("成功創建中繼CA憑證！")
            
            print_subtitle("中繼CA憑證")
            print(intermediate_ca["cert_pem"][:500] + "...")
            
            print_subtitle("中繼CA私鑰")
            print(intermediate_ca["private_key_pem"][:500] + "...")
            
            # 創建用戶憑證
            print_subtitle("步驟3: 創建用戶憑證")
            print_info("請輸入用戶憑證的通用名稱(CN):")
            common_name = input("> ")
            if not common_name:
                common_name = "Fake User"
            
            print_info(f"正在使用中繼CA私鑰創建用戶憑證 (CN={common_name})...")
            user_cert = create_user_certificate(
                intermediate_ca["cert_pem"], 
                intermediate_ca["private_key_pem"],
                common_name
            )
            print_success("成功創建用戶憑證！")
            
            print_subtitle("用戶憑證")
            print(user_cert["cert_pem"][:500] + "...")
            
            print_subtitle("用戶私鑰")
            print(user_cert["private_key_pem"][:500] + "...")
            
            # 保存憑證鏈到文件
            print_subtitle("步驟4: 保存憑證鏈")
            try:
                os.makedirs("certs", exist_ok=True)
                
                with open("certs/root_ca.pem", "w") as f:
                    f.write(root_cert_pem)
                
                with open("certs/root_ca_key.pem", "w") as f:
                    f.write(root_key_pem)
                
                with open("certs/intermediate_ca.pem", "w") as f:
                    f.write(intermediate_ca["cert_pem"])
                
                with open("certs/intermediate_ca_key.pem", "w") as f:
                    f.write(intermediate_ca["private_key_pem"])
                
                with open("certs/user_cert.pem", "w") as f:
                    f.write(user_cert["cert_pem"])
                
                with open("certs/user_key.pem", "w") as f:
                    f.write(user_cert["private_key_pem"])
                
                print_success("憑證鏈已保存到 'certs' 目錄")
            except Exception as e:
                print_error(f"保存憑證鏈時發生錯誤: {e}")
            
            # 提交憑證鏈給服務器
            print_subtitle("步驟5: 提交憑證鏈給服務器")
            print_info("是否立即提交憑證鏈給服務器進行驗證? (y/n)")
            submit = input("> ")
            
            if submit.lower() == "y":
                print_info("正在提交憑證鏈...")
                
                # 關閉舊連接並創建新連接
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("localhost", 12347))
                
                # 發送憑證鏈
                s.sendall(b"VERIFY_CERT_CHAIN")
                
                cert_chain = {
                    "user_cert": user_cert["cert_pem"],
                    "intermediate_cert": intermediate_ca["cert_pem"],
                    "root_cert": root_cert_pem
                }
                
                s.sendall(json.dumps(cert_chain).encode())
                
                # 接收驗證結果
                result_data = s.recv(4096).decode()
                result = json.loads(result_data)
                
                if result["status"] == "success":
                    print_success("\n" + result["message"])
                    if "final_secret" in result:
                        print_subtitle("最終獎勵")
                        print_info(result["final_secret"])
                else:
                    print_error("\n" + result["message"])
            else:
                print_info("你可以稍後使用保存的憑證鏈手動提交。")
    
    except ConnectionRefusedError:
        print_error("無法連接到服務器，請確認服務器已啟動。")
    except Exception as e:
        print_error(f"發生錯誤: {e}")

if __name__ == "__main__":
    main()