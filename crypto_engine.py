import os
import struct
import hashlib
from Crypto.Cipher import AES, ChaCha20_Poly1305

MAGIC = b"AEGISCRYPT1"
ALGO_AES_GCM = 1
ALGO_CHACHA20 = 2

# تنظیمات استاندارد و امن Scrypt برای مشتق‌گیری کلید بدون وابستگی خارجی
SCRYPT_N = 16384  # میزان حافظه/سختی محاسباتی
SCRYPT_R = 8      # اندازه بلوک
SCRYPT_P = 1      # موازی‌سازی

def derive_key(password: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """مشتق‌گیری کلید ۳۲ بایتی با استفاده از hashlib استاندارد خود پایتون"""
    return hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32
    )

def encrypt_file(src_path: str, dst_path: str, password: str, algorithm: str,
                 memory_kib: int = 65536, iterations: int = 2, parallelism: int = 2):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(src_path, "rb") as f:
        plaintext = f.read()

    if algorithm == "AES-256-GCM":
        algo_id = ALGO_AES_GCM
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        payload = tag + ciphertext
    elif algorithm == "ChaCha20-Poly1305":
        algo_id = ALGO_CHACHA20
        nonce = os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        payload = tag + ciphertext
    else:
        raise ValueError(f"الگوریتم پشتیبانی نمی‌شود: {algorithm}")

    # هدر استاندارد شامل مشخصات الگوریتم، salt و nonce
    header = MAGIC + struct.pack(">B I I I", algo_id, memory_kib, iterations, parallelism) + salt + nonce

    with open(dst_path, "wb") as f:
        f.write(header)
        f.write(payload)

def decrypt_file(src_path: str, dst_path: str, password: str):
    header_len = len(MAGIC) + 13 + 16 + 12

    with open(src_path, "rb") as f:
        header = f.read(header_len)
        data = f.read()

    if len(header) < header_len or not header.startswith(MAGIC):
        raise ValueError("فایل نامعتبر است یا ساختار Aegis ندارد.")

    offset = len(MAGIC)
    algo_id, memory_kib, iterations, parallelism = struct.unpack(">B I I I", header[offset:offset + 13])
    offset += 13

    salt = header[offset:offset + 16]
    offset += 16

    nonce = header[offset:offset + 12]

    # ساخت مجدد کلید رمزنگاری
    key = derive_key(password, salt)

    tag = data[:16]
    ciphertext = data[16:]

    if algo_id == ALGO_AES_GCM:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    elif algo_id == ALGO_CHACHA20:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    else:
        raise ValueError("شناسایی الگوریتم در هدر فایل نامعتبر است.")

    with open(dst_path, "wb") as f:
        f.write(plaintext)
