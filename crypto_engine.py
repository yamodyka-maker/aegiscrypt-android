import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

MAGIC = b"AEGISCRYPT1"
ALGO_AES_GCM = 1
ALGO_CHACHA20 = 2


def derive_key(password: str, salt: bytes, memory_kib: int, iterations: int, parallelism: int) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=parallelism,
        memory_cost=memory_kib,
        ad=None,
        secret_box=None
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_file(src_path: str, dst_path: str, password: str, algorithm: str,
                 memory_kib: int = 65536, iterations: int = 2, parallelism: int = 2):
    salt = os.urandom(16)
    key = derive_key(password, salt, memory_kib, iterations, parallelism)

    with open(src_path, "rb") as f:
        plaintext = f.read()

    if algorithm == "AES-256-GCM":
        algo_id = ALGO_AES_GCM
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
    elif algorithm == "ChaCha20-Poly1305":
        algo_id = ALGO_CHACHA20
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    header = MAGIC + struct.pack(">B I I I", algo_id, memory_kib, iterations, parallelism) + salt + nonce

    with open(dst_path, "wb") as f:
        f.write(header)
        f.write(ciphertext)


def decrypt_file(src_path: str, dst_path: str, password: str):
    header_len = len(MAGIC) + 13 + 16 + 12

    with open(src_path, "rb") as f:
        header = f.read(header_len)
        ciphertext = f.read()

    if len(header) < header_len or not header.startswith(MAGIC):
        raise ValueError("Invalid Aegis file or corrupted header.")

    offset = len(MAGIC)
    algo_id, memory_kib, iterations, parallelism = struct.unpack(">B I I I", header[offset:offset + 13])
    offset += 13

    salt = header[offset:offset + 16]
    offset += 16

    nonce = header[offset:offset + 12]

    key = derive_key(password, salt, memory_kib, iterations, parallelism)

    if algo_id == ALGO_AES_GCM:
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    elif algo_id == ALGO_CHACHA20:
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    else:
        raise ValueError("Unsupported algorithm ID in file header.")

    with open(dst_path, "wb") as f:
        f.write(plaintext)
