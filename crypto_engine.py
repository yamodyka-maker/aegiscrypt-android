# crypto_engine.py
import os
import struct

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError:
    # حالت اجرا روی اندروید با پکیج argon2-cffi-bindings
    from _argon2_cffi_bindings import ffi, lib
    
    class Type:
        D = 0
        I = 1
        ID = 2  # Argon2id
    
    def hash_secret_raw(secret: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int, hash_len: int, type: int):
        out = ffi.new(f"uint8_t[{hash_len}]")
        res = lib.argon2_hash(
            time_cost, memory_cost, parallelism,
            secret, len(secret),
            salt, len(salt),
            out, hash_len,
            ffi.NULL, 0,
            type, 0x13
        )
        if res != 0:
            raise ValueError(f"Argon2 failed with error code {res}")
        return bytes(ffi.buffer(out, hash_len))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAGIC = b"AEGISCRYPT1"
CHUNK_SIZE = 1024 * 1024  # 1 MB chunking

def create_cipher(algorithm_name: str, key: bytes):
    if algorithm_name == "AES-256-GCM":
        return AESGCM(key), 1
    elif algorithm_name == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key), 2
    raise ValueError(f"Unknown algorithm: {algorithm_name}")

def get_cipher_by_id(algo_id: int, key: bytes):
    if algo_id == 1:
        return AESGCM(key), "AES-256-GCM"
    elif algo_id == 2:
        return ChaCha20Poly1305(key), "ChaCha20-Poly1305"
    raise ValueError(f"Unknown algorithm ID: {algo_id}")

def encrypt_file(src: str, dst: str, password: str, algo: str, mem_kib: int, iters: int, parallel: int):
    salt = os.urandom(16)
    nonce_prefix = os.urandom(8)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=iters,
        memory_cost=mem_kib,
        parallelism=parallel,
        hash_len=32,
        type=Type.ID,
    )
    cipher, algo_id = create_cipher(algo, key)
    header = MAGIC + salt + nonce_prefix + bytes([algo_id]) + struct.pack(">III", mem_kib, iters, parallel)

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header)
        chunk_idx = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk and chunk_idx != 0:
                break
            nonce = nonce_prefix + struct.pack(">I", chunk_idx)
            aad = header + struct.pack(">I", chunk_idx)
            encrypted = cipher.encrypt(nonce, chunk, aad)
            fout.write(struct.pack(">I", len(encrypted)))
            fout.write(encrypted)
            chunk_idx += 1
            if not chunk:
                break

def decrypt_file(src: str, dst: str, password: str):
    header_len = len(MAGIC) + 16 + 8 + 1 + 12
    with open(src, "rb") as fin:
        header = fin.read(header_len)
        if len(header) < header_len or not header.startswith(MAGIC):
            raise ValueError("فایل نامعتبر است یا ساختار Aegis ندارد.")

        offset = len(MAGIC)
        salt = header[offset : offset + 16]; offset += 16
        nonce_prefix = header[offset : offset + 8]; offset += 8
        algo_id = header[offset]; offset += 1
        mem_kib, iters, parallel = struct.unpack(">III", header[offset : offset + 12])

        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=iters,
            memory_cost=mem_kib,
            parallelism=parallel,
            hash_len=32,
            type=Type.ID,
        )
        cipher, algo_name = get_cipher_by_id(algo_id, key)

        with open(dst, "wb") as fout:
            chunk_idx = 0
            while True:
                length_bytes = fin.read(4)
                if not length_bytes:
                    break
                chunk_len = struct.unpack(">I", length_bytes)[0]
                encrypted = fin.read(chunk_len)
                if len(encrypted) != chunk_len:
                    raise ValueError("فایل ناقص یا خراب شده است.")
                nonce = nonce_prefix + struct.pack(">I", chunk_idx)
                aad = header + struct.pack(">I", chunk_idx)
                decrypted = cipher.decrypt(nonce, encrypted, aad)
                fout.write(decrypted)
                chunk_idx += 1

    return algo_name, mem_kib, iters, parallel
