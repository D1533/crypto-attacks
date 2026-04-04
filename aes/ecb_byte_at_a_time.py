#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from random import randint

def encrypt_oracle(pt):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt + secret, AES.block_size))
    return ct

def ecb_byte_at_a_time():
    len_0 = len(encrypt_oracle(b""))
    for i in range(16):
        len_i = len(encrypt_oracle(b"A" * (i+1)))
        if len_i > len_0:
            secret_len = len_0 - (i+1)
            break

    secret = b""
    for i in range(secret_len):  
        block_idx = i // 16

        payload = b"A" * (15 - (i % 16))
        ct = encrypt_oracle(payload)

        for b in range(256):
            pt_b = payload + secret + bytes([b])
            ct_b = encrypt_oracle(pt_b)

            if ct_b[16*(block_idx):16*(block_idx + 1)] == ct[16*(block_idx):16*(block_idx + 1)]:
                secret += bytes([b])
                break

    return secret


# --- Setup ---
key = os.urandom(16)
secret = os.urandom(randint(1, 100))

# --- PoC - ECB Byte At A Time ---
secret_recovered = ecb_byte_at_a_time()
assert(secret == secret_recovered)


