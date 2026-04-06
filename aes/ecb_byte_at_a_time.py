#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
from random import randint

BLOCK_SIZE = 16

class Oracle():
    def __init__(self):
        self.key = os.urandom(BLOCK_SIZE)
        self.secret = os.urandom(randint(1,100))

    def encrypt(self, pt):
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(pt + self.secret, BLOCK_SIZE))
        return ct

def ecb_byte_at_a_time_attack(oracle):
    len_0 = len(oracle.encrypt(b""))
    for i in range(BLOCK_SIZE):
        len_i = len(oracle.encrypt(b"A" * (i+1)))
        if len_i > len_0:
            secret_len = len_0 - (i+1)
            break

    secret = b""
    for i in range(secret_len):  
        block_idx = i // BLOCK_SIZE

        payload = b"A" * (BLOCK_SIZE - 1 - (i % BLOCK_SIZE))
        ct = oracle.encrypt(payload)

        for b in range(256):
            pt_b = payload + secret + bytes([b])
            ct_b = oracle.encrypt(pt_b)
            
            curr_block = ct_b[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            target_block = ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            if curr_block == target_block:
                secret += bytes([b])
                break

    return secret

# --- Setup ---
oracle = Oracle()

# --- PoC - ECB Byte At A Time ---
secret = ecb_byte_at_a_time_attack(oracle)
assert(oracle.secret == secret)


