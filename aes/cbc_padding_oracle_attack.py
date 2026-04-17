#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from random import randint

BLOCK_SIZE = 16

class Oracle:
    def __init__(self):
        self.key = os.urandom(16)
        self.iv = os.urandom(16)
        self.secret = os.urandom(randint(1,100))

    def encrypt_secret(self):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        ct = cipher.encrypt(pad(self.secret, BLOCK_SIZE))
        return self.iv + ct

    def decrypt(self, ct):
        cipher = AES.new(self.key, AES.MODE_CBC)
        try:
            pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
            return True
        except:
            return False


def cbc_padding_oracle_attack(oracle, ct):
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]

    pt = b""
    prev_block = blocks[0]
    for i in range(1, len(blocks)):
        curr_block = blocks[i]
        mask = bytearray(16)

        for byte_idx in range(15, -1, -1):
            pad = 16 - byte_idx
            last_block = bytearray([pad] * 16)

            for k in range(byte_idx + 1, 16):
                last_block[k] ^= mask[k]

            for b in range(256):
                last_block[byte_idx] = b
                ct_b = bytes(last_block) + curr_block

                if oracle.decrypt(ct_b):
                    mask[byte_idx] = b ^ pad
                    break

        plaintext_block = bytes([a ^ b for a,b in zip(prev_block, mask)])

        pt += plaintext_block
        prev_block = curr_block
    
    return pt

def main():
    # --- Setup ---
    oracle = Oracle()
    ct = oracle.encrypt_secret()

    # --- PoC - CBC Padding Oracle Attack ---
    pt = unpad(cbc_padding_oracle_attack(oracle, ct), BLOCK_SIZE)
    assert(pt == oracle.secret)    

if __name__ == "__main__":
    main()

