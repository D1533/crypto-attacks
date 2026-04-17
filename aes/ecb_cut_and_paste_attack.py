#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = 16

class Oracle():
    def __init__(self):
        self.key = os.urandom(BLOCK_SIZE)
    
    def encrypt(self, user):
        user = user.replace(b"=", b"").replace(b";", b"")
        pt =  b"user=" + user + b";admin=False"
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(pt, BLOCK_SIZE))
        return ct
    
    def decrypt(self, ct):
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
        return pt


def ecb_cut_and_paste_attack(oracle, len_prefix, len_sufix, target, target_offset):
    pad_len = BLOCK_SIZE - (len_prefix % BLOCK_SIZE)
    
    pt1 = b"A"*pad_len + b"B"*( (BLOCK_SIZE - target_offset) % BLOCK_SIZE)
    ct1 = oracle.encrypt(pt1)

    pt2 = b"A"*pad_len + pad(target, BLOCK_SIZE)
    ct2 = oracle.encrypt(pt2)
    
    block = len_sufix // 16 + 1
    ct = ct1[:-16] + ct2[-16*(block+1):-16*block]
    
    return ct

def main():
    oracle = Oracle()
    
    len_prefix = len("user=")
    len_sufix = len(";admin=False")
    target = b"True"
    target_offset = len_sufix - len("False")

    ct = ecb_cut_and_paste_attack(oracle, len_prefix, len_sufix, target, target_offset)
    assert(b";admin=True" in oracle.decrypt(ct))

if __name__ == "__main__":
    main()
















