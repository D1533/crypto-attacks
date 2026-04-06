#!/usr/bin/env python3

from Crypto.Cipher import AES
from random import randint
import os

BLOCK_SIZE = 16

class Oracle():
    def __init__(self):
        self.key = os.urandom(BLOCK_SIZE)
        self.nonce = os.urandom(8)

    def encrypt(self, pt):
        pt = pt.replace(b";", b"").replace(b"=", b"")
        pt = b"user=" + pt + b";admin=false"

        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
        return cipher.encrypt(pt)

    def decrypt(self, ct):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
        return cipher.decrypt(ct)

def ctr_bit_flipping_attack(ct, original, target, offset):
    ct = bytearray(ct)
    for i in range(len(original)):
        ct[offset + i] ^= (original[i] ^ target[i])
    return bytes(ct)

# --- Setup ---
oracle = Oracle()
user = os.urandom(8)
ct = oracle.encrypt(user)

# --- PoC - Bit Flipping Attack ---
offset = len(b"user=" + user + b";admin=") 
ct = ctr_bit_flipping_attack(ct, b"false", b"true\x00", offset)
assert(b";admin=true" in oracle.decrypt(ct))


