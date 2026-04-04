#!/usr/bin/env python3

from Crypto.Cipher import AES
from random import randint
import os


def encrypt_oracle(userdata):
    userdata = userdata.replace(b";", b"").replace(b"=", b"")
    pt = b"user=" + userdata + b";admin=false"

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(pt)

def decrypt(ct):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)

def ctr_bit_flipping_attack():
    payload = b"A" * 16
    ct = encrypt_oracle(payload)

    prefix = b"user=" + payload + b";admin="
    offset = len(prefix)

    original = b"false"
    target = b"true\x00"
    ct = bytearray(ct)
    for i in range(len(original)):
        ct[offset + i] ^= original[i] ^ target[i]

    return bytes(ct)

# --- Setup ---
key = os.urandom(16)
nonce = os.urandom(8)


# --- PoC - Bit Flipping Attack ---
ct = ctr_bit_flipping_attack()
pt = decrypt(ct)
assert b";admin=true" in pt


