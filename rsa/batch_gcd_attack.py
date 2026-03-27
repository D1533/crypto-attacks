#!/usr/bin/env python3

import os
from math import gcd
from Crypto.Util.number import bytes_to_long, getPrime

def generate_rsa_key(e):
    while True:
        p = getPrime(512)
        q = getPrime(512)
        phi = (p-1)*(q-1) 
        if gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            return p, q, d

def batch_gcd_attack(ciphertexts, moduli, e):
    for i in range(len(ciphertexts)-1):
        for j in range(i+1, len(ciphertexts)):
            N_i = moduli[i]
            N_j = moduli[j]
            p = gcd(N_i, N_j)
            if p != 1:
                q = N_i // p
                phi = (p-1)*(q-1)
                d = pow(e, -1, phi)
                m = pow(ciphertexts[i], d, N_i)
                return m
    return None

# --- Setup ---
e = 0x10001
m = bytes_to_long(os.urandom(32))
ciphertexts = []
moduli = []
for _ in range(15):
    p, q, d = generate_rsa_key(e)
    N = p*q
    moduli.append(N)
    ciphertexts.append(pow(m, e, N))

# add a public key with shared factors
q = getPrime(512)
N = p*q
moduli.append(N)
ciphertexts.append(pow(m, e, N))

# --- Batch GCD Attack ---
m_recovered = batch_gcd_attack(ciphertexts, moduli, e)
assert(m_recovered == m)

