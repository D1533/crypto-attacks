#!/usr/bin/env python3

import os
from math import gcd
from Crypto.Util.number import bytes_to_long, getPrime
import random

class VulnerableRSA:
    def __init__(self):
        self.e = 0x10001
        self.keys = self.generate_keys()

    def generate_keys(self):
        keys = []
        p = getPrime(512)
        for _ in range(2):
            while True:
                q = getPrime(512)
                if gcd(self.e, (p-1)*(q-1)) == 1:
                    keys.append( (p*q, pow(self.e, -1, (p-1)*(q-1))))
                    break
        return keys

    def encrypt(self, m):
        n = random.choice(self.keys)[0]
        return n, self.e, pow(m, self.e, n)
    
    def decrypt(self, c, n):
        for n_i, d_i in self.keys:
            if n_i == n:
                return pow(c, d_i, n_i)
        return None


def batch_gcd_attack(ciphertexts, moduli, e):
    for i in range(len(ciphertexts)-1):
        for j in range(i+1, len(ciphertexts)):
            N_i = moduli[i]
            N_j = moduli[j]
            p = gcd(N_i, N_j)
            if p != 1 and p != N_i:
                q = N_i // p
                phi = (p-1)*(q-1)
                d = pow(e, -1, phi)
                m = pow(ciphertexts[i], d, N_i)
                return m
    return None

def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()

    m = bytes_to_long(os.urandom(32))
    ciphertexts = []
    moduli = []
    for _ in range(100):
        n, e, c = vuln_rsa.encrypt(m)
        moduli.append(n)
        ciphertexts.append(c)

    # --- Batch GCD Attack ---
    assert(m == batch_gcd_attack(ciphertexts, moduli, e))


if __name__ == "__main__":
    main()
