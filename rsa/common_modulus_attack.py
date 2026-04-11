#!/usr/bin/env python3

from math import gcd
from Crypto.Util.number import getPrime, bytes_to_long
import random
import os

class VulnerableRSA:
    def __init__(self):
        self.n, self.e, self.d = self.generate_keys()
    
    def generate_keys(self):
        p = getPrime(512)
        q = getPrime(512)
        n = p*q
        phi = (p-1)*(q-1)
        while True:
            e1 = random.randint(2, n-1)
            e2 = random.randint(2, n-1)
            if gcd(e1, phi) == 1 and gcd(e2,phi) == 1 and gcd(e1, e2) == 1:
                d1 = pow(e1, -1, phi)
                d2 = pow(e2, -1, phi)
                return n, (e1, e2), (d1, d2)
    
    def encrypt(self, m):
        n = self.n
        e1, e2 = self.e[0], self.e[1]
        return n, (e1, e2), (pow(m, e1, n), pow(m, e2, n))

def common_modulus_attack(c1, c2, e1, e2, n):
    def xgcd(a, b):
        x0, x1 = 1, 0
        y0, y1 = 0, 1
        while b != 0:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1

        return a, x0, y0

    g, u, v = xgcd(e1, e2)
    assert(g == 1)
    
    if u < 0:
        c1 = pow(c1, -1, n)
        u = -u
    if v < 0:
        c2 = pow(c2, -1, n)
        v = -v
    m = (pow(c1, u, n) * pow(c2, v, n)) % n
    
    return m

def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()
    m = bytes_to_long(os.urandom(32))
    n, (e1, e2), (c1, c2) = vuln_rsa.encrypt(m)

    # --- PoC - Common Modulus attack ---
    assert(m == common_modulus_attack(c1, c2, e1, e2, n))

if __name__ == "__main__":
    main()
