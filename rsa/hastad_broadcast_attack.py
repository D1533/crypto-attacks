#!/usr/bin/env python3

import os
from sage.all import *
from Crypto.Util.number import bytes_to_long, getPrime
from gmpy2 import iroot


class VulnerableRSA:
    def __init__(self):
        self.e = 3
        self.n, self.d = self.generate_keys()

    def generate_keys(self):
        n = []
        d = []
        for _ in range(self.e):
            while True:
                p = getPrime(512)
                q = getPrime(512)
                if gcd(self.e, (p-1)*(q-1)) == 1:
                    n.append(p*q)
                    d.append(pow(self.e, -1, p*q))
                    break
        return n, d

    def encrypt(self, m):
        pubkeys =  []
        ct = []
        for n in self.n:
            pubkeys.append((n, self.e))
            ct.append(pow(m, self.e, n))

        return pubkeys, ct

def hastad_broadcast_attack(ciphertexts, moduli, e):
    m = crt(ciphertexts, moduli)
    m, exact = iroot(m, e)
    if exact:
        return m
    return None


def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()
    m = bytes_to_long(os.urandom(16))
    pubkeys, ciphertexts = vuln_rsa.encrypt(m)

    # --- PoC - Hastad's Broadcast Attack ---
    moduli = [n for n, e in pubkeys]
    e = pubkeys[0][1]
    assert(m == hastad_broadcast_attack(ciphertexts, moduli, e))

if __name__ == "__main__":
    main()


