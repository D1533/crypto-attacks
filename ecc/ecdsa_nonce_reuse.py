#!/usr/bin/env python3

import os
from sage.all import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long


class VulnerableECDSA:
    def __init__(self):
        self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        self.E = EllipticCurve(GF(self.p), [self.a, self.b])
        self.G = self.E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
        self.q = int(self.G.order())
        
        self.d = randint(1, self.q - 1)
        self.k = randint(1, self.q - 1)
        self.Q = self.d * self.G 

    def get_public_parameters(self):
        return self.E, self.G, self.Q, self.q

    def sign(self, m):
        kG = self.k*self.G
        r = int(kG[0]) % self.q

        h = bytes_to_long(sha1(m).digest()) 
        if h.bit_length() > self.q.bit_length():
            h >>= (h.bit_length() - self.q.bit_length())  

        s = (pow(self.k, -1, self.q) * (h + r*self.d) ) % self.q

        return r, s


def ecdsa_nonce_reuse_attack(r1, s1, r2, s2, m1, m2, q):
    h1 = bytes_to_long(sha1(m1).digest())
    if h1.bit_length() > q.bit_length():
        h1 >>= (h1.bit_length() - q.bit_length())

    h2 = bytes_to_long(sha1(m2).digest())
    if h2.bit_length() > q.bit_length():
        h2 >>= (h2.bit_length() - q.bit_length())

    k = ((h1 - h2) * pow(s1 - s2, -1, q) ) % q
    d = (pow(r1, -1, q) * (s1*k - h1 ) ) % q 
    return d


def main():
    # --- Setup ---
    vuln_ecdsa = VulnerableECDSA()
    E, G, Q, q = vuln_ecdsa.get_public_parameters()

    m1 = os.urandom(32)
    m2 = os.urandom(32)
    r1, s1 = vuln_ecdsa.sign(m1)
    r2, s2 = vuln_ecdsa.sign(m2)

    # --- PoC - ECDSA Nonce Reuse Attack ---
    d = ecdsa_nonce_reuse_attack(r1, s1, r2, s2, m1, m2, q)

    assert(d == vuln_ecdsa.d)



if __name__ == "__main__":
    main()


