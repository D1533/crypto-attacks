#!/usr/bin/env python3

import os
from sage.all import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

class VulnerableECDSA:
    def __init__(self):
        self.p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        self.a = -3
        self.b = 41058363725152142129326129780047268409114441015993725554835256314039467401291

        self.E = EllipticCurve(GF(self.p), [self.a, self.b])
        self.G = self.E.gen(0)
        self.q = self.G.order()

        self.d = randint(2, self.q - 1) 
        self.Q = self.d*self.G 

    def get_public_parameters(self):
        return self.E, self.G, self.Q, self.q

    def sign(self, m):
        k = random.getrandbits(128)
        r = int((k*self.G)[0])
        while r % self.q == 0:
            k = random.getrandbits(128)
            r = int((k*self.G)[0])

        h = bytes_to_long(sha1(m).digest())
        s = (pow(k,-1,self.q) * (h + r*self.d)) % self.q

        return (r, s)

def biased_nonce_attack(signatures, hashes, G, Q, q, k_bound):
    assert(len(signatures) == len(hashes))
    a = []
    t = [] 
    for (r, s), h in zip(signatures, hashes):
        a.append( (pow(s, -1, q)*h) % q)
        t.append( (pow(s, -1, q)*r) % q)
    
    B = k_bound
    n = len(signatures)
    M = Matrix(QQ, n + 2, n + 2)
    for i in range(n):
        M[i, i] = q
    
    for i in range(n):
        M[n, i] = t[i]
    M[n, n] = B / q
    
    for i in range(n):
        M[n + 1, i] = a[i]
    M[n + 1, n + 1] = B
    
    L = M.LLL()
    
    r1 = signatures[0][0]
    s1 = signatures[0][1]
    h1 = hashes[0]
    for row in L:
        k1 = int(row[0])
        d = int((pow(r1, -1, q) * (k1*s1 - h1) ) % q)
        if d*G == Q:
            return d

def main():
    # --- Setup ---
    vuln_ecdsa = VulnerableECDSA()
    E, G, Q, q = vuln_ecdsa.get_public_parameters()

    messages = [os.urandom(16) for i in range(3)]
    signatures = [vuln_ecdsa.sign(m) for m in messages]

    # --- PoC - Biased Nonce Attack ---
    hashes = [bytes_to_long(sha1(m).digest()) for m in messages]
    d = biased_nonce_attack(signatures, hashes, G, Q, q, 2**128) 
    assert(d == vuln_ecdsa.d)

if __name__ == "__main__":
    main()
