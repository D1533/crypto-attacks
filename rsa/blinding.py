#!/usr/bin/env python3

from math import gcd
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from random import randint

class Oracle:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.e = 0x10001
        self.d = pow(self.e, -1, (self.p - 1)*(self.q - 1))
    
    def get_public_key(self):
        return self.n, self.e

    def sign(self, m):
        if m == b"admin":
            return None
        return pow(bytes_to_long(m), self.d, self.n)


def main():
    # --- Setup ---
    oracle = Oracle()
    n, e = oracle.get_public_key()

    # --- PoC - Blinding Attack --- 
    m = bytes_to_long(b"admin")
    r = randint(2, n - 1)
    
    # Ensure we can take the inverse of r mod n later
    while gcd(r, n) != 1:
        r = randint(2, n - 1)

    m_blinded = long_to_bytes((pow(r, e, n) * m ) % n)
    S_blinded = oracle.sign(m_blinded)
    S_m = (pow(r, -1, n)*S_blinded ) % n

    assert(long_to_bytes(pow(S_m, e, n)) == b"admin")

if __name__ == "__main__":
    main()

