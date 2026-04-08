#!/usr/bin/env python3

from os import urandom
from Crypto.Util.number import getPrime, GCD, bytes_to_long
from gmpy2 import iroot

class VulnerableRSA:
    def __init__(self):
        self.e = 3
        self.p, self.q = self.generate_primes()
        self.n = self.p * self.q
        self.d = pow(self.e, -1, (self.p-1)*(self.q-1))

    def generate_primes(self):
        while True:
            p = getPrime(512)
            q = getPrime(512)
            if GCD(self.e, (p-1)*(q-1)) == 1:
                return p, q
    
    def get_public_key(self):
        return self.n , self.e

    def encrypt(self, m):
        return pow(m, self.e, self.n)

def small_exponent_attack(c, e):
    m, exact = iroot(c, e)
    if exact:
        return m
    return None


def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()
    m = bytes_to_long(urandom(32))
    c = vuln_rsa.encrypt(m)
    
    # --- Poc - Small Exponent Attack
    n, e = vuln_rsa.get_public_key()
    assert(m == small_exponent_attack(c, e))



if __name__ == "__main__":
    main()
