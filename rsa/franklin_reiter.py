#!/usr/bin/env python3

from sage.all import *


class VulnerableRSA:
    def __init__(self):
        self.e = 3
        self.p, self.q = self.generate_primes()
        self.n = self.p * self.q
        self.d = pow(self.e, -1, (self.p - 1)*(self.q - 1))

    def generate_primes(self):
        while True:
            p = int(random_prime(2**512))
            q = int(random_prime(2**512))
            phi = (p-1)*(q-1) 
            if gcd(self.e, phi) == 1:
                return p, q 
    def get_public_key(self):
        return self.n, self.e
    
    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def affine_encrypt(self, m):
        a = randint(1, self.n - 1)
        b = randint(0, self.n - 1)
        return a, b, pow(a*m + b, self.e, self.n)
    
def franklin_reiter_attack(a, b, e, c1, c2, N):
     
    R = PolynomialRing(Zmod(N), 'x')
    x = R.gen()
    
    def polynomial_gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    f = x**e - c1
    g =  (a*x + b)**e - c2
    
    h = polynomial_gcd(f, g)
    m = -h[0] % N
    
    return m

def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()
    n, e = vuln_rsa.get_public_key()
    m = randint(2, n - 1)
    c1 = vuln_rsa.encrypt(m)
    a, b, c2 = vuln_rsa.affine_encrypt(m)
    
    # --- PoC - Franklin-Reiter Attack
    assert (m == franklin_reiter_attack(a, b, e, c1, c2, n))


if __name__ == "__main__":
    main()




