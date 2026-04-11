#!/usr/bin/env python3

from sage.all import *

class VulnerableRSA:
    def __init__(self):
        self.e = 3
        self.n, self.d = self.generate_keys()
        self.k = randint(2, 30)
    
    def generate_keys(self):
        while True:
            p = int(random_prime(2**512))
            q = int(random_prime(2**512))
            n = int(p*q)
            phi = (p-1)*(q-1) 
            if gcd(self.e, phi) == 1:
                d = pow(self.e, -1, phi)
                return n, d
    
    def get_public_keys(self):
        return self.n, self.e
    
    def encrypt(self, m):
        r = int(randint(0, 2**self.k - 1))
        return pow(2**self.k*m + r, self.e, self.n)

def coppersmith_short_pad_attack(c1, c2, N, e, eps):
    R1 = PolynomialRing(Zmod(N), ['x', 'y'])
    x, y = R1.gens()
    R2 = PolynomialRing(Zmod(N), 'y')
    y = R2.gen()

    g1 = (x**e - c1).change_ring(R2)
    g2 = ( (x+y)**e - c2).change_ring(R2)

    res = g1.resultant(g2, variable=x)
    roots = res.univariate_polynomial().change_ring(Zmod(N)).small_roots(epsilon=eps)
    
    delta = roots[0]
    
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

    m = franklin_reiter_attack(1, delta, e, c1, c2, N)
    
    return int(m)


def main():
    # --- Setup --
    vuln_rsa = VulnerableRSA()
    k = vuln_rsa.k
    n, e = vuln_rsa.get_public_keys()
    
    m = randint(2, 2**(n.bit_length() - k))
    c1 = vuln_rsa.encrypt(m)
    c2 = vuln_rsa.encrypt(m)

    # -- PoC - Coppersmith's Short Pad Attack ---
    m1 = coppersmith_short_pad_attack(c1, c2, n, e, eps=1/20) # m1 = 2**k*m + r1
    assert(m == m1 // 2**k)


if __name__ == "__main__":
    main()
