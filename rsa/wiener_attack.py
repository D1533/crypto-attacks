#!/usr/bin/env python3

from sage.all import *

class VulnerableRSA:
    def __init__(self):
        self.d, self.p, self.q = self.generate_privkey()
        self.n = self.p * self.q
        self.e = pow(self.d, -1, (self.p - 1)*(self.q - 1))

    def generate_privkey(self):
        q = int(random_prime(2**128))
        while True:
            p = int(random_prime(2*q))
            if p < q:
                continue
            n = p*q
            phi = (p-1)*(q-1)
            d = randint(2, int(n**(1/4)//3))
            if gcd(d, phi) == 1:
                return d, p, q
    
    def get_public_key(self):
        return self.n, self.e

def wiener_attack(e, n):
    conv = continued_fraction(QQ(e)/n).convergents() 
    for kd in conv:
        k = kd.numerator()
        d = kd.denominator()

        if k == 0 or (e*d - 1) % k != 0:
            continue
        
        phi = (e*d - 1) // k
        s = n - phi + 1
        discr = s**2 - 4*n
        if discr >= 0 and is_square(discr):
            t = isqrt(discr)
            p = (s + t)//2
            q = (s - t)//2

            if p*q == n:
                return d
    return None


def main():
    # --- Setup ---
    vuln_rsa = VulnerableRSA()

    # --- PoC - Wiener Attack ---
    n, e = vuln_rsa.get_public_key()
    assert(vuln_rsa.d == wiener_attack(e, n))

if __name__ == "__main__":
    main()
