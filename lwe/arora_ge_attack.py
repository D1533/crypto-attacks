#!/usr/bin/env python3

from sage.all import *


class VulnerableLWE:
    def __init__(self):
        self.n = 32
        self.m = 512
        self.q = random_prime(2**16)
        self.s = VectorSpace(GF(self.q), self.n).random_element() 

    def encrypt(self):
        A = []
        b = []
        V = VectorSpace(GF(self.q), self.n)
        for _ in range(self.m):
            a = V.random_element()
            A.append(a)
            b.append( a*self.s + randint(0,1))

        return A, b, self.q

def arora_ge_attack(q, A, b, E):
    m = len(A)
    n = len(A[0])
    
    R = PolynomialRing(GF(q), n, 's')
    s = R.gens()
    
    f = []
    for i in range(m):
        p = prod((b[i] - sum(A[i][j]*s[j] for j in range(n)) - e) for e in E)
        f.append(p)
    
    s = []
    for p in R.ideal(f).groebner_basis():
        assert p.nvariables() == 1 and p.degree() == 1
        s.append(int(-p.constant_coefficient()))

    return s

def main():
    # -- Setup --
    vuln_lwe = VulnerableLWE()
    A, b, q = vuln_lwe.encrypt()

    # --- PoC - Arora-Ge Attack ---
    assert(list(vuln_lwe.s) == arora_ge_attack(q, A, b, (0,1)))

if __name__ == "__main__":
    main()
