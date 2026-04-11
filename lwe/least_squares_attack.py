#!/usr/bin/env python3

from sage.all import *

class VulnerableLWE:
    def __init__(self):
        self.n = 32
        self.m = 32
        self.q = random_prime(2**16)
        self.s = vector([randint(0, self.q-1) for _ in range(self.n)])

    def encrypt(self):
        A = []
        b = []
        for _ in range(self.m):
            a = vector([randint(0, self.q - 1) for _ in range(self.n)])
            A.append(a)
            b.append(a*self.s + randint(-3,3))

        return A, b, self.q

def least_squares_attack(A, b):
    A = Matrix(RR, A)
    b = vector(RR, b)
    s = (A.T * A).solve_right(A.T * b)
    s = vector(ZZ, [round(s_i) for s_i in s])
    return s

def main():
    # --- Setup ---
    vuln_lwe = VulnerableLWE()
    A, b, q = vuln_lwe.encrypt()

    # --- PoC - Least-squares attack 
    assert(vuln_lwe.s == least_squares_attack(A, b))

if __name__ == "__main__":
    main()
