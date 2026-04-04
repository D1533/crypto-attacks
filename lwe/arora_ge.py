#!/usr/bin/env python3

from sage.all import *

def arora_ge(q, A, b, E):
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


# -- Setup --
n = 32
m = 512
q = random_prime(2**16)
A = []
b = []
V = VectorSpace(GF(q), n)
s = V.random_element()
for i in range(m):
    a_i = V.random_element()
    b_i = a_i*s + randint(0,1)
    A.append(a_i)
    b.append(b_i)


# --- PoC - Arora-Ge ---
s_recovered = arora_ge(q, A, b, (0,1))
assert(s == V(s_recovered))
