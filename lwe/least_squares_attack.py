#!/usr/bin/env python3

from sage.all import *

def no_modulus(A, b):
    A = Matrix(RR, A)
    b = vector(RR, b)
    s = (A.T * A).solve_right(A.T * b)
    s = vector(ZZ, [round(s_i) for s_i in s])
    return s

# --- Setup ---
n = 32
q = random_prime(2**16)
s = vector([randint(0, q-1) for _ in range(n)])
A = []
b = []
for i in range(n):
    a_i = vector([randint(0,q-1) for _ in range(n)])
    b_i = a_i*s + randint(-3, 3)
    A.append(a_i)
    b.append(b_i)


# --- PoC - Least-squares attack 
s_recovered = no_modulus(A, b)
assert(s_recovered == s)
