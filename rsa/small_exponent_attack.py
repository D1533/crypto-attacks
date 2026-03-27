#!/usr/bin/env python3

from sage.all import *
from gmpy2 import iroot

def small_exponent_attack(c, e):
    m, exact = iroot(c, e)
    if exact:
        return m

    return None

# --- Setup ---
p = random_prime(2**512)
q = random_prime(2**512)
N = int(p*q)
e = 3

m = randint(2, iroot(N, e)[0])
assert(m**e < N)

c = pow(m, e, N)

# --- Poc - Small Exponent Attack
m_recovered = small_exponent_attack(c, e)
assert(m_recovered == m)




