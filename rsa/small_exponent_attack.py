#!/usr/bin/env python3

from Crypto.Util.number import getPrime
from gmpy2 import iroot
from random import randint

def small_exponent_attack(c, e):
    m, exact = iroot(c, e)
    if exact:
        return m

    return None

# --- Setup ---
p = getPrime(512)
q = getPrime(512)
N = p*q
e = 3

m = randint(2, iroot(N, e)[0])
assert(m**e < N)

c = pow(m, e, N)

# --- Poc - Small Exponent Attack
m_recovered = small_exponent_attack(c, e)
assert(m_recovered == m)




