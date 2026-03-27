#!/usr/bin/env python3

from sage.all import *
from Crypto.Util.number import getPrime

def generate_rsa_keys():
    p = getPrime(512)
    q = getPrime(512)
    phi = (p-1)*(q-1)
    N = p*q
    while True:
        e1 = randint(2, N-1)
        e2 = randint(2, N-1)
        if gcd(e1, phi) == 1 and gcd(e2,phi) == 1 and gcd(e1, e2) == 1:
            d1 = pow(e1, -1, phi)
            d2 = pow(e2, -1, phi)
            return N, e1, e2, d1, d2

def common_modulus_attack(c1, c2, e1, e2, N):
    g, u, v = xgcd(e1, e2)
    assert(g == 1)
    
    if u < 0:
        c1 = pow(c1, -1, N)
        u = -u
    if v < 0:
        c2 = pow(c2, -1, N)
        v = -v
    m = (pow(c1, u, N) * pow(c2, v, N)) % N
    
    return m

# --- Setup ---
N, e1, e2, d1, d2 = generate_rsa_keys()
m = randint(2, N-1)

c1 = pow(m, e1, N)
c2 = pow(m, e2, N)

# --- PoC - Common Modulus attack ---
m_recovered = common_modulus_attack(c1, c2, e1, e2, N) 
assert(m_recovered == m)


