#!/usr/bin/env python3

from sage.all import *

def generate_rsa_key():
    e = 3
    while True:
        p = int(random_prime(2**512))
        q = int(random_prime(2**512))
        phi = (p-1)*(q-1) 
        if gcd(e, phi) == 1:
            N = p*q
            d = pow(e, -1, phi)
            return N, e, d

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

# --- Setup ---
N, e, d = generate_rsa_key()

Z_N = Zmod(N)
a = Z_N.random_element()
b = Z_N.random_element()

# Ensure m1, m2 are units in Z_N
m1 = Z_N.random_element()
m2 = Z_N(a*m1 + b)
while gcd(m1, N) != 1 or gcd(m2, N) != 1:
    m1 = Z_N.random_element()
    m2 = Z_N(a*m1 + b)

c1 = pow(m1, e, N)
c2 = pow(m2, e, N)


# --- PoC - Franklin-Reiter Attack ---
m = franklin_reiter_attack(a, b, e, c1, c2, N)
assert(m == m1)

