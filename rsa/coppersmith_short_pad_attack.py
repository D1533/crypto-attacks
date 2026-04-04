#!/usr/bin/env python3

from sage.all import *

def coppersmith_short_pad(c1, c2, N, e, eps):
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
    
    return m

# --- Setup ---
e = 3
p = random_prime(2**128)
q = random_prime(2**128)
while gcd(e, (p-1)*(q-1)) != 1:
    p = random_prime(2**512)
    q = random_prime(2**512)

N = int(p*q)

k = randint(2, 100)
r1 = randint(0, 2**k - 1)
r2 = randint(0, 2**k - 1)
m = randint(2, 2**(N.bit_length() - k))
m1 = 2**k*m + r1
m2 = 2**k*m + r2
c1 = pow(m1, e, N)
c2 = pow(m2, e, N)

# --- PoC - Coopersmith's Short Pad Attack --- 
m1_recovered = coppersmith_short_pad(c1, c2, N, e, eps=1/20)
m_recovered = m1 // 2**k
assert(m1_recovered == m1) 
assert(m_recovered == m)

