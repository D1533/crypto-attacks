#!/usr/bin/env python3

from sage.all import *

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

# --- Setup ---
q = int(random_prime(2**128))

while True:
    p = int(random_prime(2*q))
    if p < q:
        continue
    n = p*q
    phi = (p-1)*(q-1)

    d = randint(2, int(n**(1/4)//3))
    if gcd(d, phi) == 1:
        e = pow(d, -1, phi)
        break

# --- PoC - Wiener Attack ---
d_recovered = wiener_attack(e, n)
assert(d == d_recovered)


