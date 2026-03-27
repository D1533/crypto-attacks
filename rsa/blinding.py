#!/usr/bin/env python3

from math import gcd
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from random import randint

# --- Setup ---
p = getPrime(512)
q = getPrime(512)
N = p*q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))

def sign(m):
    if m == b"admin":
        return None
    return pow(bytes_to_long(m), d, N)


S_admin = pow(bytes_to_long(b"admin"), d, N)


# --- PoC - Blinding Attack --- 
m = bytes_to_long(b"admin")
r = randint(2, N-1)
# Ensure we can take the inverse of r mod N later
while gcd(r, N) != 1:
    r = randint(2, N-1)

m_blinded = long_to_bytes((pow(r, e, N) * m ) % N)
S_blinded = sign(m_blinded)
S_m = (pow(r,-1,N)*S_blinded ) % N

assert(S_m == S_admin)
assert(long_to_bytes(pow(S_m, e, N)) == b"admin")


