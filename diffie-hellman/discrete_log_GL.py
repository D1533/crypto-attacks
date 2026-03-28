#!/usr/bin/env python3

from sage.all import *


def generate_matrix(K, first_col): 
    n = len(first_col)
    
    while True:
        cols = [first_col]
        for _ in range(n-1):
            col = vector([K.random_element() for _ in range(n)])
            cols.append(col)
        
        M = Matrix(K, cols).transpose()
        
        if M.is_invertible():
            return M

def discrete_log_GL(n, p, G, B):
    R = PolynomialRing(GF(p), 'x')
    x = R.gen()
    p_G = R(G.matrix().charpoly())

    factors = p_G.factor()
    roots = []
    for i, f in enumerate(factors):
        fi = f[0]
        mi = fi.degree()
        K = GF(p**mi, 'x', modulus=fi)
        x = K.gen()
        roots.append([K, fi.roots(K, multiplicities=False)])

    eigen = []
    for K, r in roots:
        G_ = G - r[0]*identity_matrix(K, n)
        eigen.append([K, r[0], G_.right_kernel().basis()[0]])

    b_residues = []
    moduli = []
    for K, r, mu in eigen:
        Q = generate_matrix(K, mu)
        D = Q**(-1)*B*Q
        d = D[0][0]

        b = d.log(r)
        b_residues.append(b)
        moduli.append(r.multiplicative_order())
    
    b = crt(b_residues, moduli)
    return b


# --- Setup ---
p = random_prime(2**16)
n = 5

GLn = GL(n, GF(p))
G = GLn.gens()[-1]
b = randint(2, G.order() - 1)
B = (G.matrix())**b


# --- PoC - Discrete logarithm in GL(n, p) ---
b_recovered = discrete_log_GL(n, p, G, B)
assert(b_recovered == b)


