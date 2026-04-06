#!/usr/bin/env python3

from sage.all import *


class VulnerableDLP():
    def __init__(self):
        self.n = randint(2, 10)
        self.p = random_prime(2**16)
        self.G = GL(self.n, GF(self.p)).gens()[-1]
        self.x = randint(2, self.G.order() - 1)
        self.B = (self.G.matrix())**self.x

    def get_public_parameters(self):
        return self.n, self.p, self.G, self.B

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

    residues = []
    moduli = []
    for K, r, mu in eigen:
        Q = generate_matrix(K, mu)
        D = Q**(-1)*B*Q
        d = D[0][0]

        x = d.log(r)
        residues.append(x)
        moduli.append(r.multiplicative_order())
    
    x = crt(residues, moduli)
    return x

def main():
    # --- Setup ---
    vuln_dlp = VulnerableDLP()
    n, p, G, B = vuln_dlp.get_public_parameters()
    print(n, p)
    # --- PoC - Discrete logarithm in GL(n, p) ---
    x = discrete_log_GL(n, p, G, B)
    assert(x == vuln_dlp.x)

if __name__ == "__main__":
    main()
