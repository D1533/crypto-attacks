#!/usr/bin/env python3

from sage.all import *


class VulnerableEllipticCurve:
    def __init__(self):
        self.p = self.get_prime(2**64)
        self.E = EllipticCurve(GF(self.p), [-1, 0])
        self.G = self.get_subgroup_generator()
        self.x = randint(2, self.G.order() - 1)
        self.P = self.x*self.G
    
    def get_prime(self, size):
        p = random_prime(size)
        while p % 4 != 3:
            p = random_prime(size)
        return p

    def get_subgroup_generator(self):
        G = self.E.gen(0)
        n = G.order()
        q = factor(G.order())[-1][0]
        return (n // q)*G
    
    def get_public_parameters(self):
        return self.E, self.G, self.P

def MOV_attack(E, G, P):
    n = G.order()
    p = E.base_ring().order()
    
    def get_embedding_degree(n, p):
        k = 1
        while p ** k % n != 1:
            k += 1
        return k

    k = get_embedding_degree(n, p)

    EK = E.base_extend(GF(p**k)) 
    PK = EK(P)
    GK = EK(G)
    
    while True:
        Q = EK.random_point()
        m = Q.order()
        Q = (m // gcd(m, n))*Q
        g = GK.weil_pairing(Q, n)
        if g.multiplicative_order() == n:
            break
    
    h = PK.weil_pairing(Q, n)
    l = h.log(g)

    return int(l)


def main():
    # --- Setup ---
    vuln_ecc = VulnerableEllipticCurve()
    E, G, P = vuln_ecc.get_public_parameters()

    # --- PoC - MOV Attack --- 
    x = MOV_attack(E, G, P)
    assert(x == vuln_ecc.x)


if __name__ == "__main__":
    main()

