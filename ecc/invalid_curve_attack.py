#!/usr/bin/env python3

from sage.all import *

class Oracle:
    def __init__(self):
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.a = 0 
        self.b = 7
        self.E = EllipticCurve(GF(self.p), [self.a,self. b])
        self.G = self.E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        self.d = randint(2, 2**128)

    def get_public_parameters(self):
        Q = self.d*self.G
        return self.E, self.G, Q
    
    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 == (-y2 % self.p):
            return None  
        if P != Q:
            m = (y2 - y1) * pow(x2 - x1,-1,self.p) % self.p
        else:
            m = (3 * x1 * x1) * pow(2 * y1,-1, self.p) % self.p

        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def double_and_add(self, k, P):
        result = None
        addend = P
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    def encrypt(self, P):
        return self.double_and_add(self.d, P)

def invalid_curve_attack(oracle, E, Q, G, key_size):
    remainders = []
    moduli = []
    def generate_invalid_curve(E, moduli):
        a = E.a4()
        p = E.base_field().order()
        while True:
            b = randint(0, p - 1)
            E0 = EllipticCurve(GF(p), [a, b])
            G0 = E0.gen(0)
            n = G0.order()
            factors = factor(n, limit=2**30)
            orders = []
            for q, e in factors:
                if q**e <= 2**30 and all(gcd(q, mod) == 1 for mod in moduli):
                    orders.append(q**e)
            if len(orders):
                return E0, G0, n, orders
        
    while True:
        E0, G0, n, orders = generate_invalid_curve(E, moduli)
        for order in orders:
            G = (n // order) * G0
            Q = oracle.encrypt(G.xy())
            try:
                d = discrete_log(E0(Q), G, ord=order, operation="+")
                remainders.append(d)
                moduli.append(order)
                d = crt(remainders, moduli)
                if prod(moduli) >= key_size:
                    return d
            except:
                pass
            
def main():
    # -- Setup ---
    oracle = Oracle()
    E, G, Q = oracle.get_public_parameters()
    
    # --- PoC - Invalid Curve Attack ---
    d = invalid_curve_attack(oracle, E, Q, G, 2**128)
    assert(d == oracle.d)

if __name__ == "__main__":
    main()


