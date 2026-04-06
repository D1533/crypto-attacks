#!/usr/bin/env python3

from sage.all import *


def Smart_Attack(E, G, P):
    p = E.base_field().order()
    assert(p == E.order())
    
    F_p = GF(p)
    Eqq = E.change_ring(QQ)
    Eqp = Eqq.change_ring(Qp(p))
    
    def Hensel_lift(E, P, F):
        x, y = map(ZZ, P.xy())
        for p in E.lift_x(x, all=True):
            xx, yy = map(F, p.xy())
            if y == yy:
                return p

    G = p*Hensel_lift(Eqp, G, F_p)
    P = p*Hensel_lift(Eqp, P, F_p)
    G_x, G_y = G.xy()
    P_x, P_y = P.xy()

    return int(F_p( (P_x / P_y) / (G_x / G_y)))

def main():
    # --- Setup ---
    p = 730750818665451459112596905638433048232067471723
    a = 425706413842211054102700238164133538302169176474
    b = 203362936548826936673264444982866339953265530166
    E = EllipticCurve(GF(p), [a, b])
    
    G = E.gen(0)
    x = randint(2, G.order()-1)
    P = x*G
    
    # --- PoC - Smart's Attack ---
    x = Smart_Attack(E, G, P)
    assert(x*G == P)

if __name__ == "__main__":
    main()
