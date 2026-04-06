#!/usr/bin/env python3

from sage.all import *


class VulnerableDLP:
    def __init__(self):
        self.p = random_prime(2**128)
        self.g = self.get_small_order_element()
        self.x = randint(2, self.g.multiplicative_order() - 1)
        self.h = pow(self.g, self.x, self.p)

    def get_small_order_element(self):
        g = primitive_root(self.p)
        factors = factor(self.p-1)
        for q, e in factors[::-1]:
            if q < 2**20:
                g = pow(g, (self.p-1)//q, self.p)
                break
        return g

    def get_public_parameters(self):
        return self.p, self.g, self.h


def main():
    # --- Setup ---
    vuln_dlp = VulnerableDLP()
    p, g, h = vuln_dlp.get_public_parameters()

    # --- PoC - Small Subgroup Attack
    x = h.log(g)
    assert(x == vuln_dlp.x)

if __name__ == "__main__":
    main()
