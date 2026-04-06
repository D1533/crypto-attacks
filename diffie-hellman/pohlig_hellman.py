#!/usr/bin/env python3

from sage.all import *

class VulnerableDLP:
    def __init__(self):
        self.p = self.get_smooth_prime()
        self.g = primitive_root(self.p)
        self.x = randint(2, self.p - 1)
        self.h = pow(self.g, self.x, self.p)

    def get_smooth_prime(self, primes_max_bit_size = 15):
        while True:
            p = 1
            for i in range(randint(2,10)):
                p_i = random_prime(2**primes_max_bit_size)
                e_i = randint(1, 5)
                p *= p_i**e_i
            
            p += 1
            if is_prime(p):
                return p
    def get_public_parameters(self):
        return self.p, self.g, self.h

def pohlig_hellman_attack(h, g, p, max_bit_size):
    factors = factor(p-1)

    residues = []
    moduli = []
    prod = 1
    for p_i, e_i in factors:
        prod *= p_i**e_i
        if int(prod).bit_length() > max_bit_size:
            break
        
        g_i = pow(g, (p-1)//(p_i**e_i), p)
        h_i = pow(h, (p-1)//(p_i**e_i), p)
        x_i = discrete_log(h_i, g_i, ord=p_i**e_i)
        residues.append(x_i)
        moduli.append(p_i**e_i)

    x = crt(residues, moduli)
    
    return x

def main():
    # --- Setup ---
    vuln_dlp = VulnerableDLP()
    p, g, h = vuln_dlp.get_public_parameters()

    # --- PoC - Pohlig Hellman Attack ---
    x = pohlig_hellman_attack(h, g, p, 2**15)
    assert(x == vuln_dlp.x)


if __name__ == "__main__":
    main()
