## Cryptography Attacks

A collection of cryptographic attack implementations and proofs-of-concept in SageMath and Python.

## Requirements 
- SageMath, Python
- PyCryptodome

## Structure and Contents

### Diffie-Hellman Attacks
- [Discrete log in GL(p, n)](diffie-hellman/discrete_log_GL.py) – Solve discrete log in GL(p, n)
- [Pohlig-Hellman Attack](diffie-hellman/pohlig_hellman.py) – Solve discrete log when the group order is smooth (factorable into small primes).
- [Small Subgroup Attack](diffie-hellman/small_subgroup_attack_poc.py) – Solve discrete log trivially when the order of the group is small

### Elliptic Curve Attacks
- [ECDSA Biased Nonces Attack](ecc/ecdsa_biased_nonce_attack.py) –  Recover private key when nonces are partially predictable (lattice attack).
- [ECDSA Nonce Reuse Attack](ecc/ecdsa_nonce_reuse.py) – Recover private key when the same nonce is reused in two signatures.
- [MOV Attack](mov_attack.py) –  Reduce elliptic curve discrete log to finite field discrete log using weil-pairing.
- [Smart Attack](ecc/smart_attack.py) – Solve discrete log on anomalous curves (when #E = p).

### LWE Attacks
- [Arora-Ge](lwe/arora_ge.py) - Algebraic attack on LWE by solving polynomial systems (works for small noise).

### RSA Attacks
- [Batch GCD Attack](rsa/batch_gcd_attack.py) - Factor multiple RSA moduli sharing primes.
- [Blinding Attack](rsa/blinding.py) - Forge a valid signature for a prohibited message using a signing oracle.
- [Common Modulus Attack](rsa/common_modulus_attack.py) -   Recover plaintext when same modulus is used with coprime exponents.
- [Coopersmith Short Pad Attack](rsa/coopersmith_short_pad_attack.py) -  Recover message when padding is too short (small unknown part).
- [Franklin-Reiter Attack](rsa/franklin_reiter.py) -   Recover messages that are linearly related and encrypted with same modulus.
- [Hastad Broadcast Attack](rsa/hastad_broadcast_attack.py) - Recover plaintext sent to multiple recipients with a small exponent.
- [Small Exponent Attack](rsa/small_exponent_attack.py) - Recover plaintext directly when exponent is small.
