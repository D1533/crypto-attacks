## Cryptography Attacks Repository

A collection of cryptographic attack implementations and proofs-of-concept in SageMath and Python

## Requirements 
- SageMath, Python
- PyCryptodome

## Structure and Contents

## Diffie-Hellman Attacks
- [Discrete log in GL(p, n)](diffie-hellman/discrete_log_GL.py) – Solve discrete log in GL(p, n)
- [Pohlig-Hellman Attack](ecc/pohlig_hellman.py) – Pohlig-Hellman attack for smooth-order groups
- [Small Subgroup Attack](ecc/small_subgroup_attack_poc.py) – Solve discrete log trivially when the order of the group is small

## Elliptic Curve Attacks
- [ECDSA Biased Nonces Attack](ecc/ecdsa_biased_nonce_attack.py) – Recover private key from biased nonces
- [ECDSA Nonce Reuse Attack](ecc/ecdsa_nonce_reuse.py) – Exploit nonce reuse in ECDSA
- [MOV Attack](mov_attack.py) – MOV attack for pairing-based curves
- [Smart Attack](ecc/smart_attack.py) – Smart attack on weak curves


## LWE Attacks
- [Arora-Ge](lwe/arora_ge.py) 

## RSA Attacks
- [Batch GCD Attack](rsa/batch_gcd_attack.py)
- [Blinding Demo](rsa/blinding.py)
- [Common Modulus Attack](rsa/common_modulus_attack.py)
- [Coopersmith Short Pad Attack](rsa/coopersmith_short_pad_attack.py)
- [Franklin-Reiter Attack](rsa/franklin_reiter.py)
- [Hastad Broadcast Attack](rsa/hastad_broadcast_attack.py)
- [Small Exponent Attack](rsa/small_exponent_attack.py)
