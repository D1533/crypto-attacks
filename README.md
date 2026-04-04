## Cryptography Attacks Repository

A collection of cryptographic attack implementations and proofs-of-concept in SageMath and Python

## Requirements 
- SageMath, Python
- PyCryptodome

## Structure and Contents

- **diffie-hellman/** – Attacks on Diffie-Hellman key exchange
  - `discrete_log_GL.py` – Solve discrete log in GL(p, n)
  - `pohlig_hellman.py` – Pohlig-Hellman attack for smooth-order groups
  - `small_subgroup_attack_poc.py` – Solve discrete log trivially when the order of the group is small

- **ecc/** – Attacks on elliptic curve cryptography
  - `ecdsa_biased_nonce_attack.py` – Recover private key from biased nonces
  - `ecdsa_nonce_reuse.py` – Exploit nonce reuse in ECDSA
  - `mov_attack.py` – MOV attack for pairing-based curves
  - `smart_attack.py` – Smart attack on weak curves

- **lwe/** – Attacks on lattice-based schemes
  - `arora_ge.py` – Arora-Ge algorithm for LWE

## RSA Attacks
- [Batch GCD Attack](rsa/batch_gcd_attack.py)
- [Blinding Demo](rsa/blinding.py)
- [Common Modulus Attack](rsa/common_modulus_attack.py)
- [Coopersmith Short Pad Attack](rsa/coopersmith_short_pad_attack.py)
- [Franklin-Reiter Attack](rsa/franklin_reiter.py)
- [Hastad Broadcast Attack](rsa/hastad_broadcast_attack.py)
- [Small Exponent Attack](rsa/small_exponent_attack.py)
