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

- **rsa/** – Attacks on RSA cryptosystem
  - `batch_gcd_attack.py` – Exploit shared factors among multiple moduli
  - `blinding.py` – RSA blinding demonstration
  - `common_modulus_attack.py` – Exploit same modulus with different exponents
  - `coopersmith_short_pad_attack.py` – Coopersmith attack on small padding
  - `franklin_reiter.py` – Franklin-Reiter related-message attack
  - `hastad_broadcast_attack.py` – Hastad’s broadcast attack
  - `small_exponent_attack.py` – Attack when exponent is small

