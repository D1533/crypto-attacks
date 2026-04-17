## Crypto Attacks

A collection of cryptographic attack implementations and proofs-of-concept in SageMath and Python.

## Requirements 
- SageMath, Python 3
- PyCryptodome

## Structure and Contents


### AES Attacks
| Attack | Description |
|--------|-------------|
|[CBC Padding Oracle Attack](aes/cbc_padding_oracle_attack.py) | Recover plaintext by modifying ciphertext blocks and using a valid/invalid padding oracle to infer bytes. |
|[CTR Bit Flipping Attack](aes/ctr_bit_flipping_attack.py) | Modify ciphertext to produce a chosen plaintext upon decryption. |
|[ECB Byte At A Time](aes/ecb_byte_at_a_time.py) | Recover secret appended to controlled input using an ECB encryption oracle.|
|[ECB Cut  and Paste Attack](aes/ecb_cut_and_paste_attack.py) | Create and rearrenge encrypted blocks to forge a new message.|

### Diffie-Hellman Attacks
- [Discrete log in GL(n, p)](diffie-hellman/discrete_log_GL.py) – Solve discrete log in GL(n, p).
- [Pohlig-Hellman Attack](diffie-hellman/pohlig_hellman.py) – Solve discrete log when the group order is smooth (factorable into small primes).
- [Small Subgroup Attack](diffie-hellman/small_subgroup_attack_poc.py) – Solve discrete log when the order of the group is small.

### Elliptic Curve Attacks
- [ECDSA Biased Nonces Attack](ecc/ecdsa_biased_nonce_attack.py) –  Recover private key when nonces are partially predictable (lattice attack).
- [ECDSA Nonce Reuse Attack](ecc/ecdsa_nonce_reuse.py) – Recover private key when the same nonce is reused in two signatures.
- [MOV Attack](mov_attack.py) –  Reduce elliptic curve discrete log to finite field discrete log using weil-pairing.
- [Smart Attack](ecc/smart_attack.py) – Solve discrete log on anomalous curves (when #E = p).

### LWE Attacks
- [Arora-Ge](lwe/arora_ge.py) - Algebraic attack on LWE by solving polynomial systems (works for small noise).
- [Least-Squares Attack](lwe/least_squares_attack.py) - Recover secret vector when modulus reduction is not applied.

### RSA Attacks
- [Batch GCD Attack](rsa/batch_gcd_attack.py) - Factor multiple RSA moduli sharing primes.
- [Blinding Attack](rsa/blinding.py) - Forge a valid signature for a prohibited message using a signing oracle.
- [Common Modulus Attack](rsa/common_modulus_attack.py) -   Recover plaintext when same modulus is used with coprime exponents.
- [Coppersmith Short Pad Attack](rsa/coppersmith_short_pad_attack.py) -  Recover message when padding is too short (small unknown part).
- [Franklin-Reiter Attack](rsa/franklin_reiter.py) -   Recover messages that are linearly related and encrypted with same modulus.
- [Hastad Broadcast Attack](rsa/hastad_broadcast_attack.py) - Recover plaintext sent to multiple recipients with a small exponent.
- [Small Exponent Attack](rsa/small_exponent_attack.py) - Recover plaintext directly when exponent is small.
- [Wiener Attack](rsa/wiener_attack.py) - Recover $d$ when $d < \frac{1}{3} N^{1/4}$.

## References
- Boneh, D. (1999). *Twenty Years of Attacks on the RSA Cryptosystem*. 
- Arora, S., & Ge, R. (2011). *New algorithms for learning in presence of errors*.
- Menezes, A. J., & Wu, Y.-H. (1997). *The Discrete Logarithm Problem in GL(n, q)*.
- Pohlig, S. C., & Hellman, M. (1978). *An Improved Algorithm for Computing Logarithms over GF(p).*
- Smart, N. P. (1999). *The Discrete Logarithm Problem on Elliptic Curves of Trace One*.
- Menezes, A., Okamoto, T., & Vanstone, S. (1993). *Reducing Elliptic Curve Logarithms to Logarithms in a Finite Field*.
- Breitner, J., & Heninger, N. (2019). *Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies*.

