# Technical Documentation: Dilithium Seed Reuse

## The Protocol: ML-DSA-44 (Dilithium-2)
ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum signature scheme standardized by NIST.
It relies on the hardness of finding short vectors in lattices (Module-LWE and Module-SIS problems).

Key generation in Dilithium involves generating a 32-byte seed $\rho$ (rho) and a 64-byte seed $\sigma$ (sigma/encoding-seed).
These seeds are expanded using SHAKE-256 (an XOF - Extendable Output Function) to generate the matrix $A$ and the secret vectors $s_1, s_2$.

$$
(A, s_1, s_2) \leftarrow \text{Expand}( \rho, \sigma )
$$

Crucially, this process is **deterministic**. Given the same initial seeds, the algorithms `ExpandA` and `ExpandS` will produce the exact same lattice structures and secret vectors.

## The Vulnerability: Seed Collision
In a secure system, the initial seeds are drawn from a high-quality True Random Number Generator (TRNG) or a CSPRNG.
If the RNG fails (e.g., returns a constant, or repeats a state due to a VM snapshot reset, or a "Dimensional Fracture"), the consequences are fatal.

If two parties generate keys using the **same seed**:
1.  They derive the exact same `pk` (Public Key) and `sk` (Private Key).
2.  Party A can sign messages that validly verify against Party B's public key.
3.  Party A can decrypt messages encrypted for Party B (if using a KEM derived similarly).

In this lab, the "Dimensional Rift" causes the RNG to return a static seed (`[0x42; 32]`) when instability is high.
Since both the Admin and the Guest accounts are created during this instability, they collide.
The attacker (Guest) simply needs to re-run the `KeyGen` function with the known static seed to recover the Admin's private key.
