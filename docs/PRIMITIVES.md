# Post-Quantum Primitives

This document describes the post-quantum cryptographic primitives implemented in Kriptix.

## Overview

Kriptix implements NIST PQC Round 3 finalists and candidates, focusing on lattice-based cryptography which provides strong security guarantees against quantum attacks.

## Key Encapsulation Mechanisms (KEMs)

### Kyber (ML-KEM)

**Status:** Placeholder implementation (needs real ML-KEM)

**Description:**
Kyber is a lattice-based key encapsulation mechanism that enables secure key exchange over insecure channels. It uses the Module-LWE problem for security.

**Mathematical Foundation:**
- Based on Module Learning With Errors (M-LWE)
- Uses polynomial rings over finite fields
- Security reducible to worst-case lattice problems

**Parameters:**
```
Kyber512: n=256, k=2, q=3329, η₁=3, η₂=2, dᵤ=10, dᵥ=4
Kyber768: n=256, k=3, q=3329, η₁=2, η₂=2, dᵤ=10, dᵥ=4
Kyber1024: n=256, k=4, q=3329, η₁=2, η₂=2, dᵤ=11, dᵥ=5
```

**Key Generation:**
1. Sample secret vector s ∈ ℤ_q^{k×n}
2. Sample error vector e ∈ ℤ_q^{k×n}
3. Compute public key t = A·s + e (mod q)
4. Encode (t, ρ) where ρ is seed for A

**Encapsulation:**
1. Sample random m ∈ ℤ_q^n
2. Compute c₁ = Compress_q(t⊤·r + e₁, dᵤ)
3. Compute c₂ = Compress_q(m + ⌈q/2⌉·(t⊤·r + e₁), dᵥ)
4. Shared secret = SHAKE256(m || (t⊤·r + e₁))

**Decapsulation:**
1. Recover r from c₁ and private key
2. Recover m from c₂ and r
3. Verify ciphertext validity
4. Return shared secret

## Digital Signature Schemes

### Dilithium (ML-DSA)

**Status:** Placeholder implementation (needs real ML-DSA)

**Description:**
Dilithium is a lattice-based digital signature scheme providing EUF-CMA security. It uses the Module-LWE and Module-SIS problems.

**Mathematical Foundation:**
- Based on Fiat-Shamir with Aborts
- Uses rejection sampling for Gaussian-like distributions
- Security based on M-LWE and M-SIS hardness

**Parameters:**
```
Dilithium2: n=256, k=4, l=4, η=2, γ₁=2^17, γ₂=2^18, τ=39, β=78
Dilithium3: n=256, k=6, l=5, η=4, γ₁=2^19, γ₂=2^19, τ=49, β=196
Dilithium5: n=256, k=8, l=7, η=2, γ₁=2^19, γ₂=2^20, τ=60, β=120
```

**Key Generation:**
1. Sample secret vectors s₁ ∈ ℤ_q^l, s₂ ∈ ℤ_q^k
2. Sample error vectors e ∈ ℤ_q^k
3. Compute t = A·s₁ + s₂ (mod q)
4. Encode public key (ρ, t₁) and private key (ρ, K, tr, s₁, s₂, t₀)

**Signing:**
1. Hash message to obtain μ
2. Generate commitment c through rejection sampling
3. Compute responses z = y - c·s₁, w₁ = w - c·s₂
4. Apply rejection sampling to ensure bounds
5. Return signature (c, z, w₁)

**Verification:**
1. Recompute commitment from signature
2. Verify z and w₁ are in bounds
3. Check c = H(μ || w₁')
4. Accept if all checks pass

### SPHINCS+ (SLH-DSA)

**Status:** Placeholder implementation (needs real SLH-DSA)

**Description:**
SPHINCS+ is a stateless hash-based signature scheme providing EUF-CMA security. It uses only hash functions, making it quantum-resistant by design.

**Mathematical Foundation:**
- Based on XMSS and HORST constructions
- Uses few-time signatures (FTS) with Merkle trees
- Security based on hash function properties

**Parameters:**
```
SPHINCS+-128f: n=16, h=66, d=22, w=16, τ=2^16
SPHINCS+-128s: n=16, h=63, d=7, w=16, τ=2^16
SPHINCS+-192f: n=24, h=66, d=22, w=16, τ=2^18
SPHINCS+-192s: n=24, h=63, d=7, w=16, τ=2^18
SPHINCS+-256f: n=32, h=68, d=17, w=16, τ=2^20
SPHINCS+-256s: n=32, h=64, d=8, w=16, τ=2^20
```

**Key Generation:**
1. Generate random secret seed SK.seed
2. Generate random public seed PK.seed
3. Compute root of Merkle tree over all WOTS+ public keys
4. Public key = (PK.seed, PK.root)

**Signing:**
1. Select random index idx
2. Compute WOTS+ signature of message
3. Compute authentication path for idx
4. Return signature (idx, R, SIG_WOTS, AUTH)

**Verification:**
1. Reconstruct WOTS+ public key from signature
2. Verify WOTS+ signature
3. Verify authentication path
4. Accept if all verifications pass

## Hybrid Schemes

### PQC + Classical Combinations

**Status:** Not implemented

**Description:**
Hybrid schemes combine post-quantum and classical cryptography to provide security during the transition period. They offer the best of both worlds: quantum resistance from PQC and performance from classical algorithms.

**Proposed Schemes:**
- Kyber512 + AES-256: PQ KEM + symmetric encryption
- Kyber768 + AES-256: Higher security PQ KEM + symmetric
- Kyber1024 + AES-256: Maximum security PQ KEM + symmetric

**Construction:**
1. Use PQ KEM to establish shared secret
2. Derive symmetric keys from shared secret
3. Use classical symmetric crypto for bulk encryption

## Security Considerations

### Quantum Security

All implemented primitives are believed to be secure against quantum attacks:
- Kyber: Security based on M-LWE problem
- Dilithium: Security based on M-LWE and M-SIS
- SPHINCS+: Security based on hash function properties

### Classical Security

Primitives maintain security against classical attacks:
- Kyber: IND-CCA2 secure KEM
- Dilithium: EUF-CMA secure signatures
- SPHINCS+: EUF-CMA secure signatures

### Implementation Security

- Constant-time operations where possible
- No secret-dependent branches or memory access
- Secure memory wiping after use
- Input validation and error handling

## Performance Characteristics

### Operation Costs (estimated)

| Algorithm | KeyGen | Enc/Sign | Dec/Verify | Key Size |
|-----------|--------|----------|------------|----------|
| Kyber512  | ~1ms   | ~0.1ms   | ~0.1ms     | 2.4KB    |
| Kyber768  | ~2ms   | ~0.2ms   | ~0.2ms     | 3.6KB    |
| Kyber1024 | ~3ms   | ~0.3ms   | ~0.3ms     | 4.8KB    |
| Dilithium2| ~1ms   | ~2ms     | ~1ms       | 3.8KB    |
| Dilithium3| ~2ms   | ~3ms     | ~2ms       | 6.0KB    |
| Dilithium5| ~3ms   | ~5ms     | ~3ms       | 7.5KB    |
| SPHINCS+  | ~0.1ms | ~10ms    | ~1ms       | 96B      |

*Timings are approximate and depend on hardware*

## References

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [SPHINCS+ Specification](https://sphincs.org/)
- [Open Quantum Safe](https://openquantumsafe.org/)