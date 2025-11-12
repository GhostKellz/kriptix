# Kriptix API Reference

## Overview

Kriptix provides a unified API for post-quantum cryptographic operations. All functions follow a consistent interface pattern with algorithm parameterization.

## Core Types

### Algorithm

```zig
pub const Algorithm = enum {
    // Key Encapsulation Mechanisms
    Kyber512,
    Kyber768,
    Kyber1024,

    // Digital Signatures
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Sphincs128f,
    Sphincs128s,
    Sphincs192f,
    Sphincs192s,
    Sphincs256f,
    Sphincs256s,

    // Hybrid Schemes (PQC + Classical)
    Kyber512_AES256,
    Kyber768_AES256,
    Kyber1024_AES256,
};
```

### KeyPair

```zig
pub const KeyPair = struct {
    public_key: []u8,
    private_key: []u8,
    algorithm: Algorithm,
};
```

### Ciphertext

```zig
pub const Ciphertext = struct {
    data: []u8,
    algorithm: Algorithm,
};
```

### Signature

```zig
pub const Signature = struct {
    data: []u8,
    algorithm: Algorithm,
};
```

## Core API Functions

### Initialization

```zig
pub fn init() void
pub fn deinit() void
```

Initialize and cleanup global library state. Call `init()` once at startup and `deinit()` at shutdown.

### Key Generation

```zig
pub fn generate_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair
pub fn generate_keypair_deterministic(allocator: std.mem.Allocator, algo: Algorithm, seed: []const u8) !KeyPair
```

Generate a new keypair for the specified algorithm.

**Parameters:**
- `allocator`: Memory allocator for key storage
- `algo`: Cryptographic algorithm to use

**Returns:** New `KeyPair` with algorithm-specific key sizes

**Example:**
```zig
const keypair = try kriptix.generate_keypair(allocator, .Kyber512);
defer allocator.free(keypair.public_key);
defer allocator.free(keypair.private_key);
```

Deterministic key generation derives the same keypair from the same seed (supported for Kyber and Dilithium families plus classical Ed25519 backing keys used by hybrid helpers):

```zig
const seed = "ghostchain::validator-001";
const deterministic = try kriptix.generate_keypair_deterministic(allocator, .Kyber768, seed);
defer allocator.free(deterministic.public_key);
defer allocator.free(deterministic.private_key);
```

> Returns `error.UnsupportedAlgorithm` when deterministic derivation is not available for the requested algorithm (for example SPHINCS+ or hybrid wrapper identifiers).

### Key Encapsulation

```zig
pub fn encrypt(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !Ciphertext
```

Encrypt a message using a public key (KEM operation).

**Parameters:**
- `allocator`: Memory allocator for ciphertext
- `public_key`: Recipient's public key
- `message`: Message to encrypt
- `algo`: Algorithm (must be KEM type)

**Returns:** `Ciphertext` containing encrypted data

### Key Decapsulation

```zig
pub fn decrypt(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: Ciphertext) ![]u8
```

Decrypt a ciphertext using a private key (KEM operation).

**Parameters:**
- `allocator`: Memory allocator for plaintext
- `private_key`: Recipient's private key
- `ciphertext`: Encrypted data with algorithm info

**Returns:** Decrypted plaintext

### Digital Signing

```zig
pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, algo: Algorithm) !Signature
```

Create a digital signature for a message.

**Parameters:**
- `allocator`: Memory allocator for signature
- `private_key`: Signer's private key
- `message`: Message to sign
- `algo`: Signature algorithm

**Returns:** `Signature` containing signature data

### Signature Verification

```zig
pub fn verify(public_key: []const u8, message: []const u8, signature: Signature) !bool
```

Verify a digital signature against a message.

**Parameters:**
- `public_key`: Signer's public key
- `message`: Original message
- `signature`: Signature to verify

**Returns:** `true` if signature is valid, `false` otherwise

## Algorithm Details

### Kyber (ML-KEM)

**Security Levels:**
- `Kyber512`: ~AES-128 equivalent security
- `Kyber768`: ~AES-192 equivalent security
- `Kyber1024`: ~AES-256 equivalent security

**Key Sizes:**
- Public key: 800/1184/1568 bytes
- Private key: 1632/2400/3168 bytes
- Ciphertext: 768/1088/1568 bytes

**Operations:** KEM only (no signatures)

### Dilithium (ML-DSA)

**Security Levels:**
- `Dilithium2`: ~AES-128 equivalent
- `Dilithium3`: ~AES-192 equivalent
- `Dilithium5`: ~AES-256 equivalent

**Key Sizes:**
- Public key: 1312/1952/2592 bytes
- Private key: 2528/4000/4888 bytes
- Signature: 2420/3293/4595 bytes

**Operations:** Signatures only

### SPHINCS+ (SLH-DSA)

**Security Levels:**
- `Sphincs128f/s`: ~AES-128 equivalent (fast/small variants)
- `Sphincs192f/s`: ~AES-192 equivalent
- `Sphincs256f/s`: ~AES-256 equivalent

**Key Sizes:**
- Public key: 32 bytes
- Private key: 64 bytes
- Signature: 7856-49856 bytes (varies by parameter set)

**Operations:** Signatures only (stateless hash-based)

## Error Handling

All functions return `!T` (error union types). Common errors:
- `OutOfMemory`: Allocation failure
- `InvalidAlgorithm`: Unsupported algorithm for operation
- `InvalidKey`: Malformed key data
- `VerificationFailed`: Signature verification failed

## Memory Management

- All functions that return allocated data require the caller to free it
- Use the same allocator passed to the function for cleanup
- Keys and ciphertexts contain algorithm metadata for proper handling

## Thread Safety

- Library functions are not thread-safe by default
- Use external synchronization for concurrent access
- RNG state is global and should be protected in multi-threaded environments

## Performance Considerations

- PQ algorithms are computationally intensive
- Key generation and signing are the most expensive operations
- Consider caching public keys for repeated encryption operations
- Hybrid schemes may offer better performance during transition periods

## Benchmark Harness

- Enable the suite with `zig build -Dbenchmarks=true bench`
- Measures Kyber KEM, Dilithium signing, and SPHINCS+ signature performance
- Includes deterministic Kyber/Dilithium keygen runs that verify seeded reproducibility alongside timing data
