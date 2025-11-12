# Kriptix

**Kriptix** — The Post-Quantum Cryptography SDK for Zig

Secure the future of blockchain, cloud, and distributed systems with lattice-based and hybrid cryptography written natively in Zig 0.16.0-dev.

## Overview

Kriptix provides a comprehensive suite of post-quantum cryptographic primitives designed for the Ghostchain blockchain and other security-critical applications. Built with performance, safety, and modularity in mind.

## Features

- **Post-Quantum Algorithms**: Kyber (KEM), Dilithium (Signatures), SPHINCS+ (Signatures)
- **Hybrid Cryptography**: PQC + Classical combinations for transition security
- **Zig Native**: Zero-cost abstractions with compile-time safety
- **Multi-Target**: Library, FFI bindings, and WebAssembly support
- **Deterministic Keygen**: Seed-driven derivations for PQC, Ed25519, and hybrid bundles
- **Extensible**: Modular design for easy integration

## Quick Start

```zig
const kriptix = @import("kriptix");

// Initialize the library
kriptix.init();
defer kriptix.deinit();

// Generate a Kyber keypair
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();

const keypair = try kriptix.generate_keypair(allocator, .Kyber512);
defer allocator.free(keypair.public_key);
defer allocator.free(keypair.private_key);

// Use for encryption/decryption
const message = "Hello, Quantum World!";
const ciphertext = try kriptix.encrypt(allocator, keypair.public_key, message, .Kyber512);
defer allocator.free(ciphertext.data);

const decrypted = try kriptix.decrypt(allocator, keypair.private_key, ciphertext);
defer allocator.free(decrypted);

// Deterministic seed-based key generation
const seed = "ghostchain::demo-seed";
const deterministic = try kriptix.generate_keypair_deterministic(allocator, .Kyber512, seed);
defer allocator.free(deterministic.public_key);
defer allocator.free(deterministic.private_key);
```

## Building

```bash
# Build the library
zig build

# Build with FFI support
zig build --enable-ffibuild

# Build WebAssembly
zig build wasm

# Run tests
zig build test

# Run the CLI demo
zig build run

# Run benchmarks (enable benchmark feature)
zig build -Dbenchmarks=true bench
# → collects Kyber/Dilithium performance plus deterministic seed verification output
```

### Build Options

| Flag | Default | Description |
| --- | --- | --- |
| `-Dml-kem` | `false` | Enable ML-KEM (Kyber) key encapsulation |
| `-Dkyber` | `false` | Enable legacy Kyber module (pre-FIPS) |
| `-Dml-dsa` | `false` | Enable ML-DSA (Dilithium) signatures |
| `-Ddilithium` | `false` | Enable legacy Dilithium module (pre-FIPS) |
| `-Dslh-dsa` | `false` | Enable SLH-DSA (FIPS 205) signatures |
| `-Dsphincs` | `false` | Enable SLH-DSA (SPHINCS+) signatures |
| `-Dhybrid` | `false` | Build hybrid PQC + classical manager |
| `-Dblockchain` | `false` | Include blockchain integration modules |
| `-Dinterop` | `false` | Compile interoperability utilities |
| `-Dbenchmarks` | `false` | Compile benchmark harness and enable `zig build bench` |
| `-Dtests` | `false` | Compile unit/integration tests |
| `-Dexamples` | `false` | Compile example binaries |
| `-Dall-features` | `false` | Convenience toggle that enables every feature flag |
| `-Dminimal` | `false` | Strip optional modules for the smallest footprint |
| `-Dfast-build` | `false` | Prefer faster builds over peak runtime performance |

Example Ghostchain build:

```bash
zig build -Dml-kem=true -Dml-dsa=true -Dhybrid=true -Dtests=true
```

## Project Structure

- `src/root.zig` - Main library API
- `src/rng.zig` - Secure random number generation
- `src/hash.zig` - Cryptographic hash functions
- `src/pq/` - Post-quantum algorithm implementations
  - `kyber.zig` - Kyber KEM
  - `dilithium.zig` - Dilithium signatures
  - `sphincs.zig` - SPHINCS+ signatures
  - `hybrid.zig` - Hybrid schemes
- `src/hybrid/manager.zig` - Deterministic hybrid manager (PQC + classical)
- `src/ghostchain.zig` - Ghostchain integration helpers with seeded keygen
- `examples/benchmark.zig` - Benchmark harness entry point

## Dependencies

Kriptix is self-contained. All cryptographic primitives build directly on Zig's standard library and local modules—no external packages required.

## Roadmap

- [ ] Complete PQ algorithm implementations
- [ ] NIST compliance and test vectors
- [ ] Hardware acceleration support
- [ ] Formal verification
- [ ] Integration with Ghostchain

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please see the TODO.md for current development priorities.
