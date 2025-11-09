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

## Dependencies

- `zcrypto` - Classical cryptography primitives
- `zsync` - Async I/O library

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
