//! Hybrid Post-Quantum + Classical Cryptography
//! Combines PQC primitives with traditional algorithms for transition security

const std = @import("std");

// Placeholder for hybrid schemes
// TODO: Implement Kyber + AES-256 hybrid KEM

pub const Algorithm = enum {
    Kyber512_AES256,
    Kyber768_AES256,
    Kyber1024_AES256,
};

// TODO: Implement hybrid key generation, encryption, etc.
