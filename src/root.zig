//! Kriptix - Post-Quantum Cryptography Library for Zig
//! Secure the future with lattice-based and hybrid cryptography.

// Optional: zcrypto for classical cryptography primitives
// pub const zcrypto = @import("zcrypto");

const std = @import("std");

// Re-export core modules
pub const rng = @import("rng.zig");
pub const hash = @import("hash.zig");
pub const pq = @import("pq/root.zig");
pub const blockchain = @import("blockchain/root.zig");

// Algorithm enumerations
pub const Algorithm = enum {
    // Post-Quantum Key Encapsulation Mechanisms
    Kyber512,
    Kyber768,
    Kyber1024,

    // Post-Quantum Signatures
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Sphincs128f,
    Sphincs128s,
    Sphincs192f,
    Sphincs192s,
    Sphincs256f,
    Sphincs256s,

    // Hybrid schemes (PQC + Classical)
    Kyber512_AES256,
    Kyber768_AES256,
    Kyber1024_AES256,
};

// Key structures
pub const KeyPair = struct {
    public_key: []u8,
    private_key: []u8,
    algorithm: Algorithm,
};

pub const Ciphertext = struct {
    data: []u8,
    algorithm: Algorithm,
};

pub const Signature = struct {
    data: []u8,
    algorithm: Algorithm,
};

// Core API functions
pub fn generate_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.generate_keypair(allocator, algo),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.generate_keypair(allocator, algo),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => pq.sphincs.generate_keypair(allocator, algo),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.generate_hybrid_kem_keypair(allocator, algo),
    };
}

pub fn encrypt(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !Ciphertext {
    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.encrypt(allocator, public_key, message, algo),
        .Dilithium2, .Dilithium3, .Dilithium5 => @panic("Dilithium is signature only"),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => @panic("SPHINCS+ is signature only"),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.encrypt_hybrid(allocator, public_key, message, algo),
    };
}

pub fn decrypt(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: Ciphertext) ![]u8 {
    return switch (ciphertext.algorithm) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.decrypt(allocator, private_key, ciphertext.data),
        .Dilithium2, .Dilithium3, .Dilithium5 => @panic("Dilithium is signature only"),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => @panic("SPHINCS+ is signature only"),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.decrypt_hybrid(allocator, private_key, ciphertext),
    };
}

pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, algo: Algorithm) !Signature {
    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => @panic("Kyber is KEM only"),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.sign(allocator, private_key, message, algo),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => pq.sphincs.sign(allocator, private_key, message, algo),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => @panic("Hybrid schemes are KEM only"),
    };
}

pub fn verify(public_key: []const u8, message: []const u8, signature: Signature) !bool {
    return switch (signature.algorithm) {
        .Kyber512, .Kyber768, .Kyber1024 => @panic("Kyber is KEM only"),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.verify(public_key, message, signature.data),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => pq.sphincs.verify(public_key, message, signature.data),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => @panic("Hybrid schemes are KEM only"),
    };
}

// Utility functions
pub fn init() void {
    // Initialize any global state if needed
    rng.init();
}

pub fn deinit() void {
    // Clean up global state
    rng.deinit();
}

test "basic functionality" {
    std.testing.refAllDecls(@This());
}
