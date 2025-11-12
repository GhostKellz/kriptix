//! Kriptix - Modular Post-Quantum Cryptography Library for Zig
//! Secure the future with lattice-based and hybrid cryptography.

const std = @import("std");
const build_options = @import("build_options");

// Conditional imports based on build configuration
pub const rng = @import("rng.zig");
pub const hash = @import("hash.zig");

// Conditional PQ modules
pub const pq = if (build_options.ml_kem_enabled or
    build_options.kyber_enabled or
    build_options.ml_dsa_enabled or
    build_options.dilithium_enabled or
    build_options.slh_dsa_enabled or
    build_options.sphincs_enabled)
    @import("pq/root.zig")
else
    struct {};

// Modular algorithm imports
pub const modules = struct {
    pub const ml_kem = if (build_options.ml_kem_enabled) @import("modules/ml_kem.zig") else struct {};
    pub const ml_dsa = if (build_options.ml_dsa_enabled) @import("modules/ml_dsa.zig") else struct {};
    pub const slh_dsa = if (build_options.slh_dsa_enabled) @import("modules/slh_dsa.zig") else struct {};
};

// Conditional blockchain support
pub const blockchain = if (build_options.blockchain_enabled)
    @import("blockchain/root.zig")
else
    struct {};

// Conditional interoperability
pub const interop = if (build_options.interop_enabled)
    @import("interop.zig")
else
    struct {};

pub const cross_platform = if (build_options.interop_enabled)
    @import("cross_platform.zig")
else
    struct {};

pub const classical = if (build_options.hybrid_enabled or build_options.blockchain_enabled)
    @import("classic/root.zig")
else
    struct {};

pub const ghostchain = if (build_options.hybrid_enabled)
    @import("ghostchain.zig")
else
    struct {};

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

// Core API functions - only available in non-minimal builds
pub fn generate_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports:\n" ++
            "  const ml_kem = @import(\"kriptix\").modules.ml_kem;\n" ++
            "  const keypair = try ml_kem.MlKem768.keygen(allocator);");
    }

    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.generate_keypair(allocator, algo),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.generate_keypair(allocator, algo),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => pq.sphincs.generate_keypair(allocator, algo),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.generate_hybrid_kem_keypair(allocator, algo),
    };
}

pub fn generate_keypair_deterministic(allocator: std.mem.Allocator, algo: Algorithm, seed: []const u8) !KeyPair {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports.");
    }

    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.generate_keypair_deterministic(allocator, algo, seed),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.generate_keypair_deterministic(allocator, algo, seed),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => error.UnsupportedAlgorithm,
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => error.UnsupportedAlgorithm,
    };
}

pub fn encrypt(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !Ciphertext {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports.");
    }

    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.encrypt(allocator, public_key, message, algo),
        .Dilithium2, .Dilithium3, .Dilithium5 => @panic("Dilithium is signature only"),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => @panic("SPHINCS+ is signature only"),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.encrypt_hybrid(allocator, public_key, message, algo),
    };
}

pub fn decrypt(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: Ciphertext) ![]u8 {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports.");
    }

    return switch (ciphertext.algorithm) {
        .Kyber512, .Kyber768, .Kyber1024 => pq.kyber.decrypt(allocator, private_key, ciphertext.data),
        .Dilithium2, .Dilithium3, .Dilithium5 => @panic("Dilithium is signature only"),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => @panic("SPHINCS+ is signature only"),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => pq.hybrid.decrypt_hybrid(allocator, private_key, ciphertext),
    };
}

pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, algo: Algorithm) !Signature {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports.");
    }

    return switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => @panic("Kyber is KEM only"),
        .Dilithium2, .Dilithium3, .Dilithium5 => pq.dilithium.sign(allocator, private_key, message, algo),
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => pq.sphincs.sign(allocator, private_key, message, algo),
        .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => @panic("Hybrid schemes are KEM only"),
    };
}

pub fn verify(public_key: []const u8, message: []const u8, signature: Signature) !bool {
    if (build_options.minimal_enabled) {
        @compileError("Legacy API not available in minimal build. Use modular imports.");
    }

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
