//! ML-KEM (FIPS 203) - Module Lattice-Based Key Encapsulation Mechanism
//! Standalone module for Ghostchain compatibility

const std = @import("std");
const build_options = @import("build_options");

// Only compile if enabled
comptime {
    if (!build_options.ml_kem_enabled) {
        @compileError("ML-KEM not enabled in build configuration. Use -Dml-kem=true");
    }
}

// Import existing Kyber implementation (ML-KEM is standardized Kyber)
const kyber_impl = @import("pq/kyber.zig");

// ML-KEM is the standardized version of Kyber
pub const MlKem512 = kyber_impl.Kyber512;
pub const MlKem768 = kyber_impl.Kyber768;
pub const MlKem1024 = kyber_impl.Kyber1024;

// Alias for compatibility
pub const Kyber512 = MlKem512;
pub const Kyber768 = MlKem768;
pub const Kyber1024 = MlKem1024;

// Common operations
pub fn keygen(allocator: std.mem.Allocator, comptime params: type) !kyber_impl.KeyPair {
    return params.keygen(allocator);
}

pub fn encaps(allocator: std.mem.Allocator, public_key: []const u8, comptime params: type) !kyber_impl.EncapsResult {
    return params.encaps(allocator, public_key);
}

pub fn decaps(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: []const u8, comptime params: type) ![]u8 {
    return params.decaps(allocator, private_key, ciphertext);
}

// Types
pub const PublicKey = kyber_impl.PublicKey;
pub const PrivateKey = kyber_impl.PrivateKey;
pub const KeyPair = kyber_impl.KeyPair;
pub const Ciphertext = kyber_impl.Ciphertext;
pub const SharedSecret = kyber_impl.SharedSecret;
pub const EncapsResult = kyber_impl.EncapsResult;

// Error types
pub const KyberError = kyber_impl.KyberError;
pub const MlKemError = KyberError; // Alias

// Recommended parameter set for Ghostchain
pub const Recommended = MlKem768;

// Test interface for fast unit tests
test "ml-kem module availability" {
    const testing = std.testing;
    try testing.expect(@TypeOf(MlKem768) != void);
    try testing.expect(@TypeOf(keygen) != void);
}
