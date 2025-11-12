//! ML-DSA (FIPS 204) - Module Lattice-Based Digital Signature Algorithm
//! Standalone module for Ghostchain compatibility

const std = @import("std");

// Import existing Dilithium implementation (ML-DSA is standardized Dilithium)
const dilithium_impl = @import("../pq/dilithium.zig");

// ML-DSA is the standardized version of Dilithium
pub const MlDsa44 = dilithium_impl.Dilithium2;
pub const MlDsa65 = dilithium_impl.Dilithium3;
pub const MlDsa87 = dilithium_impl.Dilithium5;

// Alias for compatibility
pub const Dilithium2 = MlDsa44;
pub const Dilithium3 = MlDsa65;
pub const Dilithium5 = MlDsa87;

// Common operations
pub fn keygen(allocator: std.mem.Allocator, comptime params: type) !dilithium_impl.KeyPair {
    return params.keygen(allocator);
}

pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, comptime params: type) ![]u8 {
    return params.sign(allocator, private_key, message);
}

pub fn verify(public_key: []const u8, signature: []const u8, message: []const u8, comptime params: type) !bool {
    return params.verify(public_key, signature, message);
}

// Types
pub const PublicKey = dilithium_impl.PublicKey;
pub const PrivateKey = dilithium_impl.PrivateKey;
pub const KeyPair = dilithium_impl.KeyPair;
pub const Signature = dilithium_impl.Signature;

// Error types
pub const DilithiumError = dilithium_impl.DilithiumError;
pub const MlDsaError = DilithiumError; // Alias

// Recommended parameter set for Ghostchain (balance of security and performance)
pub const Recommended = MlDsa65;

// Test interface for fast unit tests
test "ml-dsa module availability" {
    const testing = std.testing;

    // Ensure types are available
    _ = MlDsa44;
    _ = MlDsa65;
    _ = MlDsa87;
    _ = keygen;
    _ = sign;
    _ = verify;

    try testing.expect(true);
}

test "ml-dsa parameter sets" {
    const testing = std.testing;

    // Test that we have the three NIST parameter sets
    _ = MlDsa44;
    _ = MlDsa65;
    _ = MlDsa87;

    try testing.expect(true);
}
