//! SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm
//! Standalone module for Ghostchain compatibility

const std = @import("std");

// Import existing SPHINCS+ implementation (SLH-DSA is standardized SPHINCS+)
const sphincs_impl = @import("../pq/sphincs.zig");

// SLH-DSA is the standardized version of SPHINCS+
pub const SlhDsa128S = sphincs_impl.Sphincs128s;
pub const SlhDsa128F = sphincs_impl.Sphincs128f;
pub const SlhDsa192S = sphincs_impl.Sphincs192s;
pub const SlhDsa192F = sphincs_impl.Sphincs192f;
pub const SlhDsa256S = sphincs_impl.Sphincs256s;
pub const SlhDsa256F = sphincs_impl.Sphincs256f;

// Alias for compatibility
pub const Sphincs128s = SlhDsa128S;
pub const Sphincs128f = SlhDsa128F;
pub const Sphincs192s = SlhDsa192S;
pub const Sphincs192f = SlhDsa192F;
pub const Sphincs256s = SlhDsa256S;
pub const Sphincs256f = SlhDsa256F;

// Common operations
pub fn keygen(allocator: std.mem.Allocator, comptime params: type) !sphincs_impl.KeyPair {
    return params.keygen(allocator);
}

pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, comptime params: type) ![]u8 {
    return params.sign(allocator, private_key, message);
}

pub fn verify(public_key: []const u8, signature: []const u8, message: []const u8, comptime params: type) !bool {
    return params.verify(public_key, signature, message);
}

// Types
pub const PublicKey = sphincs_impl.PublicKey;
pub const PrivateKey = sphincs_impl.PrivateKey;
pub const KeyPair = sphincs_impl.KeyPair;
pub const Signature = sphincs_impl.Signature;

// Error types
pub const SphincsError = sphincs_impl.SphincsError;
pub const SlhDsaError = SphincsError; // Alias

// Recommended parameter set for Ghostchain (NOT recommended due to performance)
// SLH-DSA is very slow compared to ML-DSA, only use for specific requirements
pub const Recommended = SlhDsa128F; // Fast variant if you must use SLH-DSA

// Test interface for fast unit tests
test "slh-dsa module availability" {
    const testing = std.testing;

    // Ensure types are available
    _ = SlhDsa128S;
    _ = SlhDsa128F;
    _ = keygen;
    _ = sign;
    _ = verify;

    try testing.expect(true);
}

test "slh-dsa parameter sets" {
    const testing = std.testing;

    // Test that we have the main parameter sets
    _ = SlhDsa128S;
    _ = SlhDsa128F;
    _ = SlhDsa192S;
    _ = SlhDsa192F;
    _ = SlhDsa256S;
    _ = SlhDsa256F;

    try testing.expect(true);
}
