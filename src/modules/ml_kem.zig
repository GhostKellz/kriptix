//! ML-KEM (FIPS 203) - Module Lattice-Based Key Encapsulation Mechanism
//! Standalone module for Ghostchain compatibility

const std = @import("std");

// Import existing Kyber implementation (ML-KEM is standardized Kyber)
const kyber_impl = @import("../pq/kyber.zig");

// We need to get the Algorithm enum from root, but avoid circular imports
const root = @import("../root.zig");

// ML-KEM parameter sets as structs with methods
pub const MlKem512 = struct {
    pub const keygen = generateKeypair512;
    pub const encaps = encrypt512;
    pub const decaps = decrypt512;
};

pub const MlKem768 = struct {
    pub const keygen = generateKeypair768;
    pub const encaps = encrypt768;
    pub const decaps = decrypt768;
};

pub const MlKem1024 = struct {
    pub const keygen = generateKeypair1024;
    pub const encaps = encrypt1024;
    pub const decaps = decrypt1024;
};

// Individual functions for each parameter set
fn generateKeypair512(allocator: std.mem.Allocator) !root.KeyPair {
    return kyber_impl.generate_keypair(allocator, .Kyber512);
}

fn encrypt512(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8) !root.Ciphertext {
    return kyber_impl.encrypt(allocator, public_key, message, .Kyber512);
}

fn decrypt512(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: []const u8) ![]u8 {
    return kyber_impl.decrypt(allocator, private_key, ciphertext);
}

fn generateKeypair768(allocator: std.mem.Allocator) !root.KeyPair {
    return kyber_impl.generate_keypair(allocator, .Kyber768);
}

fn encrypt768(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8) !root.Ciphertext {
    return kyber_impl.encrypt(allocator, public_key, message, .Kyber768);
}

fn decrypt768(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: []const u8) ![]u8 {
    return kyber_impl.decrypt(allocator, private_key, ciphertext);
}

fn generateKeypair1024(allocator: std.mem.Allocator) !root.KeyPair {
    return kyber_impl.generate_keypair(allocator, .Kyber1024);
}

fn encrypt1024(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8) !root.Ciphertext {
    return kyber_impl.encrypt(allocator, public_key, message, .Kyber1024);
}

fn decrypt1024(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: []const u8) ![]u8 {
    return kyber_impl.decrypt(allocator, private_key, ciphertext);
}

// Alias for compatibility
pub const Kyber512 = MlKem512;
pub const Kyber768 = MlKem768;
pub const Kyber1024 = MlKem1024;

// Common error types
pub const MlKemError = error{
    InvalidKeySize,
    InvalidCiphertextSize,
    DecryptionFailed,
    AllocationFailed,
};

// Test interface for fast unit tests
test "ml-kem module availability" {
    const testing = std.testing;

    // Ensure types are available
    _ = MlKem512;
    _ = MlKem768;
    _ = MlKem1024;

    try testing.expect(true);
}
