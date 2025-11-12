//! Ed25519 Signatures implemented with Zig std.crypto

const std = @import("std");
const security = @import("../security.zig");
const testing = std.testing;
const blake3 = std.crypto.hash.Blake3;

const ed25519 = std.crypto.sign.Ed25519;

pub const SignatureLength = ed25519.Signature.encoded_length;
pub const PublicKeyLength = ed25519.PublicKey.encoded_length;
pub const PrivateKeyLength = ed25519.SecretKey.encoded_length;

pub const KeyPair = struct {
    public_key: []u8,
    private_key: []u8,

    pub fn deinit(self: *KeyPair, allocator: std.mem.Allocator) void {
        if (self.public_key.len > 0) allocator.free(self.public_key);
        if (self.private_key.len > 0) {
            security.SecureMemory.secure_zero(self.private_key);
            allocator.free(self.private_key);
        }
    }
};

/// Generate an Ed25519 keypair using system randomness
pub fn generateKeypair(allocator: std.mem.Allocator) !KeyPair {
    const key_pair = ed25519.KeyPair.generate();

    const public_bytes = key_pair.public_key.toBytes();
    const private_bytes = key_pair.secret_key.toBytes();

    const public_key = try allocator.dupe(u8, public_bytes[0..]);
    const private_key = try allocator.dupe(u8, private_bytes[0..]);

    var scrub = private_bytes;
    security.SecureMemory.secure_zero(scrub[0..]);

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Generate an Ed25519 keypair deterministically from caller-provided seed material.
/// The seed may be any length; it is expanded with BLAKE3 to the required 32-byte seed.
pub fn generateKeypairDeterministic(allocator: std.mem.Allocator, seed: []const u8) !KeyPair {
    var seed_material: [ed25519.KeyPair.seed_length]u8 = undefined;
    blake3.hash(seed, &seed_material, .{});

    const key_pair = try ed25519.KeyPair.generateDeterministic(seed_material);

    const public_bytes = key_pair.public_key.toBytes();
    const private_bytes = key_pair.secret_key.toBytes();

    const public_key = try allocator.dupe(u8, public_bytes[0..]);
    const private_key = try allocator.dupe(u8, private_bytes[0..]);

    var scrub = private_bytes;
    security.SecureMemory.secure_zero(scrub[0..]);

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Sign a message using Ed25519
pub fn sign(allocator: std.mem.Allocator, message: []const u8, private_key: []const u8) ![]u8 {
    if (private_key.len != PrivateKeyLength) return error.InvalidPrivateKeyLength;

    var secret_bytes: [PrivateKeyLength]u8 = undefined;
    @memcpy(secret_bytes[0..], private_key);
    defer security.SecureMemory.secure_zero(secret_bytes[0..]);

    const secret = try ed25519.SecretKey.fromBytes(secret_bytes);
    const key_pair = try ed25519.KeyPair.fromSecretKey(secret);

    const signature = try ed25519.KeyPair.sign(key_pair, message, null);
    const sig_bytes = signature.toBytes();

    const out = try allocator.dupe(u8, sig_bytes[0..]);
    return out;
}

/// Verify an Ed25519 signature
pub fn verify(signature: []const u8, message: []const u8, public_key: []const u8) !bool {
    if (signature.len != SignatureLength) return error.InvalidSignatureLength;
    if (public_key.len != PublicKeyLength) return error.InvalidPublicKeyLength;

    var sig_bytes: [SignatureLength]u8 = undefined;
    @memcpy(sig_bytes[0..], signature);
    const sig = ed25519.Signature.fromBytes(sig_bytes);

    var pk_bytes: [PublicKeyLength]u8 = undefined;
    @memcpy(pk_bytes[0..], public_key);
    const pk = try ed25519.PublicKey.fromBytes(pk_bytes);

    ed25519.Signature.verify(sig, message, pk) catch |err| switch (err) {
        error.SignatureVerificationFailed => return false,
        else => return error.InvalidKeyMaterial,
    };

    return true;
}

pub const Error = error{
    InvalidPrivateKeyLength,
    InvalidSignatureLength,
    InvalidPublicKeyLength,
    InvalidKeyMaterial,
};

test "ed25519 deterministic keygen stable" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed = "kriptix-ed25519-deterministic-seed";

    var kp1 = try generateKeypairDeterministic(allocator, seed);
    defer {
        allocator.free(kp1.public_key);
        allocator.free(kp1.private_key);
    }

    var kp2 = try generateKeypairDeterministic(allocator, seed);
    defer {
        allocator.free(kp2.public_key);
        allocator.free(kp2.private_key);
    }

    try testing.expectEqualSlices(u8, kp1.public_key, kp2.public_key);
    try testing.expectEqualSlices(u8, kp1.private_key, kp2.private_key);
}

comptime {
    std.debug.assert(SignatureLength == 64);
    std.debug.assert(PublicKeyLength == 32);
}
