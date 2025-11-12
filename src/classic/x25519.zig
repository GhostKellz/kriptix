//! X25519 Diffie-Hellman key exchange helpers using Zig std.crypto

const std = @import("std");
const security = @import("../security.zig");

const x25519 = std.crypto.dh.X25519;

pub const PublicKeyLength = x25519.public_length;
pub const PrivateKeyLength = x25519.secret_length;
pub const SharedSecretLength = x25519.shared_length;

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

/// Generate an X25519 keypair
pub fn generateKeypair(allocator: std.mem.Allocator) !KeyPair {
    const pair = x25519.KeyPair.generate();

    const public_key = try allocator.dupe(u8, pair.public_key[0..]);

    const private_key = try allocator.dupe(u8, pair.secret_key[0..]);
    var secret_scrub = pair.secret_key;
    security.SecureMemory.secure_zero(secret_scrub[0..]);

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Compute shared secret using private key and peer public key
pub fn computeSharedSecret(allocator: std.mem.Allocator, private_key: []const u8, peer_public_key: []const u8) ![]u8 {
    if (private_key.len != PrivateKeyLength) return error.InvalidPrivateKeyLength;
    if (peer_public_key.len != PublicKeyLength) return error.InvalidPublicKeyLength;

    var secret_buf: [PrivateKeyLength]u8 = undefined;
    @memcpy(secret_buf[0..], private_key);
    defer security.SecureMemory.secure_zero(secret_buf[0..]);

    var public_buf: [PublicKeyLength]u8 = undefined;
    @memcpy(public_buf[0..], peer_public_key);

    const shared_bytes = x25519.scalarmult(secret_buf, public_buf) catch |err| switch (err) {
        error.IdentityElement => return error.InvalidKeyMaterial,
    };

    var shared_copy = shared_bytes;
    defer security.SecureMemory.secure_zero(shared_copy[0..]);

    const out = try allocator.dupe(u8, shared_copy[0..]);
    return out;
}

pub const Error = error{
    InvalidPrivateKeyLength,
    InvalidPublicKeyLength,
    InvalidKeyMaterial,
};
