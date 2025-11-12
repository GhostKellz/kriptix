//! ChaCha20-Poly1305 AEAD helpers built on Zig std.crypto

const std = @import("std");
const security = @import("../security.zig");

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const KeyLength = ChaCha20Poly1305.key_length;
pub const NonceLength = ChaCha20Poly1305.nonce_length;
pub const TagLength = ChaCha20Poly1305.tag_length;

/// Encrypt `plaintext` with ChaCha20-Poly1305, returning ciphertext + tag.
pub fn encrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    plaintext: []const u8,
    associated_data: []const u8,
) !struct {
    ciphertext: []u8,
    tag: [TagLength]u8,
} {
    if (key.len != KeyLength) return error.InvalidKeyLength;
    if (nonce.len != NonceLength) return error.InvalidNonceLength;

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    var tag: [TagLength]u8 = undefined;

    var key_buf: [KeyLength]u8 = undefined;
    @memcpy(key_buf[0..], key[0..KeyLength]);
    defer security.SecureMemory.secure_zero(key_buf[0..]);

    var nonce_buf: [NonceLength]u8 = undefined;
    @memcpy(nonce_buf[0..], nonce[0..NonceLength]);

    ChaCha20Poly1305.encrypt(ciphertext, &tag, plaintext, associated_data, nonce_buf, key_buf);

    return .{ .ciphertext = ciphertext, .tag = tag };
}

/// Decrypt `ciphertext` with ChaCha20-Poly1305. Returns plaintext slice owned by caller.
pub fn decrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    associated_data: []const u8,
    tag: [TagLength]u8,
) ![]u8 {
    if (key.len != KeyLength) return error.InvalidKeyLength;
    if (nonce.len != NonceLength) return error.InvalidNonceLength;

    const plaintext = try allocator.alloc(u8, ciphertext.len);

    var key_buf: [KeyLength]u8 = undefined;
    @memcpy(key_buf[0..], key[0..KeyLength]);
    defer security.SecureMemory.secure_zero(key_buf[0..]);

    var nonce_buf: [NonceLength]u8 = undefined;
    @memcpy(nonce_buf[0..], nonce[0..NonceLength]);

    try ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, associated_data, nonce_buf, key_buf);

    return plaintext;
}

/// Securely wipe a key buffer
pub fn zeroKey(key: []u8) void {
    security.SecureMemory.secure_zero(key);
}

pub const Error = error{
    InvalidKeyLength,
    InvalidNonceLength,
};
