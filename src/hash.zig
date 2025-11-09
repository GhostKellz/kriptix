//! Cryptographic Hash Functions
//! SHA3, SHAKE, BLAKE3 backends using Zig std.crypto

const std = @import("std");
const crypto = std.crypto;

/// Hash algorithm enumeration
pub const HashAlgorithm = enum {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    Blake3,
};

/// Hash function interface
pub const Hasher = union(HashAlgorithm) {
    Sha3_224: crypto.hash.sha3.Sha3_224,
    Sha3_256: crypto.hash.sha3.Sha3_256,
    Sha3_384: crypto.hash.sha3.Sha3_384,
    Sha3_512: crypto.hash.sha3.Sha3_512,
    Shake128: crypto.hash.sha3.Shake128,
    Shake256: crypto.hash.sha3.Shake256,
    Blake3: crypto.hash.Blake3,

    /// Create a new hasher
    pub fn init(algo: HashAlgorithm) Hasher {
        return switch (algo) {
            .Sha3_224 => .{ .Sha3_224 = crypto.hash.sha3.Sha3_224.init(.{}) },
            .Sha3_256 => .{ .Sha3_256 = crypto.hash.sha3.Sha3_256.init(.{}) },
            .Sha3_384 => .{ .Sha3_384 = crypto.hash.sha3.Sha3_384.init(.{}) },
            .Sha3_512 => .{ .Sha3_512 = crypto.hash.sha3.Sha3_512.init(.{}) },
            .Shake128 => .{ .Shake128 = crypto.hash.sha3.Shake128.init(.{}) },
            .Shake256 => .{ .Shake256 = crypto.hash.sha3.Shake256.init(.{}) },
            .Blake3 => .{ .Blake3 = crypto.hash.Blake3.init(.{}) },
        };
    }

    /// Update the hash with data
    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            .Sha3_224 => |*h| h.update(data),
            .Sha3_256 => |*h| h.update(data),
            .Sha3_384 => |*h| h.update(data),
            .Sha3_512 => |*h| h.update(data),
            .Shake128 => |*h| h.update(data),
            .Shake256 => |*h| h.update(data),
            .Blake3 => |*h| h.update(data),
        }
    }

    /// Finalize and get the hash digest
    pub fn final(self: *Hasher, out: []u8) void {
        switch (self.*) {
            .Sha3_224 => |*h| h.final(@as(*[28]u8, @ptrCast(out.ptr))),
            .Sha3_256 => |*h| h.final(@as(*[32]u8, @ptrCast(out.ptr))),
            .Sha3_384 => |*h| h.final(@as(*[48]u8, @ptrCast(out.ptr))),
            .Sha3_512 => |*h| h.final(@as(*[64]u8, @ptrCast(out.ptr))),
            .Shake128 => |*h| h.final(out),
            .Shake256 => |*h| h.final(out),
            .Blake3 => |*h| h.final(out),
        }
    }

    /// Get the output length for the algorithm
    pub fn outputLength(algo: HashAlgorithm) usize {
        return switch (algo) {
            .Sha3_224 => 28,
            .Sha3_256 => 32,
            .Sha3_384 => 48,
            .Sha3_512 => 64,
            .Shake128 => 32, // Default output length
            .Shake256 => 64, // Default output length
            .Blake3 => 32,
        };
    }
};

/// Compute hash of data with specified algorithm
pub fn hash(algo: HashAlgorithm, data: []const u8, out: []u8) void {
    switch (algo) {
        .Sha3_224 => crypto.hash.sha3.Sha3_224.hash(data, out[0..28], .{}),
        .Sha3_256 => crypto.hash.sha3.Sha3_256.hash(data, out[0..32], .{}),
        .Sha3_384 => crypto.hash.sha3.Sha3_384.hash(data, out[0..48], .{}),
        .Sha3_512 => crypto.hash.sha3.Sha3_512.hash(data, out[0..64], .{}),
        .Shake128 => crypto.hash.sha3.Shake128.hash(data, out[0..32], .{}),
        .Shake256 => crypto.hash.sha3.Shake256.hash(data, out[0..64], .{}),
        .Blake3 => crypto.hash.Blake3.hash(data, out[0..32], .{}),
    }
}

/// SHAKE extendable output function
pub const Shake = struct {
    /// Generate variable-length output from SHAKE128
    pub fn shake128(input: []const u8, output: []u8) void {
        crypto.hash.sha3.Shake128.hash(input, output, .{});
    }

    /// Generate variable-length output from SHAKE256
    pub fn shake256(input: []const u8, output: []u8) void {
        crypto.hash.sha3.Shake256.hash(input, output, .{});
    }
};

test "SHA3-256 hash" {
    const data = "Hello, World!";
    var digest: [32]u8 = undefined;

    hash(.Sha3_256, data, &digest);

    // Expected SHA3-256 of "Hello, World!"
    const expected = [_]u8{
        0x1a, 0xf1, 0x7a, 0x66, 0x4e, 0x3f, 0xa8, 0xe4,
        0x19, 0xb8, 0xba, 0x05, 0xc2, 0xa1, 0x73, 0x16,
        0x9d, 0xf7, 0x61, 0x62, 0xa5, 0xa2, 0x86, 0xe0,
        0xc4, 0x05, 0xb4, 0x60, 0xd4, 0x78, 0xf7, 0xef,
    };

    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "BLAKE3 hash" {
    const data = "test";
    var digest: [32]u8 = undefined;

    hash(.Blake3, data, &digest);

    // BLAKE3 is deterministic, so we can check it's not all zeros
    var all_zero = true;
    for (digest) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "SHAKE128 extendable output" {
    const input = "shake test";
    var output: [64]u8 = undefined;

    Shake.shake128(input, &output);

    // Check that output is not all zeros
    var all_zero = true;
    for (output) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
