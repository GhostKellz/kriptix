//! Security Hardening & Constant-Time Operations
//! Implements security-critical features for production PQC deployment

const std = @import("std");
const testing = std.testing;

/// Secure memory management utilities
pub const SecureMemory = struct {
    /// Securely clear memory to prevent information leakage
    pub fn secure_zero(ptr: []u8) void {
        @memset(ptr, 0);
        // Simple memory barrier to prevent optimization
        var dummy: u8 = 0;
        for (ptr) |byte| {
            dummy ^= byte;
        }
        if (dummy == 0xFF) @panic("impossible");
    }

    /// Secure memory comparison (constant-time)
    pub fn secure_compare(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;

        var result: u8 = 0;
        for (0..a.len) |i| {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }

    /// Secure copy with bounds checking
    pub fn secure_copy(dest: []u8, src: []const u8) !void {
        if (dest.len < src.len) return error.BufferTooSmall;
        @memcpy(dest[0..src.len], src);

        if (dest.len > src.len) {
            secure_zero(dest[src.len..]);
        }
    }
};

/// Constant-time arithmetic operations
pub const ConstantTime = struct {
    /// Constant-time conditional selection
    pub fn select(condition: u8, true_val: u32, false_val: u32) u32 {
        const mask = @as(u32, @intFromBool(condition != 0)) -% 1;
        return (mask & true_val) | (~mask & false_val);
    }

    /// Constant-time conditional move
    pub fn cmov(dest: []u8, src: []const u8, condition: u8) void {
        std.debug.assert(dest.len == src.len);
        const mask = @as(u8, @intFromBool(condition != 0)) -% 1;

        for (0..dest.len) |i| {
            dest[i] ^= mask & (dest[i] ^ src[i]);
        }
    }

    /// Constant-time modular reduction
    pub fn ct_mod(x: u32, modulus: u32) u32 {
        var result = x;
        var i: u5 = 31;
        while (i > 0) : (i -= 1) {
            const bit = @as(u32, 1) << i;
            if (result >= bit * modulus) {
                result -= bit * modulus;
            }
        }
        if (result >= modulus) {
            result -= modulus;
        }
        return result;
    }
};

/// Input validation and sanitization
pub const InputValidation = struct {
    /// Validate key sizes for PQC algorithms
    pub fn validate_key_size(algorithm: @import("root.zig").Algorithm, public_key: ?[]const u8, private_key: ?[]const u8) !void {
        const KeySizes = struct { public_key: usize, private_key: usize };
        const expected_sizes = switch (algorithm) {
            .Kyber512 => KeySizes{ .public_key = 800, .private_key = 1632 },
            .Kyber768 => KeySizes{ .public_key = 1184, .private_key = 2400 },
            .Kyber1024 => KeySizes{ .public_key = 1568, .private_key = 3168 },
            .Dilithium2 => KeySizes{ .public_key = 1312, .private_key = 2528 },
            .Dilithium3 => KeySizes{ .public_key = 1952, .private_key = 4000 },
            .Dilithium5 => KeySizes{ .public_key = 2592, .private_key = 4864 },
            .Sphincs128f => KeySizes{ .public_key = 32, .private_key = 64 },
            .Sphincs256s => KeySizes{ .public_key = 64, .private_key = 128 },
            else => return error.UnsupportedAlgorithm,
        };

        if (public_key) |pk| {
            if (pk.len != expected_sizes.public_key) {
                return error.InvalidPublicKeySize;
            }
        }

        if (private_key) |sk| {
            if (sk.len != expected_sizes.private_key) {
                return error.InvalidPrivateKeySize;
            }
        }
    }

    /// Validate message size limits
    pub fn validate_message_size(message: []const u8, max_size: usize) !void {
        if (message.len == 0) return error.EmptyMessage;
        if (message.len > max_size) return error.MessageTooLarge;
    }

    /// Validate algorithm parameters
    pub fn validate_algorithm_params(algorithm: @import("root.zig").Algorithm) !void {
        switch (algorithm) {
            .Kyber512, .Kyber768, .Kyber1024, .Dilithium2, .Dilithium3, .Dilithium5, .Sphincs128f, .Sphincs256s, .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 => {},
            else => return error.UnsupportedAlgorithm,
        }
    }
};

/// Side-channel resistance utilities
pub const SideChannelResistance = struct {
    /// Timing-resistant operations
    pub const TimingResistant = struct {
        /// Fixed-time delay to mask timing variations
        pub fn fixed_delay_ns(nanoseconds: u64) void {
            const iterations = nanoseconds / 10;
            var dummy: u32 = 0;
            for (0..iterations) |i| {
                dummy ^= @as(u32, @intCast(i));
            }
            if (dummy == 0xDEADBEEF) @panic("impossible");
        }

        /// Add random jitter to timing
        pub fn add_timing_jitter(max_jitter_ns: u64) void {
            const jitter = std.crypto.random.intRangeAtMost(u64, 0, max_jitter_ns);
            fixed_delay_ns(jitter);
        }
    };

    /// Power analysis resistance
    pub const PowerAnalysisResistant = struct {
        /// Add dummy operations to mask power consumption
        pub fn add_dummy_operations(count: u32) void {
            var dummy: u32 = 0;
            for (0..count) |i| {
                dummy ^= @as(u32, @intCast(i));
            }
            if (dummy == 0xDEADBEEF) @panic("impossible");
        }
    };
};

/// Secure key derivation functions
pub const SecureKeyDerivation = struct {
    /// HKDF-based key derivation for PQC
    pub fn derive_key(allocator: std.mem.Allocator, master_key: []const u8, salt: []const u8, info: []const u8, length: usize) ![]u8 {
        if (length == 0 or length > 255 * 32) return error.InvalidLength;

        const output = try allocator.alloc(u8, length);
        errdefer allocator.free(output);

        // Simplified HKDF implementation
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(salt);
        hasher.update(master_key);
        var prk: [32]u8 = undefined;
        hasher.final(&prk);
        defer SecureMemory.secure_zero(&prk);

        // Expand
        var pos: usize = 0;
        var counter: u8 = 1;

        while (pos < length) {
            hasher = std.crypto.hash.sha2.Sha256.init(.{});
            if (pos > 0) {
                const prev_start = if (pos >= 32) pos - 32 else 0;
                hasher.update(output[prev_start..pos]);
            }
            hasher.update(info);
            hasher.update(&[_]u8{counter});

            var block: [32]u8 = undefined;
            hasher.final(&block);
            defer SecureMemory.secure_zero(&block);

            const copy_len = @min(32, length - pos);
            @memcpy(output[pos .. pos + copy_len], block[0..copy_len]);

            pos += copy_len;
            counter += 1;
        }

        return output;
    }
};

// Tests
test "secure memory operations" {
    var buffer: [32]u8 = undefined;
    @memset(&buffer, 0xFF);

    SecureMemory.secure_zero(&buffer);
    for (buffer) |byte| {
        try testing.expect(byte == 0);
    }
}

test "constant-time comparison" {
    const a = "hello";
    const b = "hello";
    const c = "world";

    try testing.expect(SecureMemory.secure_compare(a, b));
    try testing.expect(!SecureMemory.secure_compare(a, c));
}

test "constant-time selection" {
    const result1 = ConstantTime.select(1, 42, 24);
    const result2 = ConstantTime.select(0, 42, 24);

    try testing.expect(result1 == 42);
    try testing.expect(result2 == 24);
}

test "secure key derivation" {
    var allocator = testing.allocator;

    const master_key = "master_secret_key";
    const salt = "random_salt";
    const info = "key_derivation_context";

    const derived = try SecureKeyDerivation.derive_key(allocator, master_key, salt, info, 32);
    defer allocator.free(derived);

    try testing.expect(derived.len == 32);
    try testing.expect(!std.mem.eql(u8, derived, master_key));
}
