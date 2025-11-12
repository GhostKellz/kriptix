//! Secure Random Number Generation and DRBG
//! Based on Zig's std.crypto for cryptographic randomness

const std = @import("std");
const crypto = std.crypto;

var initialized = false;

/// Initialize the RNG system (idempotent)
pub fn init() void {
    if (!initialized) {
        // Warm up std.crypto random; no explicit state required.
        var probe: [8]u8 = undefined;
        crypto.random.bytes(&probe);
        initialized = true;
    }
}

/// Deinitialize the RNG system
pub fn deinit() void {
    initialized = false;
}

/// Fill a buffer with cryptographically secure random bytes
pub fn randomBytes(buf: []u8) void {
    crypto.random.bytes(buf);
}

/// Generate a random u64
pub fn randomU64() u64 {
    return crypto.random.int(u64);
}

/// Generate a random u32
pub fn randomU32() u32 {
    return crypto.random.int(u32);
}

/// Generate a random integer of type T
pub fn randomInt(comptime T: type) T {
    return crypto.random.int(T);
}

/// DRBG (Deterministic Random Bit Generator) for reproducible randomness
pub const DRBG = struct {
    state: [32]u8, // Internal state
    counter: u64,

    const Self = @This();

    /// Initialize DRBG with a seed
    pub fn init(seed: []const u8) Self {
        var state: [32]u8 = undefined;
        crypto.hash.sha3.Shake256.hash(seed, &state, .{});
        return Self{
            .state = state,
            .counter = 0,
        };
    }

    /// Generate random bytes deterministically
    pub fn generate(self: *Self, buf: []u8) void {
        var i: usize = 0;
        while (i < buf.len) {
            var block: [32]u8 = undefined;
            crypto.hash.sha3.Shake256.hash(&std.mem.toBytes(self.counter), &block, .{});
            crypto.hash.sha3.Shake256.hash(&self.state, &block, .{});

            const copy_len = @min(block.len, buf.len - i);
            @memcpy(buf[i .. i + copy_len], block[0..copy_len]);
            i += copy_len;
            self.counter += 1;
        }
    }

    /// Reseed the DRBG
    pub fn reseed(self: *Self, additional_input: []const u8) void {
        var new_seed = std.ArrayList(u8).initCapacity(std.heap.page_allocator, self.state.len + additional_input.len) catch unreachable;
        defer new_seed.deinit();
        new_seed.appendSliceAssumeCapacity(&self.state);
        new_seed.appendSliceAssumeCapacity(additional_input);
        crypto.hash.sha3.Shake256.hash(new_seed.items, &self.state, .{});
    }
};

test "RNG basic functionality" {
    init();
    defer deinit();

    var buf: [32]u8 = undefined;
    randomBytes(&buf);

    // Check that not all bytes are zero (very unlikely for random)
    var all_zero = true;
    for (buf) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "DRBG deterministic output" {
    var drbg = DRBG.init("test_seed");

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    drbg.generate(&buf1);
    drbg = DRBG.init("test_seed"); // Reset
    drbg.generate(&buf2);

    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}
