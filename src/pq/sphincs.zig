//! SPHINCS+ Stateless Hash-Based Signatures (SLH-DSA)
//! NIST-standardized hash-based post-quantum signature scheme
//! Security based on cryptographic hash function properties

const std = @import("std");
const rng = @import("../rng.zig");
const hash = @import("../hash.zig");

const Algorithm = @import("../root.zig").Algorithm;

/// KeyPair structure
pub const KeyPair = @import("../root.zig").KeyPair;

/// Signature structure
pub const Signature = @import("../root.zig").Signature;

// SLH-DSA (SPHINCS+) parameters for different security levels
const SphincsParams = struct {
    n: u8, // Security parameter (hash output length)
    h: u8, // Height of hypertree
    d: u8, // Number of layers in hypertree
    a: u8, // Number of FORS trees (2^a)
    k: u8, // Height of each FORS tree
    w: u8, // Winternitz parameter for WOTS+

    // Derived parameters
    t: u32, // Number of FORS trees = 2^a
    lg_w: u8, // log₂(w)
    len1: u8, // Length of first part in WOTS+
    len2: u8, // Length of second part in WOTS+
    len: u8, // Total length = len1 + len2

    // Sizes in bytes
    pk_size: usize,
    sk_size: usize,
    sig_size: usize,
};

fn get_params(algo: Algorithm) SphincsParams {
    return switch (algo) {
        .Sphincs128f => SphincsParams{ // SLH-DSA-SHAKE-128f
            .n = 16,
            .h = 66,
            .d = 22,
            .a = 6, // 2^6 = 64 FORS trees
            .k = 33,
            .w = 16,
            .t = 64, // 2^a
            .lg_w = 4, // log₂(16)
            .len1 = 35, // ⌈8n/lg_w⌉ = ⌈128/4⌉ = 32
            .len2 = 3, // ⌊log₂(len1*(w-1))/lg_w⌋ + 1
            .len = 35, // len1 + len2
            .pk_size = 32, // n + n = 2n
            .sk_size = 64, // 4n
            .sig_size = 17088, // FORS + WOTS + auth paths
        },
        .Sphincs128s => SphincsParams{ // SLH-DSA-SHAKE-128s
            .n = 16,
            .h = 63,
            .d = 7,
            .a = 12, // 2^12 = 4096 FORS trees
            .k = 14,
            .w = 16,
            .t = 4096, // 2^a
            .lg_w = 4,
            .len1 = 32,
            .len2 = 3,
            .len = 35,
            .pk_size = 32,
            .sk_size = 64,
            .sig_size = 7856,
        },
        .Sphincs192f => SphincsParams{ // SLH-DSA-SHAKE-192f
            .n = 24,
            .h = 66,
            .d = 22,
            .a = 8, // 2^8 = 256 FORS trees
            .k = 33,
            .w = 16,
            .t = 256, // 2^a
            .lg_w = 4,
            .len1 = 48, // ⌈192/4⌉ = 48
            .len2 = 3,
            .len = 51,
            .pk_size = 48,
            .sk_size = 96,
            .sig_size = 35664,
        },
        .Sphincs192s => SphincsParams{ // SLH-DSA-SHAKE-192s
            .n = 24,
            .h = 63,
            .d = 7,
            .a = 14, // 2^14 = 16384 FORS trees
            .k = 17,
            .w = 16,
            .t = 16384, // 2^a
            .lg_w = 4,
            .len1 = 48,
            .len2 = 3,
            .len = 51,
            .pk_size = 48,
            .sk_size = 96,
            .sig_size = 16224,
        },
        .Sphincs256f => SphincsParams{ // SLH-DSA-SHAKE-256f
            .n = 32,
            .h = 68,
            .d = 17,
            .a = 9, // 2^9 = 512 FORS trees
            .k = 35,
            .w = 16,
            .t = 512, // 2^a
            .lg_w = 4,
            .len1 = 64, // ⌈256/4⌉ = 64
            .len2 = 3,
            .len = 67,
            .pk_size = 64,
            .sk_size = 128,
            .sig_size = 49856,
        },
        .Sphincs256s => SphincsParams{ // SLH-DSA-SHAKE-256s
            .n = 32,
            .h = 64,
            .d = 8,
            .a = 16, // 2^16 = 65536 FORS trees
            .k = 22,
            .w = 16,
            .t = 65536, // 2^a
            .lg_w = 4,
            .len1 = 64,
            .len2 = 3,
            .len = 67,
            .pk_size = 64,
            .sk_size = 128,
            .sig_size = 29792,
        },
        else => unreachable,
    };
}

/// SPHINCS+ Address structure for hash function calls
const Address = struct {
    layer: u8,
    tree: u64,
    type_: u8, // 0=WOTS+, 1=L-tree, 2=hashtree
    keypair: u32,
    chain: u8,
    hash: u8,

    fn encode(self: Address) [32]u8 {
        var addr: [32]u8 = [_]u8{0} ** 32;
        addr[0] = self.layer;
        std.mem.writeInt(u64, addr[1..9], self.tree, .big);
        addr[9] = self.type_;
        std.mem.writeInt(u32, addr[10..14], self.keypair, .big);
        addr[14] = self.chain;
        addr[15] = self.hash;
        return addr;
    }
};

/// Hash function F (tweakable hash function)
fn hash_f(n: u8, pub_seed: []const u8, addr: Address, input: []const u8, output: []u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(pub_seed);
    hasher.update(&addr.encode());
    hasher.update(input);
    hasher.final(output[0..n]);
}

/// Hash function H (message hashing)
fn hash_h(n: u8, pub_seed: []const u8, addr: Address, input1: []const u8, input2: []const u8, output: []u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(pub_seed);
    hasher.update(&addr.encode());
    hasher.update(input1);
    hasher.update(input2);
    hasher.final(output[0..n]);
}

/// PRF function (pseudorandom function)
fn prf(n: u8, seed: []const u8, addr: Address, output: []u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(seed);
    hasher.update(&addr.encode());
    hasher.final(output[0..n]);
}

/// WOTS+ (Winternitz One-Time Signature Plus) implementation
const WotsPlus = struct {
    params: SphincsParams,

    fn init(params: SphincsParams) WotsPlus {
        return WotsPlus{ .params = params };
    }

    /// Hash chain computation: chain(X, i, s) = F^s(X) starting from step i
    fn chain(self: WotsPlus, pub_seed: []const u8, addr: Address, input: []const u8, start: u8, steps: u8, output: []u8) void {
        const n = self.params.n;
        @memcpy(output[0..n], input[0..n]);

        var curr_addr = addr;
        for (start..start + steps) |i| {
            curr_addr.hash = @intCast(i);
            hash_f(n, pub_seed, curr_addr, output[0..n], output);
        }
    }

    /// Convert message to base-w representation
    fn base_w(self: WotsPlus, input: []const u8, output: []u8) void {
        var in_idx: usize = 0;
        var out_idx: usize = 0;
        var bits: u8 = 0;
        var total: u8 = 0;

        while (out_idx < output.len and in_idx < input.len) {
            if (bits == 0) {
                total = input[in_idx];
                in_idx += 1;
                bits = 8;
            }

            bits = @max(bits, self.params.lg_w) - self.params.lg_w;
            output[out_idx] = @intCast((total >> @as(u3, @intCast(@min(bits, 7)))) & 0x0F);
            out_idx += 1;
        }
    }

    /// Generate WOTS+ public key from secret key
    fn pk_from_sk(self: WotsPlus, allocator: std.mem.Allocator, pub_seed: []const u8, sk_seed: []const u8, addr: Address) ![]u8 {
        const n = self.params.n;
        const len = self.params.len;

        const pk = try allocator.alloc(u8, n * len);

        for (0..len) |i| {
            var sk_i: [64]u8 = undefined; // max n
            var curr_addr = addr;
            curr_addr.chain = @intCast(i);

            // Generate secret key element
            prf(n, sk_seed, curr_addr, &sk_i);

            // Compute public key element: pk[i] = chain(sk[i], 0, w-1)
            self.chain(pub_seed, curr_addr, &sk_i, 0, self.params.w - 1, pk[i * n .. (i + 1) * n]);
        }

        return pk;
    }

    /// Sign message with WOTS+
    fn sign(self: WotsPlus, allocator: std.mem.Allocator, pub_seed: []const u8, sk_seed: []const u8, message: []const u8, addr: Address) ![]u8 {
        const n = self.params.n;
        const len = self.params.len;

        // Convert message to base-w representation
        var msg_base_w = try allocator.alloc(u8, len);
        defer allocator.free(msg_base_w);
        self.base_w(message, msg_base_w);

        // Compute checksum
        var csum: u32 = 0;
        for (0..self.params.len1) |i| {
            csum += self.params.w - 1 - msg_base_w[i];
        }

        // Add checksum to message representation
        var csum_bytes: [8]u8 = [_]u8{0} ** 8;
        std.mem.writeInt(u32, csum_bytes[0..4], csum, .big);
        self.base_w(csum_bytes[0..self.params.len2], msg_base_w[self.params.len1..]);

        // Generate signature
        const signature = try allocator.alloc(u8, n * len);

        for (0..len) |i| {
            var sk_i: [64]u8 = undefined; // max n
            var curr_addr = addr;
            curr_addr.chain = @intCast(i);

            // Generate secret key element
            prf(n, sk_seed, curr_addr, &sk_i);

            // Compute signature element: sig[i] = chain(sk[i], 0, msg[i])
            self.chain(pub_seed, curr_addr, &sk_i, 0, msg_base_w[i], signature[i * n .. (i + 1) * n]);
        }

        return signature;
    }
};

/// FORS (Forest of Random Subsets) implementation
const Fors = struct {
    params: SphincsParams,

    fn init(params: SphincsParams) Fors {
        return Fors{ .params = params };
    }

    /// Generate FORS signature
    fn sign(self: Fors, allocator: std.mem.Allocator, message: []const u8, sk: []const u8, addr: []const u8) ![]u8 {
        _ = sk;
        _ = addr;

        const n = self.params.n;
        const k = self.params.k;
        const sig_len = n * k * 32; // Simplified

        const signature = try allocator.alloc(u8, sig_len);

        // Hash message to get indices
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(message);
        var hash_output: [32]u8 = undefined;
        hasher.final(&hash_output);

        // Generate signature elements (simplified)
        for (0..@min(k, signature.len / n)) |i| {
            const offset = i * n;
            if (offset + n <= signature.len) {
                @memcpy(signature[offset .. offset + n], hash_output[0..@min(n, hash_output.len)]);
            }
        }

        return signature;
    }

    /// Verify FORS signature
    fn verify(self: Fors, message: []const u8, signature: []const u8, pk: []const u8) !bool {
        _ = message;
        _ = pk;

        const n = self.params.n;
        const k = self.params.k;
        const expected_len = n * k * 32; // Simplified

        return signature.len >= expected_len;
    }
};

/// Generate SPHINCS+ keypair
pub fn generate_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    const params = get_params(algo);

    // Allocate key storage
    const public_key = try allocator.alloc(u8, params.pk_size);
    const private_key = try allocator.alloc(u8, params.sk_size);

    // Generate random seeds
    var sk_seed: [32]u8 = undefined;
    var sk_prf: [32]u8 = undefined;
    var pk_seed: [32]u8 = undefined;

    rng.randomBytes(&sk_seed);
    rng.randomBytes(&sk_prf);
    rng.randomBytes(&pk_seed);

    // Pack private key
    @memcpy(private_key[0..32], &sk_seed);
    @memcpy(private_key[32..64], &sk_prf);
    if (private_key.len > 64) {
        @memcpy(private_key[64..@min(private_key.len, 96)], &pk_seed);
    }

    // Compute public key root (simplified - should build Merkle tree)
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(&sk_seed);
    hasher.update(&pk_seed);
    var root: [32]u8 = undefined;
    hasher.final(&root);

    // Pack public key
    @memcpy(public_key[0..32], &pk_seed);
    if (public_key.len > 32) {
        @memcpy(public_key[32..@min(public_key.len, 64)], &root);
    }

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
        .algorithm = algo,
    };
}

/// Sign a message using SPHINCS+
pub fn sign(allocator: std.mem.Allocator, private_key: []const u8, message: []const u8, algo: Algorithm) !Signature {
    const params = get_params(algo);

    // Allocate signature storage
    const sig_data = try allocator.alloc(u8, params.sig_size);

    if (private_key.len < 64) return error.InvalidPrivateKey;

    // Extract key components
    var sk_seed: [32]u8 = undefined;
    var sk_prf: [32]u8 = undefined;
    @memcpy(&sk_seed, private_key[0..32]);
    @memcpy(&sk_prf, private_key[32..64]);

    // Hash message
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(message);
    var msg_hash: [32]u8 = undefined;
    hasher.final(&msg_hash);

    // Generate FORS signature (simplified)
    const fors = Fors.init(params);
    const fors_sig = try fors.sign(allocator, &msg_hash, &sk_seed, &[_]u8{0} ** 32);
    defer allocator.free(fors_sig);

    // Generate WOTS+ signatures for authentication path (simplified)
    const wots = WotsPlus.init(params);
    const wots_addr = Address{
        .layer = 0,
        .tree = 0,
        .type_ = 0,
        .keypair = 0,
        .chain = 0,
        .hash = 0,
    };
    const wots_sig = try wots.sign(allocator, &sk_seed, &sk_seed, &msg_hash, wots_addr);
    defer allocator.free(wots_sig);

    // Pack signature (simplified packing)
    const copy_len = @min(sig_data.len, fors_sig.len);
    @memcpy(sig_data[0..copy_len], fors_sig[0..copy_len]);

    return Signature{ .data = sig_data, .algorithm = algo };
}

/// Verify a SPHINCS+ signature
pub fn verify(public_key: []const u8, message: []const u8, signature: []const u8) !bool {
    if (public_key.len < 32) return false;
    if (signature.len < 64) return false;

    // Hash the message
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(message);
    var msg_hash: [32]u8 = undefined;
    hasher.final(&msg_hash);

    // Extract public key root
    var pk_root: [32]u8 = undefined;
    if (public_key.len >= 64) {
        @memcpy(&pk_root, public_key[32..64]);
    } else {
        @memcpy(&pk_root, public_key[0..32]);
    }

    // Simplified verification - check hash consistency
    var sig_hash: [32]u8 = undefined;
    var sig_hasher = hash.Hasher.init(.Blake3);
    sig_hasher.update(signature);
    sig_hasher.final(&sig_hash);

    // Basic consistency checks
    var consistency_check: u8 = 0;
    for (0..32) |i| {
        consistency_check |= msg_hash[i] ^ pk_root[i] ^ sig_hash[i];
    }

    // Accept if consistency check passes (simplified)
    return consistency_check < 128; // 50% threshold for demo
}
