//! Kyber Key Encapsulation Mechanism (KEM)
//! Lattice-based post-quantum cryptography
//! Based on ML-KEM (formerly Kyber) from NIST PQC Round 3

const std = @import("std");
const crypto = std.crypto;
const rng = @import("../rng.zig");
const hash = @import("../hash.zig");
const Algorithm = @import("../root.zig").Algorithm;
const KeyPair = @import("../root.zig").KeyPair;
const Ciphertext = @import("../root.zig").Ciphertext;

// Kyber parameters for different security levels
pub const Params = struct {
    k: usize, // Number of polynomials in vectors
    eta1: usize, // Noise parameter for key generation
    eta2: usize, // Noise parameter for encryption
    du: usize, // Bits to compress u
    dv: usize, // Bits to compress v

    pub fn fromAlgo(algo: Algorithm) Params {
        return switch (algo) {
            .Kyber512 => .{
                .k = 2,
                .eta1 = 3,
                .eta2 = 2,
                .du = 10,
                .dv = 4,
            },
            .Kyber768 => .{
                .k = 3,
                .eta1 = 2,
                .eta2 = 2,
                .du = 10,
                .dv = 4,
            },
            .Kyber1024 => .{
                .k = 4,
                .eta1 = 2,
                .eta2 = 2,
                .du = 11,
                .dv = 5,
            },
            else => unreachable,
        };
    }
};

// Constants
const N = 256;
const Q = 3329;
const SYMBYTES = 32;
const SSBYTES = 32;

// Polynomial ring element
pub const Poly = struct {
    coeffs: [N]i16,

    pub fn init() Poly {
        return Poly{ .coeffs = [_]i16{0} ** N };
    }

    pub fn add(self: *Poly, other: Poly) void {
        for (0..N) |i| {
            self.coeffs[i] = @mod(self.coeffs[i] + other.coeffs[i], Q);
        }
    }

    pub fn sub(self: *Poly, other: Poly) void {
        for (0..N) |i| {
            self.coeffs[i] = @mod(self.coeffs[i] - other.coeffs[i], Q);
        }
    }

    pub fn mul(self: Poly, other: Poly) Poly {
        var result = Poly.init();
        for (0..N) |i| {
            for (0..N) |j| {
                const idx = (i + j) % N;
                result.coeffs[idx] = @mod(result.coeffs[idx] + self.coeffs[i] * other.coeffs[j], Q);
            }
        }
        return result;
    }

    pub fn ntt(self: *Poly) void {
        // Forward NTT - simplified implementation
        // In practice, this would use the full Cooley-Tukey NTT
        var j: usize = 0;
        var k: usize = 1;
        while (k < N) {
            const len = k;
            k <<= 1;
            var angle: usize = 0;
            while (angle < N) {
                const w = zetas[j];
                j += 1;
                var i = angle;
                while (i < angle + len) {
                    const t = @mod(self.coeffs[i + len] * w, Q);
                    self.coeffs[i + len] = @mod(self.coeffs[i] - t, Q);
                    self.coeffs[i] = @mod(self.coeffs[i] + t, Q);
                    i += 1;
                }
                angle += k;
            }
        }
    }

    pub fn invNtt(self: *Poly) void {
        // Inverse NTT - simplified implementation
        var j: usize = 0;
        var k: usize = N;
        while (k > 1) {
            k >>= 1;
            var angle: usize = 0;
            while (angle < N) {
                const w = -zetas_rev[j];
                j += 1;
                var i = angle;
                while (i < angle + k) {
                    const t = self.coeffs[i];
                    self.coeffs[i] = @mod(t + self.coeffs[i + k], Q);
                    self.coeffs[i + k] = @mod(t - self.coeffs[i + k], Q);
                    self.coeffs[i + k] = @mod(self.coeffs[i + k] * w, Q);
                    i += 1;
                }
                angle += 2 * k;
            }
        }

        // Scale by N^(-1) mod Q
        const n_inv = 3303; // N^(-1) mod Q
        for (0..N) |i| {
            self.coeffs[i] = @mod(self.coeffs[i] * n_inv, Q);
        }
    }
};

// Vector of polynomials
pub const PolyVec = struct {
    vec: []Poly,

    pub fn init(allocator: std.mem.Allocator, k: usize) !PolyVec {
        const vec = try allocator.alloc(Poly, k);
        for (vec) |*p| {
            p.* = Poly.init();
        }
        return PolyVec{ .vec = vec };
    }

    pub fn deinit(self: PolyVec, allocator: std.mem.Allocator) void {
        allocator.free(self.vec);
    }

    pub fn ntt(self: PolyVec) void {
        for (self.vec) |*p| {
            p.ntt();
        }
    }

    pub fn invNtt(self: PolyVec) void {
        for (self.vec) |*p| {
            p.invNtt();
        }
    }
};

// Zetas for NTT (simplified - would need full 256 values)
const zetas = [_]i16{
    1,    2,    4,    8,    16,   32,   64,   128,  256,  512,  1024, 2048, 17,   34,   68,   136,
    272,  544,  1088, 2176, 97,   194,  388,  776,  1552, 3104, 2453, 1633, 1266, 2532, 1905, 1210,
    2420, 1672, 3344, 1427, 2854, 2239, 1102, 2204, 644,  1288, 2576, 1698, 3396, 1325, 2650, 1735,
    3470, 1455, 2910, 2355, 1144, 2288, 1017, 2034, 4068, 3157, 2447, 1628, 3256, 2445, 1624, 3248,
    2439, 1612, 3224, 2399, 1532, 3064, 2173, 877,  1754, 3508, 3049, 2132, 4264, 3559, 3151, 2435,
    1614, 3228, 2407, 1548, 3096, 2237, 1108, 2216, 637,  1274, 2548, 1739, 3478, 1489, 2978, 1989,
    3978, 3089, 2211, 1026, 2052, 4104, 3241, 2515, 1664, 3328, 2589, 1712, 3424, 2591, 1716, 3432,
    2607, 1748, 3496, 3037, 2117, 4234, 3499, 3041, 2116, 4232, 3495, 3033, 2109, 4218, 3479, 2991,
    2016, 4032, 3105, 2253, 1040, 2080, 4160, 3353, 2749, 1532, 3064, 2173, 877,  1754, 3508, 3049,
    2132, 4264, 3559, 3151, 2435, 1614, 3228, 2407, 1548, 3096, 2237, 1108, 2216, 637,  1274, 2548,
    1739, 3478, 1489, 2978, 1989, 3978, 3089, 2211, 1026, 2052, 4104, 3241, 2515, 1664, 3328, 2589,
    1712, 3424, 2591, 1716, 3432, 2607, 1748, 3496, 3037, 2117, 4234, 3499, 3041, 2116, 4232, 3495,
    3033, 2109, 4218, 3479, 2991, 2016, 4032, 3105, 2253, 1040, 2080, 4160, 3353, 2749,
};

// Reverse zetas for inverse NTT
const zetas_rev = [_]i16{
    1,    3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133,
    3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301,
    3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793,
    2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293,
    3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041,
    1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257,
    3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,
    25,   3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133,
    3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301,
    3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793,
    2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293,
    3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041,
    1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257,
    3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,
    25,   3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133,
    3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301,
    3299, 3297, 3293, 3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793,
    2601, 2353, 2041, 1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293,
    3285, 3273, 3257, 3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041,
    1657, 1189, 641,  25,   3302, 3301, 3299, 3297, 3293, 3285, 3273, 3257,
    3233, 3193, 3133, 3049, 2937, 2793, 2601, 2353, 2041, 1657, 1189, 641,
    25,
};

// Montgomery reduction
fn montgomeryReduce(a: i32) i16 {
    const u = @as(i16, @intCast(@mod(a * 62209, 1 << 16)));
    var t = @as(i32, u) * Q;
    t = a - t;
    t >>= 16;
    return @as(i16, @intCast(t));
}

// Barrett reduction
fn barrettReduce(a: i16) i16 {
    const v = @as(i32, 20159) * a;
    const t = @as(i32, v >> 26) * Q;
    return @as(i16, @intCast(a - @as(i16, @intCast(t))));
}

// Compression and decompression functions
fn compress(d: usize, x: i16) u8 {
    const shift_d = @as(u5, @intCast(d));
    const t = @as(u32, @intCast((@as(u32, @intCast(x)) << shift_d) + (@as(u32, 1) << (shift_d - 1)))) / Q;
    return @as(u8, @intCast(t & ((@as(u32, 1) << shift_d) - 1)));
}

fn decompress(d: usize, x: u8) i16 {
    const shift_d = @as(u5, @intCast(d));
    return @as(i16, @intCast((@as(u32, x) * Q + (@as(u32, 1) << (shift_d - 1))) >> shift_d));
}

// CBD (Centered Binomial Distribution) sampling
fn cbd(eta: usize, buf: []const u8) Poly {
    var poly = Poly.init();
    var i: usize = 0;
    var j: usize = 0;

    while (i < N) {
        var t: i16 = 0;
        var d: i16 = 0;

        for (0..eta) |_| {
            d += (buf[j / 8] >> @as(u3, @intCast(j % 8))) & 1;
            j += 1;
        }

        for (0..eta) |_| {
            d -= (buf[j / 8] >> @as(u3, @intCast(j % 8))) & 1;
            j += 1;
        }

        t = d;
        poly.coeffs[i] = @as(i16, @intCast(t));
        i += 1;
    }

    return poly;
}

// Generate matrix A from seed
fn genMatrix(allocator: std.mem.Allocator, k: usize, seed: []const u8) ![]PolyVec {
    var matrix = try allocator.alloc(PolyVec, k);

    for (0..k) |i| {
        matrix[i] = try PolyVec.init(allocator, k);
        for (0..k) |j| {
            // Generate polynomial from seed
            var buf: [34]u8 = undefined;
            @memcpy(buf[0..32], seed);
            buf[32] = @as(u8, @intCast(i));
            buf[33] = @as(u8, @intCast(j));

            var p = Poly.init();
            // Simplified polynomial generation - would use SHAKE in real implementation
            for (0..N) |l| {
                p.coeffs[l] = @mod(@as(i16, @intCast(buf[l % 34])), Q);
            }
            matrix[i].vec[j] = p;
        }
    }

    return matrix;
}

// IND-CPA keypair generation
fn indcpaKeypair(allocator: std.mem.Allocator, params: Params, pk: []u8, sk: []u8) !void {
    var seed: [SYMBYTES]u8 = undefined;
    rng.randomBytes(&seed);

    // Generate matrix A
    var matrix = try genMatrix(allocator, params.k, &seed);
    defer {
        for (matrix) |*row| {
            row.deinit(allocator);
        }
        allocator.free(matrix);
    }

    // Generate secret vector s
    var s = try PolyVec.init(allocator, params.k);
    defer s.deinit(allocator);

    for (0..params.k) |i| {
        // CBD needs 2*eta*256 bits = 64*eta bytes per polynomial
        const buf_size = 64 * params.eta1;
        var buf: [64 * 3]u8 = undefined; // Max eta is 3, so 192 bytes
        rng.randomBytes(buf[0..buf_size]);
        s.vec[i] = cbd(params.eta1, buf[0..buf_size]);
    }

    // Generate error vector e
    var e = try PolyVec.init(allocator, params.k);
    defer e.deinit(allocator);

    for (0..params.k) |i| {
        // CBD needs 2*eta*256 bits = 64*eta bytes per polynomial
        const buf_size = 64 * params.eta1;
        var buf: [64 * 3]u8 = undefined; // Max eta is 3, so 192 bytes
        rng.randomBytes(buf[0..buf_size]);
        e.vec[i] = cbd(params.eta1, buf[0..buf_size]);
    }

    // Compute public key t = A*s + e
    s.ntt();
    var t = try PolyVec.init(allocator, params.k);
    defer t.deinit(allocator);

    for (0..params.k) |i| {
        t.vec[i] = Poly.init();
        for (0..params.k) |j| {
            const prod = matrix[i].vec[j].mul(s.vec[j]);
            t.vec[i].add(prod);
        }
        t.vec[i].add(e.vec[i]);
    }

    t.invNtt();

    // Encode public key
    var pk_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            const coeff = @as(u16, @intCast(t.vec[i].coeffs[j]));
            pk[pk_idx] = @as(u8, @intCast(coeff & 0xFF));
            pk[pk_idx + 1] = @as(u8, @intCast(coeff >> 8));
            pk_idx += 2;
        }
    }
    @memcpy(pk[pk_idx .. pk_idx + SYMBYTES], &seed);

    // Encode secret key
    var sk_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            const coeff = @as(u16, @intCast(s.vec[i].coeffs[j]));
            sk[sk_idx] = @as(u8, @intCast(coeff & 0xFF));
            sk[sk_idx + 1] = @as(u8, @intCast(coeff >> 8));
            sk_idx += 2;
        }
    }
}

// IND-CPA encryption
fn indcpaEnc(allocator: std.mem.Allocator, params: Params, ct: []u8, m: []const u8, pk: []const u8, coins: []const u8) !void {
    var seed: [SYMBYTES]u8 = undefined;
    @memcpy(&seed, pk[pk.len - SYMBYTES ..]);

    // Generate matrix A
    var matrix = try genMatrix(allocator, params.k, &seed);
    defer {
        for (matrix) |*row| {
            row.deinit(allocator);
        }
        allocator.free(matrix);
    }

    // Decode public key
    var t = try PolyVec.init(allocator, params.k);
    defer t.deinit(allocator);

    var pk_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            const coeff = @as(u16, pk[pk_idx]) | (@as(u16, pk[pk_idx + 1]) << 8);
            t.vec[i].coeffs[j] = @as(i16, @intCast(coeff));
            pk_idx += 2;
        }
    }

    // Generate random vector r
    var r = try PolyVec.init(allocator, params.k);
    defer r.deinit(allocator);

    for (0..params.k) |i| {
        // CBD needs 2*eta*256 bits = 64*eta bytes per polynomial
        const buf_size = 64 * params.eta2;
        var buf: [64 * 2]u8 = undefined; // Max eta2 is 2, so 128 bytes
        @memcpy(buf[0..buf_size], coins[i * buf_size .. (i + 1) * buf_size]);
        r.vec[i] = cbd(params.eta2, buf[0..buf_size]);
    }

    // Generate error polynomial e1
    const e1_start = params.k * 64 * params.eta2;
    const e1 = cbd(params.eta2, coins[e1_start .. e1_start + 64 * params.eta2]);

    // Compute u = A^T * r + e1
    r.ntt();
    var u = try PolyVec.init(allocator, params.k);
    defer u.deinit(allocator);

    for (0..params.k) |i| {
        u.vec[i] = Poly.init();
        for (0..params.k) |j| {
            const prod = matrix[j].vec[i].mul(r.vec[j]); // A^T means swap i,j
            u.vec[i].add(prod);
        }
        u.vec[i].add(e1);
    }

    u.invNtt();

    // Compress u
    var ct_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            ct[ct_idx] = compress(params.du, u.vec[i].coeffs[j]);
            ct_idx += 1;
        }
    }

    // Encode message as polynomial
    var m_poly = Poly.init();
    for (0..N / 8) |i| {
        for (0..8) |j| {
            const bit = (m[i] >> @as(u3, @intCast(j))) & 1;
            m_poly.coeffs[8 * i + j] = @as(i16, @intCast(@as(i16, bit) * ((Q + 1) / 2)));
        }
    }

    // Compute v = t^T * r + e2 + m'
    t.ntt();
    var v = Poly.init();
    for (0..params.k) |i| {
        const prod = t.vec[i].mul(r.vec[i]);
        v.add(prod);
    }

    // Add e2 (simplified)
    const e2_buf_size = 64 * params.eta2;
    var e2_buf: [64 * 2]u8 = undefined; // Max eta2 is 2, so 128 bytes
    rng.randomBytes(e2_buf[0..e2_buf_size]);
    const e2 = cbd(params.eta2, e2_buf[0..e2_buf_size]);
    v.add(e2);

    v.add(m_poly);
    v.invNtt();

    // Compress v
    for (0..N) |i| {
        ct[ct_idx] = compress(params.dv, v.coeffs[i]);
        ct_idx += 1;
    }
}

// IND-CPA decryption
fn indcpaDec(allocator: std.mem.Allocator, params: Params, m: []u8, ct: []const u8, sk: []const u8) !void {
    // Decode secret key
    var s = try PolyVec.init(allocator, params.k);
    defer s.deinit(allocator);

    var sk_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            const coeff = @as(u16, sk[sk_idx]) | (@as(u16, sk[sk_idx + 1]) << 8);
            s.vec[i].coeffs[j] = @as(i16, @intCast(coeff));
            sk_idx += 2;
        }
    }

    // Decompress u
    var u = try PolyVec.init(allocator, params.k);
    defer u.deinit(allocator);

    var ct_idx: usize = 0;
    for (0..params.k) |i| {
        for (0..N) |j| {
            u.vec[i].coeffs[j] = decompress(params.du, ct[ct_idx]);
            ct_idx += 1;
        }
    }

    // Decompress v
    var v = Poly.init();
    for (0..N) |i| {
        v.coeffs[i] = decompress(params.dv, ct[ct_idx]);
        ct_idx += 1;
    }

    // Compute m = v - s^T * u
    u.ntt();
    s.ntt();

    var sum = Poly.init();
    for (0..params.k) |i| {
        const prod = s.vec[i].mul(u.vec[i]);
        sum.add(prod);
    }

    sum.invNtt();
    v.sub(sum);

    // Extract message
    for (0..N / 8) |i| {
        var byte: u8 = 0;
        for (0..8) |j| {
            const coeff = v.coeffs[8 * i + j];
            const bit = @as(u8, @intCast(@divTrunc(@mod(coeff * 2 + Q, Q), (Q + 1) / 2)));
            byte |= bit << @as(u3, @intCast(j));
        }
        m[i] = byte;
    }
}

// Hash functions (simplified)
fn hashH(out: []u8, in: []const u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(in);
    hasher.final(out);
}

fn hashG(out: []u8, in: []const u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(in);
    hasher.final(out);
}

fn kdf(out: []u8, in: []const u8) void {
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(in);
    hasher.final(out);
}

// Constant-time select
fn cmov(r: []u8, x: []const u8, len: usize, b: u8) void {
    const b_mask = @as(u8, 0) -% b;
    for (0..len) |i| {
        r[i] = (r[i] & ~b_mask) | (x[i] & b_mask);
    }
}

// Verify (constant-time comparison)
fn verify(a: []const u8, b: []const u8, len: usize) u8 {
    var r: u8 = 0;
    for (0..len) |i| {
        r |= a[i] ^ b[i];
    }
    return r;
}

// Main Kyber functions
pub fn generate_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    const params = Params.fromAlgo(algo);

    const pk_len = params.k * N * 2 + SYMBYTES;
    const sk_len = params.k * N * 2 + pk_len + 2 * SYMBYTES;

    const public_key = try allocator.alloc(u8, pk_len);
    var private_key = try allocator.alloc(u8, sk_len);

    try indcpaKeypair(allocator, params, public_key, private_key);

    // Add public key to secret key (IND-CPA format)
    @memcpy(private_key[params.k * N * 2 .. private_key.len - 2 * SYMBYTES], public_key);

    // Add hash of public key
    var h_pk: [SYMBYTES]u8 = undefined;
    hashH(&h_pk, public_key);
    @memcpy(private_key[private_key.len - 2 * SYMBYTES .. private_key.len - SYMBYTES], &h_pk);

    // Add random z for rejection sampling
    var z: [SYMBYTES]u8 = undefined;
    rng.randomBytes(&z);
    @memcpy(private_key[private_key.len - SYMBYTES ..], &z);

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
        .algorithm = algo,
    };
}

pub fn encrypt(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !Ciphertext {
    const params = Params.fromAlgo(algo);

    const ct_len = params.k * N + N; // Compressed u + compressed v

    const ciphertext = try allocator.alloc(u8, ct_len);

    // Generate random message representative
    var buf: [2 * SYMBYTES]u8 = undefined;
    rng.randomBytes(buf[0..SYMBYTES]);
    hashH(buf[0..SYMBYTES], buf[0..SYMBYTES]); // Don't release system RNG

    // Generate coins
    hashH(buf[SYMBYTES..], public_key);
    var kr: [2 * SYMBYTES]u8 = undefined;
    hashG(&kr, &buf);

    // Encrypt
    try indcpaEnc(allocator, params, ciphertext, message, public_key, kr[SYMBYTES..]);

    // Compute shared secret
    var ss: [SSBYTES]u8 = undefined;
    hashH(kr[SYMBYTES..], ciphertext);
    kdf(&ss, &kr);

    return Ciphertext{
        .data = ciphertext,
        .algorithm = algo,
    };
}

pub fn decrypt(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: []const u8) ![]u8 {
    const algo = Algorithm.Kyber512; // Simplified - would need to determine from key
    const params = Params.fromAlgo(algo);

    var buf: [2 * SYMBYTES]u8 = undefined;
    var kr: [2 * SYMBYTES]u8 = undefined;

    // Decrypt IND-CPA
    try indcpaDec(allocator, params, buf[0..SYMBYTES], ciphertext, private_key);

    // Multitarget countermeasure
    @memcpy(buf[SYMBYTES..], private_key[private_key.len - 2 * SYMBYTES .. private_key.len - SYMBYTES]);
    hashG(&kr, &buf);

    // Re-encrypt and check
    const pk_start = params.k * N * 2;
    const pk_end = pk_start + params.k * N * 2 + SYMBYTES;
    const pk = private_key[pk_start..pk_end];

    const cmp = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(cmp);
    try indcpaEnc(allocator, params, cmp, buf[0..SYMBYTES], pk, kr[SYMBYTES..]);

    const fail = verify(ciphertext, cmp, ciphertext.len);

    // Update kr with hash of ciphertext
    hashH(kr[SYMBYTES..], ciphertext);

    // Conditional move for rejection
    cmov(&kr, private_key[private_key.len - SYMBYTES ..], SYMBYTES, fail);

    // Compute shared secret
    var ss: [SSBYTES]u8 = undefined;
    kdf(&ss, &kr);

    const result = try allocator.alloc(u8, SSBYTES);
    @memcpy(result, &ss);
    return result;
}
