//! Hybrid Post-Quantum + Classical Cryptography
//! Combines PQC algorithms with classical cryptography for transition security
//! Provides dual-layer protection against both classical and quantum attacks

const std = @import("std");
const classical = @import("../classic/root.zig");
const security = @import("../security.zig");
const kyber = @import("kyber.zig");
const dilithium = @import("dilithium.zig");
const sphincs = @import("sphincs.zig");

const Algorithm = @import("../root.zig").Algorithm;
const KeyPair = @import("../root.zig").KeyPair;
const Signature = @import("../root.zig").Signature;
const Ciphertext = @import("../root.zig").Ciphertext;

const Sha512 = std.crypto.hash.sha2.Sha512;
const random = std.crypto.random;

const x25519 = classical.x25519;
const ed25519 = classical.ed25519;
const aead = classical.aead;

const HybridError = error{
    InvalidKeyLength,
    InvalidCiphertext,
    UnsupportedAlgorithm,
};

fn baseAlgorithm(algo: Algorithm) !Algorithm {
    return switch (algo) {
        .Kyber512_AES256 => Algorithm.Kyber512,
        .Kyber768_AES256 => Algorithm.Kyber768,
        .Kyber1024_AES256 => Algorithm.Kyber1024,
        else => HybridError.UnsupportedAlgorithm,
    };
}

fn splitHybridPublicKey(algo: Algorithm, public_key: []const u8) !struct {
    kyber: []const u8,
    classic: []const u8,
} {
    const base = try baseAlgorithm(algo);
    const kyber_len = kyber.publicKeyLength(base);
    const classical_len = x25519.PublicKeyLength;

    if (public_key.len != kyber_len + classical_len) return HybridError.InvalidKeyLength;

    return .{
        .kyber = public_key[0..kyber_len],
        .classic = public_key[kyber_len..],
    };
}

fn splitHybridPrivateKey(algo: Algorithm, private_key: []const u8) !struct {
    kyber: []const u8,
    classic: []const u8,
} {
    const base = try baseAlgorithm(algo);
    const kyber_len = kyber.privateKeyLength(base);
    const classical_len = x25519.PrivateKeyLength;

    if (private_key.len != kyber_len + classical_len) return HybridError.InvalidKeyLength;

    return .{
        .kyber = private_key[0..kyber_len],
        .classic = private_key[kyber_len..],
    };
}

fn deriveHybridSecret(kyber_shared: []const u8, classical_shared: []const u8, ephemeral_public: []const u8, algo: Algorithm) [64]u8 {
    var hasher = Sha512.init(.{});
    hasher.update("kriptix.hybrid.kem");
    const algo_bytes = std.mem.toBytes(@as(u32, @intCast(@intFromEnum(algo))));
    hasher.update(algo_bytes[0..]);
    hasher.update(kyber_shared);
    hasher.update(classical_shared);
    hasher.update(ephemeral_public);

    var out: [64]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn freeKeyPair(allocator: std.mem.Allocator, kp: *KeyPair) void {
    if (kp.public_key.len > 0) allocator.free(kp.public_key);
    if (kp.private_key.len > 0) {
        security.SecureMemory.secure_zero(kp.private_key);
        allocator.free(kp.private_key);
    }
    kp.public_key = &[_]u8{};
    kp.private_key = &[_]u8{};
}

fn freeSignature(allocator: std.mem.Allocator, sig: *Signature) void {
    if (sig.data.len > 0) {
        security.SecureMemory.secure_zero(sig.data);
        allocator.free(sig.data);
    }
    sig.data = &[_]u8{};
}

/// Hybrid key exchange combining Kyber KEM with classical X25519
pub const HybridKEM = struct {
    kyber_keypair: KeyPair,
    x25519_keypair: x25519.KeyPair,

    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !HybridKEM {
        var kyber_kp = try kyber.generate_keypair(allocator, pq_algo);
        errdefer freeKeyPair(allocator, &kyber_kp);

        const x_pair = try x25519.generateKeypair(allocator);
        errdefer x_pair.deinit(allocator);

        return HybridKEM{ .kyber_keypair = kyber_kp, .x25519_keypair = x_pair };
    }

    pub fn encapsulate(self: *const HybridKEM, allocator: std.mem.Allocator) !struct {
        ciphertext: []u8,
        shared_secret: []u8,
    } {
        const base_algo = self.kyber_keypair.algorithm;
        const kem_result = try kyber.encapsulate(allocator, self.kyber_keypair.public_key, base_algo);
        defer allocator.free(kem_result.ciphertext);
        defer allocator.free(kem_result.shared_secret);

        const eph = try x25519.generateKeypair(allocator);
        defer eph.deinit(allocator);

        const classical_shared = try x25519.computeSharedSecret(allocator, eph.private_key, self.x25519_keypair.public_key);
        defer allocator.free(classical_shared);

        var derived = deriveHybridSecret(kem_result.shared_secret, classical_shared, eph.public_key, base_algo);
        defer security.SecureMemory.secure_zero(derived[0..]);

        const combined_len = kem_result.ciphertext.len + x25519.PublicKeyLength;
        const combined = try allocator.alloc(u8, combined_len);
        @memcpy(combined[0..kem_result.ciphertext.len], kem_result.ciphertext);
        @memcpy(combined[kem_result.ciphertext.len..], eph.public_key);

        const shared_secret = try allocator.alloc(u8, derived.len);
        @memcpy(shared_secret, derived[0..]);

        return .{ .ciphertext = combined, .shared_secret = shared_secret };
    }

    pub fn decapsulate(self: *const HybridKEM, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        const base_algo = self.kyber_keypair.algorithm;
        const kyber_ct_len = kyber.ciphertextLength(base_algo);

        if (ciphertext.len != kyber_ct_len + x25519.PublicKeyLength) return HybridError.InvalidCiphertext;

        const kyber_ct = ciphertext[0..kyber_ct_len];
        const eph_public = ciphertext[kyber_ct_len..];

        const kyber_shared = try kyber.decapsulate(allocator, self.kyber_keypair.private_key, kyber_ct, base_algo);
        defer allocator.free(kyber_shared);

        const classical_shared = try x25519.computeSharedSecret(allocator, self.x25519_keypair.private_key, eph_public);
        defer allocator.free(classical_shared);

        var derived = deriveHybridSecret(kyber_shared, classical_shared, eph_public, base_algo);
        defer security.SecureMemory.secure_zero(derived[0..]);

        const shared_secret = try allocator.alloc(u8, derived.len);
        @memcpy(shared_secret, derived[0..]);
        return shared_secret;
    }

    pub fn deinit(self: *HybridKEM, allocator: std.mem.Allocator) void {
        freeKeyPair(allocator, &self.kyber_keypair);
        self.x25519_keypair.deinit(allocator);
    }
};

/// Hybrid signatures combining Dilithium with Ed25519
pub const HybridSignature = struct {
    dilithium_keypair: KeyPair,
    ed25519_keypair: ed25519.KeyPair,

    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !HybridSignature {
        var dilithium_kp = try dilithium.generate_keypair(allocator, pq_algo);
        errdefer freeKeyPair(allocator, &dilithium_kp);

        var ed_kp = try ed25519.generateKeypair(allocator);
        errdefer ed_kp.deinit(allocator);

        return HybridSignature{
            .dilithium_keypair = dilithium_kp,
            .ed25519_keypair = ed_kp,
        };
    }

    pub fn sign(self: *const HybridSignature, allocator: std.mem.Allocator, message: []const u8) !HybridSignatureData {
        var dilithium_sig = try dilithium.sign(allocator, self.dilithium_keypair.private_key, message, self.dilithium_keypair.algorithm);
        errdefer freeSignature(allocator, &dilithium_sig);

        const ed_sig = try ed25519.sign(allocator, message, self.ed25519_keypair.private_key);
        errdefer allocator.free(ed_sig);

        return HybridSignatureData{
            .dilithium_signature = dilithium_sig,
            .ed25519_signature = ed_sig,
        };
    }

    pub fn verify(self: *const HybridSignature, message: []const u8, signature: HybridSignatureData) !bool {
        const dilithium_valid = try dilithium.verify(self.dilithium_keypair.public_key, message, signature.dilithium_signature.data);
        const ed_valid = try ed25519.verify(signature.ed25519_signature, message, self.ed25519_keypair.public_key);
        return dilithium_valid and ed_valid;
    }

    pub fn deinit(self: *HybridSignature, allocator: std.mem.Allocator) void {
        freeKeyPair(allocator, &self.dilithium_keypair);
        self.ed25519_keypair.deinit(allocator);
    }
};

pub const HybridSignatureData = struct {
    dilithium_signature: Signature,
    ed25519_signature: []u8,

    pub fn deinit(self: *HybridSignatureData, allocator: std.mem.Allocator) void {
        freeSignature(allocator, &self.dilithium_signature);
        allocator.free(self.ed25519_signature);
        self.ed25519_signature = &[_]u8{};
    }
};

/// SPHINCS+ with Ed25519 backup signature
pub const SphincsRsaHybrid = struct {
    sphincs_keypair: KeyPair,
    ed25519_keypair: ed25519.KeyPair,

    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !SphincsRsaHybrid {
        var sphincs_kp = try sphincs.generate_keypair(allocator, pq_algo);
        errdefer freeKeyPair(allocator, &sphincs_kp);

        const ed_kp = try ed25519.generateKeypair(allocator);
        errdefer ed_kp.deinit(allocator);

        return SphincsRsaHybrid{
            .sphincs_keypair = sphincs_kp,
            .ed25519_keypair = ed_kp,
        };
    }

    pub fn sign(self: *const SphincsRsaHybrid, allocator: std.mem.Allocator, message: []const u8) !SphincsRsaSignature {
        var sphincs_sig = try sphincs.sign(allocator, self.sphincs_keypair.private_key, message, self.sphincs_keypair.algorithm);
        errdefer freeSignature(allocator, &sphincs_sig);

        const ed_sig = try ed25519.sign(allocator, message, self.ed25519_keypair.private_key);
        errdefer allocator.free(ed_sig);

        return SphincsRsaSignature{
            .sphincs_signature = sphincs_sig,
            .ed25519_signature = ed_sig,
        };
    }

    pub fn verify(self: *const SphincsRsaHybrid, message: []const u8, signature: SphincsRsaSignature) !bool {
        const sphincs_valid = try sphincs.verify(self.sphincs_keypair.public_key, message, signature.sphincs_signature.data);
        const ed_valid = try ed25519.verify(signature.ed25519_signature, message, self.ed25519_keypair.public_key);
        return sphincs_valid and ed_valid;
    }

    pub fn deinit(self: *SphincsRsaHybrid, allocator: std.mem.Allocator) void {
        freeKeyPair(allocator, &self.sphincs_keypair);
        self.ed25519_keypair.deinit(allocator);
    }
};

pub const SphincsRsaSignature = struct {
    sphincs_signature: Signature,
    ed25519_signature: []u8,

    pub fn deinit(self: *SphincsRsaSignature, allocator: std.mem.Allocator) void {
        freeSignature(allocator, &self.sphincs_signature);
        allocator.free(self.ed25519_signature);
        self.ed25519_signature = &[_]u8{};
    }
};

pub fn generate_hybrid_kem_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    const base = try baseAlgorithm(algo);

    var kyber_kp = try kyber.generate_keypair(allocator, base);
    errdefer freeKeyPair(allocator, &kyber_kp);

    var x_pair = try x25519.generateKeypair(allocator);
    errdefer x_pair.deinit(allocator);

    const public_len = kyber.publicKeyLength(base) + x25519.PublicKeyLength;
    const public_key = try allocator.alloc(u8, public_len);
    errdefer allocator.free(public_key);
    @memcpy(public_key[0..kyber.publicKeyLength(base)], kyber_kp.public_key);
    @memcpy(public_key[kyber.publicKeyLength(base)..], x_pair.public_key);

    const private_len = kyber.privateKeyLength(base) + x25519.PrivateKeyLength;
    const private_key = try allocator.alloc(u8, private_len);
    errdefer allocator.free(private_key);
    @memcpy(private_key[0..kyber.privateKeyLength(base)], kyber_kp.private_key);
    @memcpy(private_key[kyber.privateKeyLength(base)..], x_pair.private_key);

    freeKeyPair(allocator, &kyber_kp);
    x_pair.deinit(allocator);

    return KeyPair{ .public_key = public_key, .private_key = private_key, .algorithm = algo };
}

pub fn encrypt_hybrid(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !Ciphertext {
    const segments = try splitHybridPublicKey(algo, public_key);
    const base = try baseAlgorithm(algo);

    const kem = try kyber.encapsulate(allocator, segments.kyber, base);
    defer allocator.free(kem.ciphertext);
    defer allocator.free(kem.shared_secret);

    var eph = try x25519.generateKeypair(allocator);
    defer eph.deinit(allocator);

    const classical_shared = try x25519.computeSharedSecret(allocator, eph.private_key, segments.classic);
    defer allocator.free(classical_shared);

    var derived = deriveHybridSecret(kem.shared_secret, classical_shared, eph.public_key, base);
    defer security.SecureMemory.secure_zero(derived[0..]);

    var key: [aead.KeyLength]u8 = undefined;
    @memcpy(&key, derived[0..aead.KeyLength]);

    var nonce: [aead.NonceLength]u8 = undefined;
    random.bytes(&nonce);

    const aead_result = try aead.encrypt(allocator, &key, &nonce, message, eph.public_key);
    defer allocator.free(aead_result.ciphertext);
    aead.zeroKey(&key);

    const total_len = kem.ciphertext.len + x25519.PublicKeyLength + aead.NonceLength + aead_result.ciphertext.len + aead.TagLength;
    const combined = try allocator.alloc(u8, total_len);

    var offset: usize = 0;
    @memcpy(combined[offset .. offset + kem.ciphertext.len], kem.ciphertext);
    offset += kem.ciphertext.len;
    @memcpy(combined[offset .. offset + x25519.PublicKeyLength], eph.public_key);
    offset += x25519.PublicKeyLength;
    @memcpy(combined[offset .. offset + aead.NonceLength], &nonce);
    offset += aead.NonceLength;
    @memcpy(combined[offset .. offset + aead_result.ciphertext.len], aead_result.ciphertext);
    offset += aead_result.ciphertext.len;
    @memcpy(combined[offset .. offset + aead.TagLength], &aead_result.tag);
    offset += aead.TagLength;
    std.debug.assert(offset == total_len);

    return Ciphertext{ .data = combined, .algorithm = algo };
}

pub fn decrypt_hybrid(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: Ciphertext) ![]u8 {
    const segments = try splitHybridPrivateKey(ciphertext.algorithm, private_key);
    const base = try baseAlgorithm(ciphertext.algorithm);

    const kyber_ct_len = kyber.ciphertextLength(base);
    const min_len = kyber_ct_len + x25519.PublicKeyLength + aead.NonceLength + aead.TagLength;
    if (ciphertext.data.len < min_len) return HybridError.InvalidCiphertext;

    const eph_offset = kyber_ct_len;
    const nonce_offset = eph_offset + x25519.PublicKeyLength;
    const payload_offset = nonce_offset + aead.NonceLength;
    const payload_end = ciphertext.data.len - aead.TagLength;
    if (payload_end < payload_offset) return HybridError.InvalidCiphertext;

    const kyber_ct = ciphertext.data[0..kyber_ct_len];
    const eph_public = ciphertext.data[eph_offset .. eph_offset + x25519.PublicKeyLength];

    var nonce: [aead.NonceLength]u8 = undefined;
    @memcpy(&nonce, ciphertext.data[nonce_offset .. nonce_offset + aead.NonceLength]);

    const payload = ciphertext.data[payload_offset..payload_end];

    var tag: [aead.TagLength]u8 = undefined;
    @memcpy(&tag, ciphertext.data[payload_end..]);

    const kyber_shared = try kyber.decapsulate(allocator, segments.kyber, kyber_ct, base);
    defer allocator.free(kyber_shared);

    const classical_shared = try x25519.computeSharedSecret(allocator, segments.classic, eph_public);
    defer allocator.free(classical_shared);

    var derived = deriveHybridSecret(kyber_shared, classical_shared, eph_public, base);
    defer security.SecureMemory.secure_zero(derived[0..]);

    var key: [aead.KeyLength]u8 = undefined;
    @memcpy(&key, derived[0..aead.KeyLength]);

    const plaintext = try aead.decrypt(allocator, &key, &nonce, payload, eph_public, tag);
    aead.zeroKey(&key);
    return plaintext;
}
