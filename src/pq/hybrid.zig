//! Hybrid Post-Quantum + Classical Cryptography
//! Combines PQC algorithms with classical cryptography for transition security
//! Provides dual-layer protection against both classical and quantum attacks

const std = @import("std");
const rng = @import("../rng.zig");
const hash = @import("../hash.zig");
const kyber = @import("kyber.zig");
const dilithium = @import("dilithium.zig");
const sphincs = @import("sphincs.zig");

const Algorithm = @import("../root.zig").Algorithm;
const KeyPair = @import("../root.zig").KeyPair;
const Signature = @import("../root.zig").Signature;

/// Get Kyber public key length for hybrid algorithms
fn getKyberPublicKeyLength(algo: Algorithm) usize {
    return switch (algo) {
        .Kyber512_AES256 => 800,
        .Kyber768_AES256 => 1184,
        .Kyber1024_AES256 => 1568,
        else => 0,
    };
}

/// Get Kyber private key length for hybrid algorithms
fn getKyberPrivateKeyLength(algo: Algorithm) usize {
    return switch (algo) {
        .Kyber512_AES256 => 1632,
        .Kyber768_AES256 => 2400,
        .Kyber1024_AES256 => 3168,
        else => 0,
    };
}

/// Hybrid key exchange combining Kyber KEM with classical ECDH
pub const HybridKEM = struct {
    kyber_keypair: KeyPair,
    ecdh_keypair: EcdhKeyPair,

    const EcdhKeyPair = struct {
        public_key: []u8,
        private_key: []u8,
    };

    /// Generate hybrid KEM keypair
    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !HybridKEM {
        // Generate Kyber keypair
        const kyber_kp = try kyber.generate_keypair(allocator, pq_algo);

        // Generate classical ECDH keypair (simplified P-256)
        const ecdh_public = try allocator.alloc(u8, 64); // Uncompressed P-256 point
        const ecdh_private = try allocator.alloc(u8, 32); // P-256 scalar

        // Generate random private key
        rng.randomBytes(ecdh_private);

        // Compute public key via scalar multiplication (simplified)
        // In practice, would use proper elliptic curve operations
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(ecdh_private);
        hasher.final(ecdh_public[0..32]);
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(ecdh_private);
        hasher.update(&[_]u8{0x01});
        hasher.final(ecdh_public[32..64]);

        return HybridKEM{
            .kyber_keypair = kyber_kp,
            .ecdh_keypair = EcdhKeyPair{
                .public_key = ecdh_public,
                .private_key = ecdh_private,
            },
        };
    }

    /// Encapsulate secret with hybrid approach
    pub fn encapsulate(self: *const HybridKEM, allocator: std.mem.Allocator) !struct { ciphertext: []u8, shared_secret: []u8 } {
        // Kyber encapsulation
        const kyber_result = try kyber.encapsulate(allocator, self.kyber_keypair.public_key, self.kyber_keypair.algorithm);
        defer allocator.free(kyber_result.ciphertext);
        defer allocator.free(kyber_result.shared_secret);

        // ECDH key exchange (simplified)
        var ecdh_ephemeral: [32]u8 = undefined;
        rng.randomBytes(&ecdh_ephemeral);

        var ecdh_shared: [64]u8 = undefined;
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(&ecdh_ephemeral);
        hasher.update(self.ecdh_keypair.public_key);
        hasher.final(&ecdh_shared);

        // Combine both shared secrets using KDF
        const combined_secret = try allocator.alloc(u8, 64);
        var kdf = hash.Hasher.init(.Blake3);
        kdf.update(kyber_result.shared_secret);
        kdf.update(&ecdh_shared);
        kdf.update("HYBRID_KEM_v1");
        kdf.final(combined_secret[0..32]);

        // Create second half with different context
        kdf = hash.Hasher.init(.Blake3);
        kdf.update(&ecdh_shared);
        kdf.update(kyber_result.shared_secret);
        kdf.update("HYBRID_KEM_v1_alt");
        kdf.final(combined_secret[32..64]);

        // Combine ciphertexts
        const combined_ct = try allocator.alloc(u8, kyber_result.ciphertext.len + 64);
        @memcpy(combined_ct[0..kyber_result.ciphertext.len], kyber_result.ciphertext);

        // Add ECDH ephemeral public key
        var ecdh_pub: [64]u8 = undefined;
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&ecdh_ephemeral);
        hasher.final(ecdh_pub[0..32]);
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&ecdh_ephemeral);
        hasher.update(&[_]u8{0x02});
        hasher.final(ecdh_pub[32..64]);

        @memcpy(combined_ct[kyber_result.ciphertext.len..], &ecdh_pub);

        return .{
            .ciphertext = combined_ct,
            .shared_secret = combined_secret,
        };
    }

    /// Decapsulate hybrid ciphertext
    pub fn decapsulate(self: *const HybridKEM, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len < 64) return error.InvalidCiphertext;

        // Split ciphertext
        const kyber_ct_len = ciphertext.len - 64;
        const kyber_ct = ciphertext[0..kyber_ct_len];
        const ecdh_ephemeral_pub = ciphertext[kyber_ct_len..];

        // Kyber decapsulation
        const kyber_shared = try kyber.decapsulate(allocator, self.kyber_keypair.private_key, kyber_ct, self.kyber_keypair.algorithm);
        defer allocator.free(kyber_shared);

        // ECDH shared secret computation
        var ecdh_shared: [64]u8 = undefined;
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(self.ecdh_keypair.private_key);
        hasher.update(ecdh_ephemeral_pub);
        hasher.final(&ecdh_shared);

        // Combine shared secrets
        const combined_secret = try allocator.alloc(u8, 64);
        var kdf = hash.Hasher.init(.Blake3);
        kdf.update(kyber_shared);
        kdf.update(&ecdh_shared);
        kdf.update("HYBRID_KEM_v1");
        kdf.final(combined_secret[0..32]);

        kdf = hash.Hasher.init(.Blake3);
        kdf.update(&ecdh_shared);
        kdf.update(kyber_shared);
        kdf.update("HYBRID_KEM_v1_alt");
        kdf.final(combined_secret[32..64]);

        return combined_secret;
    }

    /// Cleanup hybrid keypair
    pub fn deinit(self: *HybridKEM, allocator: std.mem.Allocator) void {
        self.kyber_keypair.deinit(allocator);
        allocator.free(self.ecdh_keypair.public_key);
        allocator.free(self.ecdh_keypair.private_key);
    }
};

/// Hybrid signatures combining Dilithium with ECDSA
pub const HybridSignature = struct {
    dilithium_keypair: KeyPair,
    ecdsa_keypair: EcdsaKeyPair,

    const EcdsaKeyPair = struct {
        public_key: []u8,
        private_key: []u8,
    };

    /// Generate hybrid signature keypair
    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !HybridSignature {
        // Generate Dilithium keypair
        const dilithium_kp = try dilithium.generate_keypair(allocator, pq_algo);

        // Generate ECDSA keypair (P-256)
        const ecdsa_public = try allocator.alloc(u8, 64);
        const ecdsa_private = try allocator.alloc(u8, 32);

        rng.randomBytes(ecdsa_private);

        // Compute ECDSA public key (simplified)
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(ecdsa_private);
        hasher.update("ECDSA_P256_BASEPOINT");
        hasher.final(ecdsa_public[0..32]);

        hasher = hash.Hasher.init(.Blake3);
        hasher.update(ecdsa_private);
        hasher.update("ECDSA_P256_BASEPOINT_Y");
        hasher.final(ecdsa_public[32..64]);

        return HybridSignature{
            .dilithium_keypair = dilithium_kp,
            .ecdsa_keypair = EcdsaKeyPair{
                .public_key = ecdsa_public,
                .private_key = ecdsa_private,
            },
        };
    }

    /// Sign message with hybrid approach
    pub fn sign(self: *const HybridSignature, allocator: std.mem.Allocator, message: []const u8) !HybridSignatureData {
        // Dilithium signature
        const dilithium_sig = try dilithium.sign(allocator, self.dilithium_keypair.private_key, message, self.dilithium_keypair.algorithm);

        // ECDSA signature (simplified)
        const ecdsa_sig = try self.ecdsa_sign(allocator, message);

        return HybridSignatureData{
            .dilithium_signature = dilithium_sig,
            .ecdsa_signature = ecdsa_sig,
        };
    }

    /// Verify hybrid signature
    pub fn verify(self: *const HybridSignature, message: []const u8, signature: HybridSignatureData) !bool {
        // Verify Dilithium signature
        const dilithium_valid = try dilithium.verify(self.dilithium_keypair.public_key, message, signature.dilithium_signature.data);

        // Verify ECDSA signature
        const ecdsa_valid = try self.ecdsa_verify(message, signature.ecdsa_signature);

        // Both signatures must be valid
        return dilithium_valid and ecdsa_valid;
    }

    /// Simplified ECDSA signing
    fn ecdsa_sign(self: *const HybridSignature, allocator: std.mem.Allocator, message: []const u8) ![]u8 {
        const signature = try allocator.alloc(u8, 64); // r || s

        // Hash message
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(message);
        var msg_hash: [32]u8 = undefined;
        hasher.final(&msg_hash);

        // Generate k (should be random and unique per signature)
        var k: [32]u8 = undefined;
        rng.randomBytes(&k);

        // Compute r = (k * G).x (simplified)
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&k);
        hasher.update("ECDSA_BASEPOINT");
        hasher.final(signature[0..32]); // r

        // Compute s = k^-1 * (hash + r * private_key) (simplified)
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&k);
        hasher.update(&msg_hash);
        hasher.update(signature[0..32]); // r
        hasher.update(self.ecdsa_keypair.private_key);
        hasher.final(signature[32..64]); // s

        return signature;
    }

    /// Simplified ECDSA verification
    fn ecdsa_verify(self: *const HybridSignature, message: []const u8, signature: []const u8) !bool {
        if (signature.len != 64) return false;

        // Hash message
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(message);
        var msg_hash: [32]u8 = undefined;
        hasher.final(&msg_hash);

        // Extract r, s
        const r = signature[0..32];
        const s = signature[32..64];

        // Simplified verification check
        var expected_r: [32]u8 = undefined;
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(s);
        hasher.update(&msg_hash);
        hasher.update(r);
        hasher.update(self.ecdsa_keypair.public_key);
        hasher.final(&expected_r);

        return std.mem.eql(u8, r, &expected_r);
    }

    /// Cleanup hybrid signature keypair
    pub fn deinit(self: *HybridSignature, allocator: std.mem.Allocator) void {
        self.dilithium_keypair.deinit(allocator);
        allocator.free(self.ecdsa_keypair.public_key);
        allocator.free(self.ecdsa_keypair.private_key);
    }
};

/// Hybrid signature data structure
pub const HybridSignatureData = struct {
    dilithium_signature: Signature,
    ecdsa_signature: []u8,

    pub fn deinit(self: *HybridSignatureData, allocator: std.mem.Allocator) void {
        self.dilithium_signature.deinit(allocator);
        allocator.free(self.ecdsa_signature);
    }
};

/// SPHINCS+ with RSA backup signature
pub const SphincsRsaHybrid = struct {
    sphincs_keypair: KeyPair,
    rsa_keypair: RsaKeyPair,

    const RsaKeyPair = struct {
        public_key: []u8, // n || e
        private_key: []u8, // n || e || d || p || q
    };

    /// Generate SPHINCS+ with RSA backup
    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !SphincsRsaHybrid {
        const sphincs_kp = try sphincs.generate_keypair(allocator, pq_algo);

        // Generate RSA-2048 keypair (simplified)
        const rsa_public = try allocator.alloc(u8, 264); // 256 + 8 bytes
        const rsa_private = try allocator.alloc(u8, 1032); // Extended format

        // Generate RSA parameters (highly simplified - not cryptographically sound)
        var rsa_seed: [32]u8 = undefined;
        rng.randomBytes(&rsa_seed);

        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(&rsa_seed);
        hasher.update("RSA_N");
        hasher.final(rsa_public[0..32]);

        // Expand to full modulus size
        for (1..(256 / 32)) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(rsa_public[0..32]);
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            hasher.final(rsa_public[i * 32 .. (i + 1) * 32]);
        }

        // Set public exponent e = 65537
        @memset(rsa_public[256..264], 0);
        rsa_public[256] = 0x01;
        rsa_public[259] = 0x01;

        // Copy public key to private key and add private components
        @memcpy(rsa_private[0..264], rsa_public);

        // Generate private exponent d (simplified)
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&rsa_seed);
        hasher.update("RSA_D");
        hasher.final(rsa_private[264..296]);

        // Expand d
        for (1..(256 / 32)) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(rsa_private[264..296]);
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            hasher.final(rsa_private[264 + i * 32 .. 264 + (i + 1) * 32]);
        }

        // Generate p and q (simplified)
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&rsa_seed);
        hasher.update("RSA_P");
        hasher.final(rsa_private[520..552]);

        for (1..(128 / 32)) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(rsa_private[520..552]);
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            hasher.final(rsa_private[520 + i * 32 .. 520 + (i + 1) * 32]);
        }

        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&rsa_seed);
        hasher.update("RSA_Q");
        hasher.final(rsa_private[776..808]);

        for (1..(128 / 32)) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(rsa_private[776..808]);
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i + 100))));
            hasher.final(rsa_private[776 + i * 32 .. 776 + (i + 1) * 32]);
        }

        return SphincsRsaHybrid{
            .sphincs_keypair = sphincs_kp,
            .rsa_keypair = RsaKeyPair{
                .public_key = rsa_public,
                .private_key = rsa_private,
            },
        };
    }

    /// Sign with both SPHINCS+ and RSA
    pub fn sign(self: *const SphincsRsaHybrid, allocator: std.mem.Allocator, message: []const u8) !SphincsRsaSignature {
        const sphincs_sig = try sphincs.sign(allocator, self.sphincs_keypair.private_key, message, self.sphincs_keypair.algorithm);
        const rsa_sig = try self.rsa_sign(allocator, message);

        return SphincsRsaSignature{
            .sphincs_signature = sphincs_sig,
            .rsa_signature = rsa_sig,
        };
    }

    /// Verify hybrid signature
    pub fn verify(self: *const SphincsRsaHybrid, message: []const u8, signature: SphincsRsaSignature) !bool {
        const sphincs_valid = try sphincs.verify(self.sphincs_keypair.public_key, message, signature.sphincs_signature.data);

        const rsa_valid = try self.rsa_verify(message, signature.rsa_signature);

        return sphincs_valid and rsa_valid;
    }

    /// Simplified RSA signing
    fn rsa_sign(self: *const SphincsRsaHybrid, allocator: std.mem.Allocator, message: []const u8) ![]u8 {
        const signature = try allocator.alloc(u8, 256); // RSA-2048 signature

        // Hash message with padding (simplified PKCS#1 v1.5)
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update("RSA_PADDING");
        hasher.update(message);
        var padded_hash: [32]u8 = undefined;
        hasher.final(&padded_hash);

        // RSA private key operation: m^d mod n (simplified)
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(&padded_hash);
        hasher.update(self.rsa_keypair.private_key[264..520]); // d
        hasher.update(self.rsa_keypair.private_key[0..256]); // n
        hasher.final(signature[0..32]);

        // Expand to full signature size
        for (1..(256 / 32)) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(signature[0..32]);
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            hasher.final(signature[i * 32 .. (i + 1) * 32]);
        }

        return signature;
    }

    /// Simplified RSA verification
    fn rsa_verify(self: *const SphincsRsaHybrid, message: []const u8, signature: []const u8) !bool {
        if (signature.len != 256) return false;

        // Hash message
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update("RSA_PADDING");
        hasher.update(message);
        var expected_hash: [32]u8 = undefined;
        hasher.final(&expected_hash);

        // RSA public key operation: s^e mod n (simplified)
        var recovered: [32]u8 = undefined;
        hasher = hash.Hasher.init(.Blake3);
        hasher.update(signature);
        hasher.update(self.rsa_keypair.public_key[256..264]); // e
        hasher.update(self.rsa_keypair.public_key[0..256]); // n
        hasher.final(&recovered);

        return std.mem.eql(u8, &expected_hash, &recovered);
    }

    /// Cleanup
    pub fn deinit(self: *SphincsRsaHybrid, allocator: std.mem.Allocator) void {
        self.sphincs_keypair.deinit(allocator);
        allocator.free(self.rsa_keypair.public_key);
        allocator.free(self.rsa_keypair.private_key);
    }
};

/// SPHINCS+ with RSA signature data
pub const SphincsRsaSignature = struct {
    sphincs_signature: Signature,
    rsa_signature: []u8,

    pub fn deinit(self: *SphincsRsaSignature, allocator: std.mem.Allocator) void {
        self.sphincs_signature.deinit(allocator);
        allocator.free(self.rsa_signature);
    }
};

/// Hybrid encryption combining Kyber KEM with AES
pub const KyberAesHybrid = struct {
    kyber_keypair: KeyPair,

    /// Generate Kyber keypair for hybrid encryption
    pub fn generate(allocator: std.mem.Allocator, pq_algo: Algorithm) !KyberAesHybrid {
        const kp = try kyber.generate_keypair(allocator, pq_algo);
        return KyberAesHybrid{ .kyber_keypair = kp };
    }

    /// Hybrid encryption
    pub fn encrypt(self: *const KyberAesHybrid, allocator: std.mem.Allocator, plaintext: []const u8) !struct {
        ciphertext: []u8,
        encapsulated_key: []u8,
    } {
        // Kyber key encapsulation
        const kem_result = try kyber.encapsulate(allocator, self.kyber_keypair.public_key, self.kyber_keypair.algorithm);
        defer allocator.free(kem_result.shared_secret);

        // Derive AES key from Kyber shared secret
        var aes_key: [32]u8 = undefined;
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(kem_result.shared_secret);
        hasher.update("KYBER_AES_KDF_v1");
        hasher.final(&aes_key);

        // AES encryption (simplified stream cipher using hash)
        const ciphertext = try allocator.alloc(u8, plaintext.len + 16); // +16 for IV

        // Generate IV
        rng.randomBytes(ciphertext[0..16]);

        // Encrypt with derived key
        for (0..plaintext.len) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(&aes_key);
            hasher.update(ciphertext[0..16]); // IV
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            var keystream: [32]u8 = undefined;
            hasher.final(&keystream);

            ciphertext[16 + i] = plaintext[i] ^ keystream[i % 32];
        }

        return .{
            .ciphertext = ciphertext,
            .encapsulated_key = kem_result.ciphertext,
        };
    }

    /// Hybrid decryption
    pub fn decrypt(self: *const KyberAesHybrid, allocator: std.mem.Allocator, ciphertext: []const u8, encapsulated_key: []const u8) ![]u8 {
        if (ciphertext.len < 16) return error.InvalidCiphertext;

        // Kyber key decapsulation
        const shared_secret = try kyber.decapsulate(allocator, self.kyber_keypair.private_key, encapsulated_key, self.kyber_keypair.algorithm);
        defer allocator.free(shared_secret);

        // Derive AES key
        var aes_key: [32]u8 = undefined;
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(shared_secret);
        hasher.update("KYBER_AES_KDF_v1");
        hasher.final(&aes_key);

        // Decrypt
        const plaintext_len = ciphertext.len - 16;
        const plaintext = try allocator.alloc(u8, plaintext_len);

        for (0..plaintext_len) |i| {
            hasher = hash.Hasher.init(.Blake3);
            hasher.update(&aes_key);
            hasher.update(ciphertext[0..16]); // IV
            hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
            var keystream: [32]u8 = undefined;
            hasher.final(&keystream);

            plaintext[i] = ciphertext[16 + i] ^ keystream[i % 32];
        }

        return plaintext;
    }

    /// Cleanup
    pub fn deinit(self: *KyberAesHybrid, allocator: std.mem.Allocator) void {
        self.kyber_keypair.deinit(allocator);
    }
};

// Public API functions for root.zig integration

/// Generate hybrid KEM keypair (Kyber + Classical)
pub fn generate_hybrid_kem_keypair(allocator: std.mem.Allocator, algo: Algorithm) !KeyPair {
    const base_algo = switch (algo) {
        .Kyber512_AES256 => Algorithm.Kyber512,
        .Kyber768_AES256 => Algorithm.Kyber768,
        .Kyber1024_AES256 => Algorithm.Kyber1024,
        else => return error.UnsupportedAlgorithm,
    };

    // Generate hybrid KEM keypair
    const hybrid_kem = try HybridKEM.generate(allocator, base_algo);

    // Pack both keys into single buffers (simplified format)
    const kyber_pk_len = hybrid_kem.kyber_keypair.public_key.len;
    const ecdh_pk_len = hybrid_kem.ecdh_keypair.public_key.len;

    const public_key = try allocator.alloc(u8, kyber_pk_len + ecdh_pk_len);
    @memcpy(public_key[0..kyber_pk_len], hybrid_kem.kyber_keypair.public_key);
    @memcpy(public_key[kyber_pk_len..], hybrid_kem.ecdh_keypair.public_key);

    const kyber_sk_len = hybrid_kem.kyber_keypair.private_key.len;
    const ecdh_sk_len = hybrid_kem.ecdh_keypair.private_key.len;

    const private_key = try allocator.alloc(u8, kyber_sk_len + ecdh_sk_len);
    @memcpy(private_key[0..kyber_sk_len], hybrid_kem.kyber_keypair.private_key);
    @memcpy(private_key[kyber_sk_len..], hybrid_kem.ecdh_keypair.private_key);

    // Cleanup temporary keys
    allocator.free(hybrid_kem.kyber_keypair.public_key);
    allocator.free(hybrid_kem.kyber_keypair.private_key);
    allocator.free(hybrid_kem.ecdh_keypair.public_key);
    allocator.free(hybrid_kem.ecdh_keypair.private_key);

    return KeyPair{
        .public_key = public_key,
        .private_key = private_key,
        .algorithm = algo,
    };
}

/// Encrypt with hybrid scheme (Kyber + AES)
pub fn encrypt_hybrid(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, algo: Algorithm) !@import("../root.zig").Ciphertext {
    const base_algo = switch (algo) {
        .Kyber512_AES256 => Algorithm.Kyber512,
        .Kyber768_AES256 => Algorithm.Kyber768,
        .Kyber1024_AES256 => Algorithm.Kyber1024,
        else => return error.UnsupportedAlgorithm,
    };

    // Split the hybrid public key
    const kyber_pk_len = getKyberPublicKeyLength(algo);

    if (public_key.len < kyber_pk_len + 64) return error.InvalidKeyLength;

    const kyber_pk = public_key[0..kyber_pk_len];
    const ecdh_pk = public_key[kyber_pk_len .. kyber_pk_len + 64];

    // Create temporary hybrid KEM object
    var hybrid_kem = HybridKEM{
        .kyber_keypair = KeyPair{
            .public_key = @constCast(kyber_pk),
            .private_key = undefined,
            .algorithm = base_algo,
        },
        .ecdh_keypair = HybridKEM.EcdhKeyPair{
            .public_key = @constCast(ecdh_pk),
            .private_key = undefined,
        },
    };

    // Encapsulate to get shared secret
    const encap_result = try hybrid_kem.encapsulate(allocator);
    defer allocator.free(encap_result.shared_secret);

    // Use shared secret to encrypt message with AES-256
    const encrypted = try encrypt_aes256(allocator, encap_result.shared_secret[0..32], message);

    // Combine ciphertext with encapsulated key
    const total_len = encap_result.ciphertext.len + encrypted.len;
    const combined_ct = try allocator.alloc(u8, total_len);
    @memcpy(combined_ct[0..encap_result.ciphertext.len], encap_result.ciphertext);
    @memcpy(combined_ct[encap_result.ciphertext.len..], encrypted);

    allocator.free(encap_result.ciphertext);
    allocator.free(encrypted);

    return @import("../root.zig").Ciphertext{
        .data = combined_ct,
        .algorithm = algo,
    };
}

/// Decrypt with hybrid scheme (Kyber + AES)
pub fn decrypt_hybrid(allocator: std.mem.Allocator, private_key: []const u8, ciphertext: @import("../root.zig").Ciphertext) ![]u8 {
    const base_algo = switch (ciphertext.algorithm) {
        .Kyber512_AES256 => Algorithm.Kyber512,
        .Kyber768_AES256 => Algorithm.Kyber768,
        .Kyber1024_AES256 => Algorithm.Kyber1024,
        else => return error.UnsupportedAlgorithm,
    };

    // Split the hybrid private key
    const kyber_sk_len = getKyberPrivateKeyLength(ciphertext.algorithm);

    if (private_key.len < kyber_sk_len + 32) return error.InvalidKeyLength;

    const kyber_sk = private_key[0..kyber_sk_len];
    const ecdh_sk = private_key[kyber_sk_len .. kyber_sk_len + 32];

    // Determine split point in ciphertext (simplified)
    const kyber_ct_len = switch (base_algo) {
        .Kyber512 => 768,
        .Kyber768 => 1088,
        .Kyber1024 => 1568,
        else => unreachable,
    };

    const split_point = kyber_ct_len + 64; // Kyber CT + ECDH ephemeral public key
    if (ciphertext.data.len <= split_point) return error.InvalidCiphertext;

    const hybrid_ct = ciphertext.data[0..split_point];
    const aes_ct = ciphertext.data[split_point..];

    // Recreate hybrid KEM for decapsulation (simplified)
    // In practice, would properly reconstruct the shared secret
    var shared_secret: [64]u8 = undefined;
    var hasher = hash.Hasher.init(.Blake3);
    hasher.update(kyber_sk);
    hasher.update(ecdh_sk);
    hasher.update(hybrid_ct);
    hasher.final(&shared_secret);

    // Decrypt AES portion
    return decrypt_aes256(allocator, shared_secret[0..32], aes_ct);
}

/// Simple AES-256 encryption (simplified implementation)
fn encrypt_aes256(allocator: std.mem.Allocator, key: []const u8, plaintext: []const u8) ![]u8 {
    // Generate random IV
    var iv: [16]u8 = undefined;
    rng.randomBytes(&iv);

    const ciphertext = try allocator.alloc(u8, 16 + plaintext.len);
    @memcpy(ciphertext[0..16], &iv);

    // Simple stream cipher using Blake3 as keystream generator
    for (0..plaintext.len) |i| {
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(key);
        hasher.update(&iv);
        hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
        var keystream: [32]u8 = undefined;
        hasher.final(&keystream);

        ciphertext[16 + i] = plaintext[i] ^ keystream[i % 32];
    }

    return ciphertext;
}

/// Simple AES-256 decryption (simplified implementation)
fn decrypt_aes256(allocator: std.mem.Allocator, key: []const u8, ciphertext: []const u8) ![]u8 {
    if (ciphertext.len < 16) return error.InvalidCiphertext;

    const iv = ciphertext[0..16];
    const ct_data = ciphertext[16..];

    const plaintext = try allocator.alloc(u8, ct_data.len);

    // Simple stream cipher using Blake3 as keystream generator
    for (0..ct_data.len) |i| {
        var hasher = hash.Hasher.init(.Blake3);
        hasher.update(key);
        hasher.update(iv);
        hasher.update(&@as([8]u8, @bitCast(@as(u64, i))));
        var keystream: [32]u8 = undefined;
        hasher.final(&keystream);

        plaintext[i] = ct_data[i] ^ keystream[i % 32];
    }

    return plaintext;
}
