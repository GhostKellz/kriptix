//! Hybrid cryptography manager shared between blockchain and Ghostchain integration.

const std = @import("std");
const kriptix = @import("../root.zig");
const classical = @import("../classic/root.zig");
const security = @import("../security.zig");
const pq_hybrid = @import("../pq/hybrid.zig");

pub const Error = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidAlgorithm,
    MissingHybridMaterial,
};

pub const HybridCryptoManager = struct {
    allocator: std.mem.Allocator,
    signing_algorithm: kriptix.Algorithm,
    kem_algorithm: ?kriptix.Algorithm,
    classical_enabled: bool,

    const Self = @This();

    pub const SeedMaterial = struct {
        signing: ?[]const u8 = null,
        classical: ?[]const u8 = null,
        kem: ?[]const u8 = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        signing_algorithm: kriptix.Algorithm,
        classical_enabled: bool,
        kem_algorithm: ?kriptix.Algorithm,
    ) Self {
        return Self{
            .allocator = allocator,
            .signing_algorithm = signing_algorithm,
            .kem_algorithm = kem_algorithm,
            .classical_enabled = classical_enabled,
        };
    }

    pub fn generate_hybrid_keypair(self: *Self, seeds: ?SeedMaterial) !HybridKeyPair {
        const seed_material = seeds;

        const signing_seed = if (seed_material) |material| material.signing else null;
        var signing_keypair = if (signing_seed) |seed|
            try kriptix.generate_keypair_deterministic(self.allocator, self.signing_algorithm, seed)
        else
            try kriptix.generate_keypair(self.allocator, self.signing_algorithm);
        errdefer {
            security.SecureMemory.secure_zero(signing_keypair.private_key);
            self.allocator.free(signing_keypair.private_key);
            self.allocator.free(signing_keypair.public_key);
        }

        var classical_keypair: ?ClassicalKeyPair = null;
        if (self.classical_enabled) {
            const classical_seed = if (seed_material) |material| material.classical else null;
            var ed_kp = if (classical_seed) |seed|
                try classical.ed25519.generateKeypairDeterministic(self.allocator, seed)
            else
                try classical.ed25519.generateKeypair(self.allocator);
            classical_keypair = ClassicalKeyPair{
                .public_key = ed_kp.public_key,
                .private_key = ed_kp.private_key,
            };
        }
        errdefer if (classical_keypair) |*classic| classic.deinit(self.allocator);

        var kem_keypair: ?kriptix.KeyPair = null;
        if (self.kem_algorithm) |kem_algo| {
            const kem_seed = if (seed_material) |material| material.kem else null;
            kem_keypair = if (kem_seed) |seed|
                try kriptix.generate_keypair_deterministic(self.allocator, kem_algo, seed)
            else
                try kriptix.generate_keypair(self.allocator, kem_algo);
        }
        errdefer {
            if (kem_keypair) |kem| {
                security.SecureMemory.secure_zero(kem.private_key);
                self.allocator.free(kem.private_key);
                self.allocator.free(kem.public_key);
            }
        }

        return HybridKeyPair{
            .signing_keypair = signing_keypair,
            .classical_keypair = classical_keypair,
            .kem_keypair = kem_keypair,
        };
    }

    pub fn hybrid_sign(self: *Self, message: []const u8, hybrid_keypair: *const HybridKeyPair) !HybridSignatureBundle {
        const pqc_signature = try kriptix.sign(self.allocator, hybrid_keypair.signing_keypair.private_key, message, self.signing_algorithm);
        errdefer self.allocator.free(pqc_signature.data);

        var classical_signature: ?[]u8 = null;
        if (self.classical_enabled) {
            const classical_keys = hybrid_keypair.classical_keypair orelse {
                self.allocator.free(pqc_signature.data);
                return Error.InvalidPrivateKey;
            };
            classical_signature = classical.ed25519.sign(self.allocator, message, classical_keys.private_key) catch |err| {
                self.allocator.free(pqc_signature.data);
                return err;
            };
        }

        return HybridSignatureBundle{
            .pqc_signature = pqc_signature.data,
            .classical_signature = classical_signature,
            .pqc_algorithm = self.signing_algorithm,
        };
    }

    pub fn hybrid_verify(self: *Self, message: []const u8, signature: HybridSignatureBundle, hybrid_pubkey: HybridPublicKey) !bool {
        const pqc_signature_mut = @constCast(signature.pqc_signature);
        const pqc_sig = kriptix.Signature{
            .data = pqc_signature_mut,
            .algorithm = signature.pqc_algorithm,
        };

        if (hybrid_pubkey.pqc_algorithm != pqc_sig.algorithm) return Error.InvalidAlgorithm;

        const pqc_valid = try kriptix.verify(hybrid_pubkey.pqc_public_key, message, pqc_sig);
        if (!pqc_valid) return false;

        if (self.classical_enabled) {
            const classical_sig = signature.classical_signature orelse return false;
            const classical_pub = hybrid_pubkey.classical_public_key orelse return false;
            const classical_valid = try classical.ed25519.verify(classical_sig, message, classical_pub);
            return classical_valid;
        }

        return true;
    }

    pub fn hybrid_encrypt(self: *Self, message: []const u8, recipient_pubkey: HybridPublicKey) !kriptix.Ciphertext {
        const kem_algo = self.kem_algorithm orelse return Error.MissingHybridMaterial;
        const recipient_kem = recipient_pubkey.kem_public_key orelse return Error.InvalidPublicKey;

        if (recipient_pubkey.kem_algorithm) |pub_algo| {
            if (pub_algo != kem_algo) return Error.InvalidAlgorithm;
        }

        return try pq_hybrid.encrypt_hybrid(self.allocator, recipient_kem, message, kem_algo);
    }

    pub fn hybrid_decrypt(self: *Self, ciphertext: kriptix.Ciphertext, hybrid_keypair: *const HybridKeyPair) ![]u8 {
        const kem_algo = self.kem_algorithm orelse return Error.MissingHybridMaterial;
        const kem_material = hybrid_keypair.kem_keypair orelse return Error.InvalidPrivateKey;

        if (ciphertext.algorithm != kem_algo) return Error.InvalidAlgorithm;

        return try pq_hybrid.decrypt_hybrid(self.allocator, kem_material.private_key, ciphertext);
    }
};

pub const ClassicalKeyPair = struct {
    public_key: []u8,
    private_key: []u8,

    pub fn deinit(self: *ClassicalKeyPair, allocator: std.mem.Allocator) void {
        if (self.public_key.len > 0) allocator.free(self.public_key);
        if (self.private_key.len > 0) {
            security.SecureMemory.secure_zero(self.private_key);
            allocator.free(self.private_key);
        }
        self.public_key = &[_]u8{};
        self.private_key = &[_]u8{};
    }
};

pub const HybridKeyPair = struct {
    signing_keypair: kriptix.KeyPair,
    classical_keypair: ?ClassicalKeyPair,
    kem_keypair: ?kriptix.KeyPair,

    pub fn deinit(self: *HybridKeyPair, allocator: std.mem.Allocator) void {
        if (self.signing_keypair.public_key.len > 0) allocator.free(self.signing_keypair.public_key);
        if (self.signing_keypair.private_key.len > 0) {
            security.SecureMemory.secure_zero(self.signing_keypair.private_key);
            allocator.free(self.signing_keypair.private_key);
        }
        self.signing_keypair.public_key = &[_]u8{};
        self.signing_keypair.private_key = &[_]u8{};

        if (self.classical_keypair) |*classic| {
            classic.deinit(allocator);
            self.classical_keypair = null;
        }

        if (self.kem_keypair) |*kem| {
            if (kem.public_key.len > 0) allocator.free(kem.public_key);
            if (kem.private_key.len > 0) {
                security.SecureMemory.secure_zero(kem.private_key);
                allocator.free(kem.private_key);
            }
            self.kem_keypair = null;
        }
    }

    pub fn public_view(self: *const HybridKeyPair) HybridPublicKey {
        return HybridPublicKey{
            .pqc_public_key = self.signing_keypair.public_key,
            .pqc_algorithm = self.signing_keypair.algorithm,
            .classical_public_key = if (self.classical_keypair) |classic| classic.public_key else null,
            .kem_public_key = if (self.kem_keypair) |kem| kem.public_key else null,
            .kem_algorithm = if (self.kem_keypair) |kem| kem.algorithm else null,
        };
    }
};

pub const HybridPublicKey = struct {
    pqc_public_key: []const u8,
    pqc_algorithm: kriptix.Algorithm,
    classical_public_key: ?[]const u8,
    kem_public_key: ?[]const u8,
    kem_algorithm: ?kriptix.Algorithm,

    pub fn has_classical(self: *const HybridPublicKey) bool {
        return self.classical_public_key != null;
    }

    pub fn has_kem(self: *const HybridPublicKey) bool {
        return self.kem_public_key != null;
    }
};

pub const HybridSignatureBundle = struct {
    pqc_signature: []const u8,
    classical_signature: ?[]const u8,
    pqc_algorithm: kriptix.Algorithm,

    pub fn deinit(self: *HybridSignatureBundle, allocator: std.mem.Allocator) void {
        if (self.pqc_signature.len > 0) {
            const mutable = @constCast(self.pqc_signature);
            security.SecureMemory.secure_zero(mutable);
            allocator.free(mutable);
        }
        if (self.classical_signature) |classical_sig| {
            allocator.free(@constCast(classical_sig));
        }
        self.pqc_signature = &[_]u8{};
        self.classical_signature = null;
    }
};
