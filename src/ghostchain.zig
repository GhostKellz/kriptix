//! Ghostchain integration helpers built on Kriptix hybrid cryptography.
//! Provides allocator-aware key generation, signing, and verification APIs
//! tailored for Ghostchain's modular blockchain stack.

const std = @import("std");
const blake3 = std.crypto.hash.Blake3;
const build_options = @import("build_options");
const kriptix = @import("root.zig");
const hybrid = @import("hybrid/manager.zig");

/// Public alias for the hybrid keypair used by Ghostchain integrations.
pub const HybridKeyPair = hybrid.HybridKeyPair;

/// Public alias for the hybrid public key view.
pub const HybridPublicKey = hybrid.HybridPublicKey;

/// Public alias for the hybrid signature bundle.
pub const HybridSignatureBundle = hybrid.HybridSignatureBundle;

/// Errors returned by Ghostchain crypto helpers.
pub const CryptoError = error{
    /// Returned when provided private key material is missing or malformed.
    InvalidPrivateKey,
    /// Returned when provided public key material does not match algorithms.
    InvalidPublicKey,
    /// Returned when signature validation fails in hybrid verification.
    InvalidSignature,
    /// Returned when hybrid operations require optional inputs that are missing.
    MissingHybridMaterial,
    /// Returned when algorithm identifiers do not line up across hybrid materials.
    InvalidAlgorithm,
};

/// Configuration for generating Ghostchain-compatible hybrid key material.
pub const KeygenOptions = struct {
    /// Algorithm used for the PQC signature component. Defaults to ML-DSA-44.
    signing_algorithm: kriptix.Algorithm = defaultSigningAlgorithm(),
    /// Whether to include the classical Ed25519 key pair alongside PQC material.
    classical: bool = true,
    /// Optional KEM algorithm to bundle for hybrid encryption (defaults to ML-KEM-768 when available).
    kem_algorithm: ?kriptix.Algorithm = defaultKemAlgorithm(),
    /// Optional master seed used to derive deterministic material for every component.
    master_seed: ?[]const u8 = null,
    /// Explicit seed material overrides for individual components.
    seed_material: ?hybrid.HybridCryptoManager.SeedMaterial = null,
};

fn defaultSigningAlgorithm() kriptix.Algorithm {
    if (build_options.ml_dsa_enabled or build_options.dilithium_enabled) {
        return kriptix.Algorithm.Dilithium2;
    }

    // Fall back to SPHINCS+ if ML-DSA is disabled but SPHINCS is enabled.
    if (build_options.sphincs_enabled) {
        return kriptix.Algorithm.Sphincs128f;
    }

    @compileError("Ghostchain requires a signature algorithm. Enable -Dml-dsa or -Dsphincs in the build.");
}

fn defaultKemAlgorithm() ?kriptix.Algorithm {
    if (build_options.ml_kem_enabled or build_options.kyber_enabled) {
        return kriptix.Algorithm.Kyber768;
    }

    // Ghostchain can operate without KEM material, so return null when unavailable.
    return null;
}

/// Generates hybrid key material compatible with Ghostchain expectations.
///
/// ## Parameters
/// - `allocator`: Memory allocator used to back the produced key material.
/// - `options`: Algorithm selections for the PQC/classical components.
///
/// ## Returns
/// A `HybridKeyPair` where the caller owns the memory and must call `deinit()`.
///
/// ## Errors
/// Propagates allocator failures, PQC key generation errors, and `CryptoError`
/// values when hybrid components are inconsistent.
pub fn keygen(allocator: std.mem.Allocator, options: KeygenOptions) !HybridKeyPair {
    if (!build_options.hybrid_enabled) {
        @compileError("ghostchain.keygen requires -Dhybrid=true");
    }

    var manager = hybrid.HybridCryptoManager.init(
        allocator,
        options.signing_algorithm,
        options.classical,
        options.kem_algorithm,
    );

    var signing_seed_storage: [64]u8 = undefined;
    var classical_seed_storage: [32]u8 = undefined;
    var kem_seed_storage: [64]u8 = undefined;
    var seed_material: ?hybrid.HybridCryptoManager.SeedMaterial = null;

    if (options.seed_material) |explicit| {
        seed_material = explicit;
    } else if (options.master_seed) |master| {
        blake3.hash(master, &signing_seed_storage, .{});

        var classical_slice: ?[]const u8 = null;
        if (options.classical) {
        blake3.hash(master, &classical_seed_storage, .{});
            classical_slice = @as([]const u8, classical_seed_storage[0..]);
        }

        var kem_slice: ?[]const u8 = null;
        if (options.kem_algorithm != null) {
        blake3.hash(master, &kem_seed_storage, .{});
            kem_slice = @as([]const u8, kem_seed_storage[0..]);
        }

        seed_material = hybrid.HybridCryptoManager.SeedMaterial{
            .signing = @as([]const u8, signing_seed_storage[0..]),
            .classical = classical_slice,
            .kem = kem_slice,
        };
    }

    return manager.generate_hybrid_keypair(seed_material) catch |err| switch (err) {
        else => err,
    };
}

/// Signs `message` using the provided hybrid keypair, producing both PQC and
/// optional classical signatures.
///
/// The returned `HybridSignatureBundle` must be cleaned up via `deinit()` when
/// no longer needed.
pub fn sign(allocator: std.mem.Allocator, keypair: *const HybridKeyPair, message: []const u8) !HybridSignatureBundle {
    if (!build_options.hybrid_enabled) {
        @compileError("ghostchain.sign requires -Dhybrid=true");
    }

    const classical_enabled = keypair.classical_keypair != null;
    const kem_algorithm = if (keypair.kem_keypair) |kem| kem.algorithm else null;

    var manager = hybrid.HybridCryptoManager.init(
        allocator,
        keypair.signing_keypair.algorithm,
        classical_enabled,
        kem_algorithm,
    );

    return manager.hybrid_sign(message, keypair) catch |err| switch (err) {
        error.InvalidPrivateKey => CryptoError.InvalidPrivateKey,
        error.InvalidPublicKey => CryptoError.InvalidPublicKey,
        error.InvalidAlgorithm => CryptoError.InvalidAlgorithm,
        error.MissingHybridMaterial => CryptoError.MissingHybridMaterial,
        else => err,
    };
}

/// Verifies a hybrid signature bundle against the provided public key material.
/// Returns `true` when both PQC (and classical, when present) signatures validate.
pub fn verify(
    allocator: std.mem.Allocator,
    public_key: HybridPublicKey,
    message: []const u8,
    signature: HybridSignatureBundle,
) !bool {
    if (!build_options.hybrid_enabled) {
        @compileError("ghostchain.verify requires -Dhybrid=true");
    }

    const classical_enabled = signature.classical_signature != null and public_key.classical_public_key != null;

    var manager = hybrid.HybridCryptoManager.init(
        allocator,
        signature.pqc_algorithm,
        classical_enabled,
        public_key.kem_algorithm,
    );

    return manager.hybrid_verify(message, signature, public_key) catch |err| switch (err) {
        error.InvalidPublicKey => CryptoError.InvalidPublicKey,
        error.InvalidAlgorithm => CryptoError.InvalidAlgorithm,
        error.MissingHybridMaterial => CryptoError.MissingHybridMaterial,
        else => err,
    };
}

/// Convenience helper that clones the hybrid public key material returned by
/// `HybridKeyPair.public_view()` so callers can retain a stable copy after the
/// source keypair is deinitialized.
pub fn clonePublicKey(allocator: std.mem.Allocator, view: HybridPublicKey) !HybridPublicKey {
    const pqc_copy = try allocator.dupe(u8, view.pqc_public_key);
    errdefer allocator.free(pqc_copy);

    var classical_copy: ?[]u8 = null;
    if (view.classical_public_key) |classical| {
        classical_copy = try allocator.dupe(u8, classical);
        errdefer allocator.free(classical_copy.?);
    }

    var kem_copy: ?[]u8 = null;
    if (view.kem_public_key) |kem| {
        kem_copy = try allocator.dupe(u8, kem);
        errdefer allocator.free(kem_copy.?);
    }

    return HybridPublicKey{
        .pqc_public_key = pqc_copy,
        .pqc_algorithm = view.pqc_algorithm,
        .classical_public_key = classical_copy,
        .kem_public_key = kem_copy,
        .kem_algorithm = view.kem_algorithm,
    };
}

/// Releases memory owned by a cloned `HybridPublicKey` produced by
/// `clonePublicKey`.
pub fn deinitClonedPublicKey(allocator: std.mem.Allocator, pk: *HybridPublicKey) void {
    if (pk.pqc_public_key.len > 0) {
        allocator.free(@constCast(pk.pqc_public_key));
    }
    pk.pqc_public_key = &[_]u8{};

    if (pk.classical_public_key) |classical| {
        allocator.free(@constCast(classical));
        pk.classical_public_key = null;
    }

    if (pk.kem_public_key) |kem| {
        allocator.free(@constCast(kem));
        pk.kem_public_key = null;
    }

    pk.kem_algorithm = null;
}

const testing = std.testing;

test "ghostchain hybrid sign/verify roundtrip" {
    if (!build_options.hybrid_enabled) return error.SkipZigTest;
    if (!(build_options.ml_dsa_enabled or build_options.dilithium_enabled or build_options.sphincs_enabled)) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var keypair = try keygen(allocator, .{});
    defer keypair.deinit(allocator);

    const message = "ghostchain::hybrid-signature";
    var signature = try sign(allocator, &keypair, message);
    defer signature.deinit(allocator);

    const public_view = keypair.public_view();
    try testing.expect(try verify(allocator, public_view, message, signature));
}

test "ghostchain deterministic keygen stable" {
    if (!build_options.hybrid_enabled) return error.SkipZigTest;
    if (!(build_options.ml_dsa_enabled or build_options.dilithium_enabled)) return error.SkipZigTest;
    if (!(build_options.ml_kem_enabled or build_options.kyber_enabled)) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master_seed = "ghostchain deterministic seed";
    const options = KeygenOptions{ .master_seed = master_seed };

    var keypair_a = try keygen(allocator, options);
    defer keypair_a.deinit(allocator);

    var keypair_b = try keygen(allocator, options);
    defer keypair_b.deinit(allocator);

    try testing.expectEqualSlices(u8, keypair_a.signing_keypair.public_key, keypair_b.signing_keypair.public_key);
    try testing.expectEqualSlices(u8, keypair_a.signing_keypair.private_key, keypair_b.signing_keypair.private_key);

    if (keypair_a.classical_keypair) |classic_a| {
        const classic_b = keypair_b.classical_keypair orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, classic_a.public_key, classic_b.public_key);
        try testing.expectEqualSlices(u8, classic_a.private_key, classic_b.private_key);
    }

    if (keypair_a.kem_keypair) |kem_a| {
        const kem_b = keypair_b.kem_keypair orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, kem_a.public_key, kem_b.public_key);
        try testing.expectEqualSlices(u8, kem_a.private_key, kem_b.private_key);
    }
}
