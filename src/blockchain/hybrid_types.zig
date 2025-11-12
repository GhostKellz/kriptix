//! Shared hybrid cryptography records for blockchain storage

const std = @import("std");
const kriptix = @import("../root.zig");
const security = @import("../security.zig");

/// Public key material used by hybrid cryptography on-chain and in gossip payloads.
pub const HybridPublicKeyRecord = struct {
    pqc_public_key: []u8,
    pqc_algorithm: kriptix.Algorithm,
    classical_public_key: ?[]u8 = null,
    kem_public_key: ?[]u8 = null,
    kem_algorithm: ?kriptix.Algorithm = null,

    pub fn deinit(self: *HybridPublicKeyRecord, allocator: std.mem.Allocator) void {
        if (self.pqc_public_key.len > 0) allocator.free(self.pqc_public_key);
        self.pqc_public_key = &[_]u8{};

        if (self.classical_public_key) |classical| {
            allocator.free(classical);
            self.classical_public_key = null;
        }

        if (self.kem_public_key) |kem| {
            allocator.free(kem);
            self.kem_public_key = null;
        }

        self.kem_algorithm = null;
    }

    pub fn clone(self: *const HybridPublicKeyRecord, allocator: std.mem.Allocator) !HybridPublicKeyRecord {
        const pqc_copy = try allocator.dupe(u8, self.pqc_public_key);
        errdefer allocator.free(pqc_copy);

        var classical_copy: ?[]u8 = null;
        if (self.classical_public_key) |classical_src| {
            classical_copy = try allocator.dupe(u8, classical_src);
            errdefer allocator.free(classical_copy.?);
        }

        var kem_copy: ?[]u8 = null;
        if (self.kem_public_key) |kem_src| {
            kem_copy = try allocator.dupe(u8, kem_src);
            errdefer allocator.free(kem_copy.?);
        }

        return HybridPublicKeyRecord{
            .pqc_public_key = pqc_copy,
            .pqc_algorithm = self.pqc_algorithm,
            .classical_public_key = classical_copy,
            .kem_public_key = kem_copy,
            .kem_algorithm = self.kem_algorithm,
        };
    }
};

/// Signature bundle captured from hybrid signing operations.
pub const HybridSignatureRecord = struct {
    pqc_signature: []u8,
    pqc_algorithm: kriptix.Algorithm,
    classical_signature: ?[]u8 = null,

    pub fn deinit(self: *HybridSignatureRecord, allocator: std.mem.Allocator) void {
        if (self.pqc_signature.len > 0) {
            security.SecureMemory.secure_zero(self.pqc_signature);
            allocator.free(self.pqc_signature);
        }
        self.pqc_signature = &[_]u8{};

        if (self.classical_signature) |classical| {
            allocator.free(classical);
            self.classical_signature = null;
        }
    }

    pub fn clone(self: *const HybridSignatureRecord, allocator: std.mem.Allocator) !HybridSignatureRecord {
        const pqc_copy = try allocator.dupe(u8, self.pqc_signature);
        errdefer allocator.free(pqc_copy);

        var classical_copy: ?[]u8 = null;
        if (self.classical_signature) |classical_src| {
            classical_copy = try allocator.dupe(u8, classical_src);
            errdefer allocator.free(classical_copy.?);
        }

        return HybridSignatureRecord{
            .pqc_signature = pqc_copy,
            .pqc_algorithm = self.pqc_algorithm,
            .classical_signature = classical_copy,
        };
    }
};
