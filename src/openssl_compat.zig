//! OpenSSL Compatibility Layer
//! Provides OpenSSL-style APIs for seamless integration with existing systems
//! Implements EVP interface emulation and standard function signatures

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const interop = @import("interop.zig");
const security = @import("security.zig");

const Algorithm = root.Algorithm;

/// OpenSSL-style error codes
pub const SSL_ERROR = enum(c_int) {
    SSL_SUCCESS = 1,
    SSL_ERROR_GENERIC = 0,
    SSL_ERROR_INVALID_ALGORITHM = -1,
    SSL_ERROR_INVALID_KEY = -2,
    SSL_ERROR_BUFFER_TOO_SMALL = -3,
    SSL_ERROR_MEMORY_ALLOCATION = -4,
    SSL_ERROR_INVALID_PARAMETER = -5,
};

/// OpenSSL-style NID (Numeric Identifier) mappings for PQC algorithms
pub const PQC_NIDS = struct {
    pub const NID_KYBER512 = 1001;
    pub const NID_KYBER768 = 1002;
    pub const NID_KYBER1024 = 1003;
    pub const NID_DILITHIUM2 = 1004;
    pub const NID_DILITHIUM3 = 1005;
    pub const NID_DILITHIUM5 = 1006;
    pub const NID_SPHINCS128F = 1007;
    pub const NID_SPHINCS256S = 1008;

    pub fn from_algorithm(algorithm: Algorithm) c_int {
        return switch (algorithm) {
            .Kyber512 => NID_KYBER512,
            .Kyber768 => NID_KYBER768,
            .Kyber1024 => NID_KYBER1024,
            .Dilithium2 => NID_DILITHIUM2,
            .Dilithium3 => NID_DILITHIUM3,
            .Dilithium5 => NID_DILITHIUM5,
            .Sphincs128f => NID_SPHINCS128F,
            .Sphincs256s => NID_SPHINCS256S,
            else => 0,
        };
    }

    pub fn to_algorithm(nid: c_int) ?Algorithm {
        return switch (nid) {
            NID_KYBER512 => .Kyber512,
            NID_KYBER768 => .Kyber768,
            NID_KYBER1024 => .Kyber1024,
            NID_DILITHIUM2 => .Dilithium2,
            NID_DILITHIUM3 => .Dilithium3,
            NID_DILITHIUM5 => .Dilithium5,
            NID_SPHINCS128F => .Sphincs128f,
            NID_SPHINCS256S => .Sphincs256s,
            else => null,
        };
    }
};

/// OpenSSL-style EVP_PKEY structure emulation
pub const EVP_PKEY = struct {
    algorithm: Algorithm,
    key_type: enum { public, private, keypair },
    public_key: ?[]u8 = null,
    private_key: ?[]u8 = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, algorithm: Algorithm) EVP_PKEY {
        return EVP_PKEY{
            .algorithm = algorithm,
            .key_type = .keypair,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EVP_PKEY) void {
        if (self.public_key) |pk| {
            security.SecureMemory.secure_zero(pk);
            self.allocator.free(pk);
        }
        if (self.private_key) |sk| {
            security.SecureMemory.secure_zero(sk);
            self.allocator.free(sk);
        }
    }

    /// Set public key data
    pub fn set_public_key(self: *EVP_PKEY, key_data: []const u8) !void {
        if (self.public_key) |old_key| {
            security.SecureMemory.secure_zero(old_key);
            self.allocator.free(old_key);
        }
        self.public_key = try self.allocator.dupe(u8, key_data);
        if (self.private_key == null) {
            self.key_type = .public;
        }
    }

    /// Set private key data
    pub fn set_private_key(self: *EVP_PKEY, key_data: []const u8) !void {
        if (self.private_key) |old_key| {
            security.SecureMemory.secure_zero(old_key);
            self.allocator.free(old_key);
        }
        self.private_key = try self.allocator.dupe(u8, key_data);
        if (self.public_key == null) {
            self.key_type = .private;
        } else {
            self.key_type = .keypair;
        }
    }

    /// Get key size for algorithm
    pub fn get_key_size(self: *const EVP_PKEY, key_type: enum { public, private }) u32 {
        return switch (key_type) {
            .public => switch (self.algorithm) {
                .Kyber512 => 800,
                .Kyber768 => 1184,
                .Kyber1024 => 1568,
                .Dilithium2 => 1312,
                .Dilithium3 => 1952,
                .Dilithium5 => 2592,
                .Sphincs128f => 32,
                .Sphincs256s => 64,
                else => 32,
            },
            .private => switch (self.algorithm) {
                .Kyber512 => 1632,
                .Kyber768 => 2400,
                .Kyber1024 => 3168,
                .Dilithium2 => 2528,
                .Dilithium3 => 4000,
                .Dilithium5 => 4864,
                .Sphincs128f => 64,
                .Sphincs256s => 128,
                else => 64,
            },
        };
    }
};

/// OpenSSL-style EVP_PKEY_CTX structure emulation
pub const EVP_PKEY_CTX = struct {
    algorithm: Algorithm,
    operation: enum { keygen, encrypt, decrypt, sign, verify },
    allocator: std.mem.Allocator,
    pkey: ?*EVP_PKEY = null,

    pub fn init(allocator: std.mem.Allocator, algorithm: Algorithm) EVP_PKEY_CTX {
        return EVP_PKEY_CTX{
            .algorithm = algorithm,
            .operation = .keygen,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EVP_PKEY_CTX) void {
        _ = self; // Nothing to cleanup for now
    }

    pub fn set_pkey(self: *EVP_PKEY_CTX, pkey: *EVP_PKEY) void {
        self.pkey = pkey;
    }
};

/// OpenSSL-style API functions
pub const OpenSSL_API = struct {
    /// Initialize OpenSSL-style context for key generation
    /// Equivalent to EVP_PKEY_CTX_new_id()
    pub fn EVP_PKEY_CTX_new_id(allocator: std.mem.Allocator, id: c_int) ?*EVP_PKEY_CTX {
        const algorithm = PQC_NIDS.to_algorithm(id) orelse return null;

        const ctx = allocator.create(EVP_PKEY_CTX) catch return null;
        ctx.* = EVP_PKEY_CTX.init(allocator, algorithm);
        return ctx;
    }

    /// Free OpenSSL-style context
    /// Equivalent to EVP_PKEY_CTX_free()
    pub fn EVP_PKEY_CTX_free(ctx: ?*EVP_PKEY_CTX, allocator: std.mem.Allocator) void {
        if (ctx) |c| {
            c.deinit();
            allocator.destroy(c);
        }
    }

    /// Initialize key generation
    /// Equivalent to EVP_PKEY_keygen_init()
    pub fn EVP_PKEY_keygen_init(ctx: ?*EVP_PKEY_CTX) c_int {
        if (ctx) |c| {
            c.operation = .keygen;
            return @intFromEnum(SSL_ERROR.SSL_SUCCESS);
        }
        return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_PARAMETER);
    }

    /// Generate key pair
    /// Equivalent to EVP_PKEY_keygen()
    pub fn EVP_PKEY_keygen(ctx: ?*EVP_PKEY_CTX, pkey: ?**EVP_PKEY) c_int {
        if (ctx == null or pkey == null) {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_PARAMETER);
        }

        const c = ctx.?;

        // Allocate new EVP_PKEY
        const new_pkey = c.allocator.create(EVP_PKEY) catch {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };
        new_pkey.* = EVP_PKEY.init(c.allocator, c.algorithm);

        // Generate dummy keys for demonstration
        const public_size = new_pkey.get_key_size(.public);
        const private_size = new_pkey.get_key_size(.private);

        const public_key = c.allocator.alloc(u8, public_size) catch {
            c.allocator.destroy(new_pkey);
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        const private_key = c.allocator.alloc(u8, private_size) catch {
            c.allocator.free(public_key);
            c.allocator.destroy(new_pkey);
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        // Fill with pseudo-random data (in real implementation, this would be proper key generation)
        for (public_key, 0..) |*byte, i| {
            byte.* = @intCast((i * 17 + 23) % 256);
        }
        for (private_key, 0..) |*byte, i| {
            byte.* = @intCast((i * 31 + 47) % 256);
        }

        new_pkey.set_public_key(public_key) catch {
            security.SecureMemory.secure_zero(public_key);
            security.SecureMemory.secure_zero(private_key);
            c.allocator.free(public_key);
            c.allocator.free(private_key);
            c.allocator.destroy(new_pkey);
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        new_pkey.set_private_key(private_key) catch {
            security.SecureMemory.secure_zero(private_key);
            c.allocator.free(private_key);
            new_pkey.deinit();
            c.allocator.destroy(new_pkey);
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        // Cleanup temporary buffers (data is now owned by EVP_PKEY)
        c.allocator.free(public_key);
        c.allocator.free(private_key);

        pkey.?.* = new_pkey;
        return @intFromEnum(SSL_ERROR.SSL_SUCCESS);
    }

    /// Free EVP_PKEY
    /// Equivalent to EVP_PKEY_free()
    pub fn EVP_PKEY_free(pkey: ?*EVP_PKEY, allocator: std.mem.Allocator) void {
        if (pkey) |pk| {
            pk.deinit();
            allocator.destroy(pk);
        }
    }

    /// Get public key size
    /// Equivalent to EVP_PKEY_size()
    pub fn EVP_PKEY_size(pkey: ?*const EVP_PKEY) c_int {
        if (pkey) |pk| {
            return @intCast(pk.get_key_size(.public));
        }
        return 0;
    }

    /// Get private key size
    pub fn EVP_PKEY_private_key_size(pkey: ?*const EVP_PKEY) c_int {
        if (pkey) |pk| {
            return @intCast(pk.get_key_size(.private));
        }
        return 0;
    }

    /// Export public key to DER format
    /// Equivalent to i2d_PUBKEY()
    pub fn i2d_PUBKEY(pkey: ?*const EVP_PKEY, out: ?*?[*]u8, allocator: std.mem.Allocator) c_int {
        if (pkey == null or out == null) {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_PARAMETER);
        }

        const pk = pkey.?;
        if (pk.public_key == null) {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_KEY);
        }

        // Export using X.509 format
        const der_data = interop.X509.encode_public_key(allocator, pk.algorithm, pk.public_key.?) catch {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        out.?.* = der_data.ptr;
        return @intCast(der_data.len);
    }

    /// Export private key to DER format
    /// Equivalent to i2d_PrivateKey()
    pub fn i2d_PrivateKey(pkey: ?*const EVP_PKEY, out: ?*?[*]u8, allocator: std.mem.Allocator) c_int {
        if (pkey == null or out == null) {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_PARAMETER);
        }

        const pk = pkey.?;
        if (pk.private_key == null) {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_INVALID_KEY);
        }

        // Export using PKCS#8 format
        const der_data = interop.PKCS8.encode_private_key(allocator, pk.algorithm, pk.private_key.?, pk.public_key) catch {
            return @intFromEnum(SSL_ERROR.SSL_ERROR_MEMORY_ALLOCATION);
        };

        out.?.* = der_data.ptr;
        return @intCast(der_data.len);
    }

    /// Import public key from DER format
    /// Equivalent to d2i_PUBKEY()
    pub fn d2i_PUBKEY(pkey: ?**EVP_PKEY, input: [*]const u8, length: c_int, allocator: std.mem.Allocator) ?*EVP_PKEY {
        if (pkey == null or length <= 0) return null;

        const der_data = input[0..@intCast(length)];

        // Import using X.509 format
        var spki = interop.X509.decode_public_key(allocator, der_data) catch return null;
        defer spki.deinit(allocator);

        const new_pkey = allocator.create(EVP_PKEY) catch return null;
        new_pkey.* = EVP_PKEY.init(allocator, spki.algorithm);

        new_pkey.set_public_key(spki.public_key) catch {
            allocator.destroy(new_pkey);
            return null;
        };

        pkey.?.* = new_pkey;
        return new_pkey;
    }

    /// Get algorithm NID from EVP_PKEY
    /// Equivalent to EVP_PKEY_id()
    pub fn EVP_PKEY_id(pkey: ?*const EVP_PKEY) c_int {
        if (pkey) |pk| {
            return PQC_NIDS.from_algorithm(pk.algorithm);
        }
        return 0;
    }

    /// Convert algorithm name to NID
    /// Equivalent to EVP_PKEY_type()
    pub fn OBJ_txt2nid(name: [*c]const u8) c_int {
        if (name == null) return 0;

        const name_str = std.mem.span(name);

        if (std.mem.eql(u8, name_str, "ML-KEM-512") or std.mem.eql(u8, name_str, "Kyber512")) {
            return PQC_NIDS.NID_KYBER512;
        } else if (std.mem.eql(u8, name_str, "ML-KEM-768") or std.mem.eql(u8, name_str, "Kyber768")) {
            return PQC_NIDS.NID_KYBER768;
        } else if (std.mem.eql(u8, name_str, "ML-KEM-1024") or std.mem.eql(u8, name_str, "Kyber1024")) {
            return PQC_NIDS.NID_KYBER1024;
        } else if (std.mem.eql(u8, name_str, "ML-DSA-44") or std.mem.eql(u8, name_str, "Dilithium2")) {
            return PQC_NIDS.NID_DILITHIUM2;
        } else if (std.mem.eql(u8, name_str, "ML-DSA-65") or std.mem.eql(u8, name_str, "Dilithium3")) {
            return PQC_NIDS.NID_DILITHIUM3;
        } else if (std.mem.eql(u8, name_str, "ML-DSA-87") or std.mem.eql(u8, name_str, "Dilithium5")) {
            return PQC_NIDS.NID_DILITHIUM5;
        } else if (std.mem.eql(u8, name_str, "SLH-DSA-SHAKE-128f") or std.mem.eql(u8, name_str, "SPHINCS-128f")) {
            return PQC_NIDS.NID_SPHINCS128F;
        } else if (std.mem.eql(u8, name_str, "SLH-DSA-SHAKE-256s") or std.mem.eql(u8, name_str, "SPHINCS-256s")) {
            return PQC_NIDS.NID_SPHINCS256S;
        }

        return 0;
    }

    /// Convert NID to algorithm name
    /// Equivalent to OBJ_nid2sn()
    pub fn OBJ_nid2sn(nid: c_int) ?[*c]const u8 {
        return switch (nid) {
            PQC_NIDS.NID_KYBER512 => "ML-KEM-512",
            PQC_NIDS.NID_KYBER768 => "ML-KEM-768",
            PQC_NIDS.NID_KYBER1024 => "ML-KEM-1024",
            PQC_NIDS.NID_DILITHIUM2 => "ML-DSA-44",
            PQC_NIDS.NID_DILITHIUM3 => "ML-DSA-65",
            PQC_NIDS.NID_DILITHIUM5 => "ML-DSA-87",
            PQC_NIDS.NID_SPHINCS128F => "SLH-DSA-SHAKE-128f",
            PQC_NIDS.NID_SPHINCS256S => "SLH-DSA-SHAKE-256s",
            else => null,
        };
    }
};

/// High-level OpenSSL compatibility interface
pub const SSLCompat = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SSLCompat {
        return SSLCompat{ .allocator = allocator };
    }

    /// Generate key pair using OpenSSL-style API
    pub fn generate_keypair(self: *SSLCompat, algorithm_name: []const u8) !*EVP_PKEY {
        const nid = OpenSSL_API.OBJ_txt2nid(algorithm_name.ptr);
        if (nid == 0) return error.UnsupportedAlgorithm;

        const ctx = OpenSSL_API.EVP_PKEY_CTX_new_id(self.allocator, nid) orelse return error.ContextCreationFailed;
        defer OpenSSL_API.EVP_PKEY_CTX_free(ctx, self.allocator);

        if (OpenSSL_API.EVP_PKEY_keygen_init(ctx) != @intFromEnum(SSL_ERROR.SSL_SUCCESS)) {
            return error.KeygenInitFailed;
        }

        var pkey: ?*EVP_PKEY = null;
        if (OpenSSL_API.EVP_PKEY_keygen(ctx, @ptrCast(&pkey)) != @intFromEnum(SSL_ERROR.SSL_SUCCESS)) {
            return error.KeygenFailed;
        }

        return pkey.?;
    }

    /// Export key to PEM format (OpenSSL-compatible)
    pub fn export_key_pem(self: *SSLCompat, pkey: *const EVP_PKEY, key_type: enum { public, private }) ![]u8 {
        var interop_mgr = interop.InteropManager.init(self.allocator);

        return switch (key_type) {
            .public => {
                if (pkey.public_key) |pk| {
                    return interop_mgr.export_public_key_pem(pkey.algorithm, pk);
                } else {
                    return error.NoPublicKey;
                }
            },
            .private => {
                if (pkey.private_key) |sk| {
                    return interop_mgr.export_private_key_pem(pkey.algorithm, sk, pkey.public_key);
                } else {
                    return error.NoPrivateKey;
                }
            },
        };
    }

    /// Get algorithm information in OpenSSL format
    pub fn get_algorithm_info(pkey: *const EVP_PKEY) struct { nid: c_int, name: ?[*c]const u8, oid: []const u8, key_size: u32, private_key_size: u32 } {
        const nid = OpenSSL_API.EVP_PKEY_id(pkey);
        const name = OpenSSL_API.OBJ_nid2sn(nid);
        const info = interop.InteropManager.get_algorithm_info(pkey.algorithm);

        return .{
            .nid = nid,
            .name = name,
            .oid = info.oid,
            .key_size = pkey.get_key_size(.public),
            .private_key_size = pkey.get_key_size(.private),
        };
    }
};

// Test suite for OpenSSL compatibility
test "OpenSSL NID conversion" {
    const nid = OpenSSL_API.OBJ_txt2nid("ML-KEM-768");
    try testing.expect(nid == PQC_NIDS.NID_KYBER768);

    const name = OpenSSL_API.OBJ_nid2sn(nid);
    try testing.expect(name != null);
    try testing.expect(std.mem.eql(u8, std.mem.span(name.?), "ML-KEM-768"));
}

test "EVP_PKEY operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pkey = EVP_PKEY.init(allocator, .Kyber768);
    defer pkey.deinit();

    const dummy_public = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dummy_private = [_]u8{ 0x05, 0x06, 0x07, 0x08 };

    try pkey.set_public_key(&dummy_public);
    try pkey.set_private_key(&dummy_private);

    try testing.expect(pkey.key_type == .keypair);
    try testing.expect(pkey.public_key != null);
    try testing.expect(pkey.private_key != null);
}

test "OpenSSL API key generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const ctx = OpenSSL_API.EVP_PKEY_CTX_new_id(allocator, PQC_NIDS.NID_KYBER768);
    try testing.expect(ctx != null);
    defer OpenSSL_API.EVP_PKEY_CTX_free(ctx, allocator);

    const init_result = OpenSSL_API.EVP_PKEY_keygen_init(ctx);
    try testing.expect(init_result == @intFromEnum(SSL_ERROR.SSL_SUCCESS));

    var pkey: ?*EVP_PKEY = null;
    const keygen_result = OpenSSL_API.EVP_PKEY_keygen(ctx, &pkey);
    try testing.expect(keygen_result == @intFromEnum(SSL_ERROR.SSL_SUCCESS));
    try testing.expect(pkey != null);

    defer OpenSSL_API.EVP_PKEY_free(pkey, allocator);
}
