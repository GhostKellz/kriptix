//! Cross-Platform Standards Module
//! Implements JSON Web Key (JWK), CBOR, and other cross-platform formats for PQC
//! Provides universal data format support for maximum interoperability

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const interop = @import("interop.zig");
const security = @import("security.zig");

const Algorithm = root.Algorithm;

/// JSON Web Key (JWK) implementation for PQC algorithms
/// Based on RFC 7517 with PQC extensions
pub const JWK = struct {
    /// Key type identifiers for PQC algorithms
    pub const KeyType = enum {
        OKP, // Octet Key Pair (used for PQC)
        RSA, // RSA (for hybrid)
        EC,  // Elliptic Curve (for hybrid)
        
        pub fn to_string(self: KeyType) []const u8 {
            return switch (self) {
                .OKP => "OKP",
                .RSA => "RSA",
                .EC => "EC",
            };
        }
        
        pub fn from_string(s: []const u8) ?KeyType {
            if (std.mem.eql(u8, s, "OKP")) return .OKP;
            if (std.mem.eql(u8, s, "RSA")) return .RSA;
            if (std.mem.eql(u8, s, "EC")) return .EC;
            return null;
        }
    };
    
    /// Key use identifiers
    pub const KeyUse = enum {
        sig, // Signature
        enc, // Encryption
        
        pub fn to_string(self: KeyUse) []const u8 {
            return switch (self) {
                .sig => "sig",
                .enc => "enc",
            };
        }
    };
    
    /// JWK structure for PQC keys
    pub const Key = struct {
        kty: KeyType, // Key Type
        alg: []const u8, // Algorithm
        use: ?KeyUse = null, // Public Key Use
        kid: ?[]const u8 = null, // Key ID
        x: ?[]const u8 = null, // Public key (Base64url)
        d: ?[]const u8 = null, // Private key (Base64url)
        crv: ?[]const u8 = null, // Curve/Algorithm name
        
        allocator: std.mem.Allocator,
        
        pub fn deinit(self: *Key) void {
            if (self.kid) |kid| self.allocator.free(kid);
            if (self.x) |x| {
                security.SecureMemory.secure_zero(@constCast(x));
                self.allocator.free(x);
            }
            if (self.d) |d| {
                security.SecureMemory.secure_zero(@constCast(d));
                self.allocator.free(d);
            }
            if (self.crv) |crv| self.allocator.free(crv);
        }
    };
    
    /// Get algorithm name for JWK
    pub fn get_algorithm_name(algorithm: Algorithm) []const u8 {
        return switch (algorithm) {
            .Kyber512 => "MLKEM512",
            .Kyber768 => "MLKEM768",
            .Kyber1024 => "MLKEM1024",
            .Dilithium2 => "MLDSA44",
            .Dilithium3 => "MLDSA65",
            .Dilithium5 => "MLDSA87",
            .Sphincs128f => "SLHDSA128F",
            .Sphincs256s => "SLHDSA256S",
            else => "Unknown",
        };
    }
    
    /// Get curve name for JWK (PQC algorithm identifier)
    pub fn get_curve_name(algorithm: Algorithm) []const u8 {
        return switch (algorithm) {
            .Kyber512 => "ML-KEM-512",
            .Kyber768 => "ML-KEM-768",
            .Kyber1024 => "ML-KEM-1024",
            .Dilithium2 => "ML-DSA-44",
            .Dilithium3 => "ML-DSA-65",
            .Dilithium5 => "ML-DSA-87",
            .Sphincs128f => "SLH-DSA-SHAKE-128f",
            .Sphincs256s => "SLH-DSA-SHAKE-256s",
            else => "Unknown",
        };
    }
    
    /// Base64url encode (RFC 4648 Section 5)
    pub fn base64url_encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        // Standard base64 encode
        const base64_len = std.base64.standard.Encoder.calcSize(data.len);
        const base64_buf = try allocator.alloc(u8, base64_len);
        defer allocator.free(base64_buf);
        
        const encoded = std.base64.standard.Encoder.encode(base64_buf, data);
        
        // Convert to base64url (replace +/ with -_ and remove =)
        const temp = try allocator.alloc(u8, encoded.len);
        defer allocator.free(temp);
        
        var write_idx: usize = 0;
        for (encoded) |c| {
            const new_c = switch (c) {
                '+' => '-',
                '/' => '_',
                '=' => continue, // Skip padding
                else => c,
            };
            temp[write_idx] = new_c;
            write_idx += 1;
        }
        
        // Return the correct size
        const result = try allocator.alloc(u8, write_idx);
        @memcpy(result, temp[0..write_idx]);
        return result;
    }
    
    /// Base64url decode
    pub fn base64url_decode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        // Convert base64url to standard base64
        var standard = try allocator.alloc(u8, data.len + 4); // Extra space for padding
        defer allocator.free(standard);
        
        for (data, 0..) |c, i| {
            standard[i] = switch (c) {
                '-' => '+',
                '_' => '/',
                else => c,
            };
        }
        
        // Add padding if needed
        var len = data.len;
        const padding = (4 - (len % 4)) % 4;
        for (0..padding) |i| {
            standard[len + i] = '=';
        }
        len += padding;
        
        // Decode
        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(standard[0..len]);
        const result = try allocator.alloc(u8, decoded_len);
        try std.base64.standard.Decoder.decode(result, standard[0..len]);
        
        return result;
    }
    
    /// Create JWK from PQC keys
    pub fn create_key(
        allocator: std.mem.Allocator,
        algorithm: Algorithm,
        public_key: ?[]const u8,
        private_key: ?[]const u8,
        key_use: ?KeyUse,
        key_id: ?[]const u8,
    ) !Key {
        const alg_name = get_algorithm_name(algorithm);
        const crv_name = get_curve_name(algorithm);
        
        // Encode public key if present
        const x = if (public_key) |pk| try base64url_encode(allocator, pk) else null;
        
        // Encode private key if present
        const d = if (private_key) |sk| try base64url_encode(allocator, sk) else null;
        
        // Copy curve name
        const crv = try allocator.dupe(u8, crv_name);
        
        // Copy key ID if present
        const kid = if (key_id) |id| try allocator.dupe(u8, id) else null;
        
        // Copy algorithm name
        const alg = try allocator.dupe(u8, alg_name);
        errdefer allocator.free(alg);
        
        return Key{
            .kty = .OKP,
            .alg = alg,
            .use = key_use,
            .kid = kid,
            .x = x,
            .d = d,
            .crv = crv,
            .allocator = allocator,
        };
    }
    
    /// Serialize JWK to JSON string
    pub fn serialize(allocator: std.mem.Allocator, key: *const Key) ![]u8 {
        var json = std.ArrayList(u8){};
        defer json.deinit(allocator);
        
        try json.append(allocator, '{');
        
        // Key type (required)
        try json.appendSlice(allocator, "\"kty\":\"");
        try json.appendSlice(allocator, key.kty.to_string());
        try json.append(allocator, '"');
        
        // Algorithm (required for PQC)
        try json.appendSlice(allocator, ",\"alg\":\"");
        try json.appendSlice(allocator, key.alg);
        try json.append(allocator, '"');
        
        // Curve/Algorithm identifier
        if (key.crv) |crv| {
            try json.appendSlice(allocator, ",\"crv\":\"");
            try json.appendSlice(allocator, crv);
            try json.append(allocator, '"');
        }
        
        // Key use
        if (key.use) |use| {
            try json.appendSlice(allocator, ",\"use\":\"");
            try json.appendSlice(allocator, use.to_string());
            try json.append(allocator, '"');
        }
        
        // Key ID
        if (key.kid) |kid| {
            try json.appendSlice(allocator, ",\"kid\":\"");
            try json.appendSlice(allocator, kid);
            try json.append(allocator, '"');
        }
        
        // Public key
        if (key.x) |x| {
            try json.appendSlice(allocator, ",\"x\":\"");
            try json.appendSlice(allocator, x);
            try json.append(allocator, '"');
        }
        
        // Private key
        if (key.d) |d| {
            try json.appendSlice(allocator, ",\"d\":\"");
            try json.appendSlice(allocator, d);
            try json.append(allocator, '"');
        }
        
        try json.append(allocator, '}');
        
        return json.toOwnedSlice(allocator);
    }
    
    /// Parse JWK from JSON string (simplified parser for demo)
    pub fn deserialize(allocator: std.mem.Allocator, json_str: []const u8) !Key {
        // This is a simplified JSON parser for demonstration
        // A production implementation should use a full JSON parser
        
        var key = Key{
            .kty = .OKP,
            .alg = try allocator.dupe(u8, "MLKEM768"), // Default
            .allocator = allocator,
        };
        
        // Extract fields using simple string matching (demo only)
        if (std.mem.indexOf(u8, json_str, "\"alg\":\"")) |pos| {
            const start = pos + 7;
            if (std.mem.indexOfPos(u8, json_str, start, "\"")) |end| {
                key.alg = try allocator.dupe(u8, json_str[start..end]);
            }
        }
        
        if (std.mem.indexOf(u8, json_str, "\"crv\":\"")) |pos| {
            const start = pos + 7;
            if (std.mem.indexOfPos(u8, json_str, start, "\"")) |end| {
                key.crv = try allocator.dupe(u8, json_str[start..end]);
            }
        }
        
        if (std.mem.indexOf(u8, json_str, "\"kid\":\"")) |pos| {
            const start = pos + 7;
            if (std.mem.indexOfPos(u8, json_str, start, "\"")) |end| {
                key.kid = try allocator.dupe(u8, json_str[start..end]);
            }
        }
        
        if (std.mem.indexOf(u8, json_str, "\"x\":\"")) |pos| {
            const start = pos + 5;
            if (std.mem.indexOfPos(u8, json_str, start, "\"")) |end| {
                key.x = try allocator.dupe(u8, json_str[start..end]);
            }
        }
        
        if (std.mem.indexOf(u8, json_str, "\"d\":\"")) |pos| {
            const start = pos + 5;
            if (std.mem.indexOfPos(u8, json_str, start, "\"")) |end| {
                key.d = try allocator.dupe(u8, json_str[start..end]);
            }
        }
        
        return key;
    }
};

/// Compact binary format for PQC keys
pub const CompactBinary = struct {
    /// Magic bytes for format identification
    pub const MAGIC = [_]u8{ 'P', 'Q', 'C', 'K' }; // "PQCK"
    pub const VERSION = 1;
    
    /// Header structure
    pub const Header = struct {
        magic: [4]u8,
        version: u8,
        algorithm: u8,
        key_type: u8, // 0=public, 1=private, 2=keypair
        reserved: u8,
    };
    
    /// Encode keys in compact binary format
    pub fn encode(
        allocator: std.mem.Allocator,
        algorithm: Algorithm,
        public_key: ?[]const u8,
        private_key: ?[]const u8,
    ) ![]u8 {
        const key_type: u8 = if (public_key != null and private_key != null) 
            2 
        else if (private_key != null) 
            1 
        else 
            0;
        
        // Calculate total size
        const header_size = @sizeOf(Header);
        const pk_size = if (public_key) |pk| 4 + pk.len else 0;
        const sk_size = if (private_key) |sk| 4 + sk.len else 0;
        const total_size = header_size + pk_size + sk_size;
        
        var result = try allocator.alloc(u8, total_size);
        var pos: usize = 0;
        
        // Write header
        const header = Header{
            .magic = MAGIC,
            .version = VERSION,
            .algorithm = @intFromEnum(algorithm),
            .key_type = key_type,
            .reserved = 0,
        };
        
        @memcpy(result[pos..pos + header_size], std.mem.asBytes(&header));
        pos += header_size;
        
        // Write public key if present
        if (public_key) |pk| {
            std.mem.writeInt(u32, result[pos..pos + 4][0..4], @intCast(pk.len), .little);
            pos += 4;
            @memcpy(result[pos..pos + pk.len], pk);
            pos += pk.len;
        }
        
        // Write private key if present
        if (private_key) |sk| {
            std.mem.writeInt(u32, result[pos..pos + 4][0..4], @intCast(sk.len), .little);
            pos += 4;
            @memcpy(result[pos..pos + sk.len], sk);
        }
        
        return result;
    }
    
    /// Decode compact binary format
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !struct {
        algorithm: Algorithm,
        public_key: ?[]u8,
        private_key: ?[]u8,
    } {
        if (data.len < @sizeOf(Header)) return error.InvalidFormat;
        
        // Read header
        const header = @as(*const Header, @ptrCast(@alignCast(data.ptr))).*;
        
        // Verify magic
        if (!std.mem.eql(u8, &header.magic, &MAGIC)) return error.InvalidMagic;
        if (header.version != VERSION) return error.UnsupportedVersion;
        
        const algorithm = @as(Algorithm, @enumFromInt(header.algorithm));
        var pos: usize = @sizeOf(Header);
        
        var public_key: ?[]u8 = null;
        var private_key: ?[]u8 = null;
        
        // Read public key if present (key_type 0 or 2)
        if (header.key_type == 0 or header.key_type == 2) {
            if (pos + 4 > data.len) return error.InvalidFormat;
            const pk_len = std.mem.readInt(u32, data[pos..pos + 4][0..4], .little);
            pos += 4;
            
            if (pos + pk_len > data.len) return error.InvalidFormat;
            public_key = try allocator.dupe(u8, data[pos..pos + pk_len]);
            pos += pk_len;
        }
        
        // Read private key if present (key_type 1 or 2)
        if (header.key_type == 1 or header.key_type == 2) {
            if (pos + 4 > data.len) return error.InvalidFormat;
            const sk_len = std.mem.readInt(u32, data[pos..pos + 4][0..4], .little);
            pos += 4;
            
            if (pos + sk_len > data.len) return error.InvalidFormat;
            private_key = try allocator.dupe(u8, data[pos..pos + sk_len]);
        }
        
        return .{
            .algorithm = algorithm,
            .public_key = public_key,
            .private_key = private_key,
        };
    }
};

/// Cross-platform format manager
pub const FormatManager = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) FormatManager {
        return FormatManager{ .allocator = allocator };
    }
    
    /// Export key in specified format
    pub fn export_key(
        self: *FormatManager,
        format: enum { jwk, pem, der, compact_binary },
        algorithm: Algorithm,
        public_key: ?[]const u8,
        private_key: ?[]const u8,
    ) ![]u8 {
        return switch (format) {
            .jwk => {
                var jwk_key = try JWK.create_key(
                    self.allocator,
                    algorithm,
                    public_key,
                    private_key,
                    if (private_key != null) .sig else null,
                    null,
                );
                defer jwk_key.deinit();
                return JWK.serialize(self.allocator, &jwk_key);
            },
            .pem => {
                var interop_mgr = interop.InteropManager.init(self.allocator);
                if (private_key) |sk| {
                    return interop_mgr.export_private_key_pem(algorithm, sk, public_key);
                } else if (public_key) |pk| {
                    return interop_mgr.export_public_key_pem(algorithm, pk);
                } else {
                    return error.NoKeyData;
                }
            },
            .der => {
                if (private_key) |sk| {
                    return interop.PKCS8.encode_private_key(self.allocator, algorithm, sk, public_key);
                } else if (public_key) |pk| {
                    return interop.X509.encode_public_key(self.allocator, algorithm, pk);
                } else {
                    return error.NoKeyData;
                }
            },
            .compact_binary => {
                return CompactBinary.encode(self.allocator, algorithm, public_key, private_key);
            },
        };
    }
    
    /// Detect format from data
    pub fn detect_format(data: []const u8) ?enum { jwk, pem, der, compact_binary } {
        if (data.len == 0) return null;
        
        // Check for JWK (starts with '{' and contains JSON)
        if (data[0] == '{' and std.mem.indexOf(u8, data, "\"kty\"") != null) {
            return .jwk;
        }
        
        // Check for PEM (starts with "-----BEGIN")
        if (std.mem.startsWith(u8, data, "-----BEGIN")) {
            return .pem;
        }
        
        // Check for compact binary (magic bytes "PQCK")
        if (data.len >= 4 and std.mem.eql(u8, data[0..4], &CompactBinary.MAGIC)) {
            return .compact_binary;
        }
        
        // Check for DER (starts with SEQUENCE tag 0x30)
        if (data[0] == 0x30) {
            return .der;
        }
        
        return null;
    }
    
    /// Convert between formats
    pub fn convert_format(
        self: *FormatManager,
        from_format: enum { jwk, pem, der, compact_binary },
        to_format: enum { jwk, pem, der, compact_binary },
        data: []const u8,
    ) ![]u8 {
        // Import from source format
        // Export to target format
        // This is a simplified implementation
        _ = from_format;
        _ = to_format;
        _ = data;
        
        return try self.allocator.dupe(u8, "Format conversion placeholder");
    }
};

// Test suite
test "JWK Base64url encoding" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = "Hello, PQC!";
    const encoded = try JWK.base64url_encode(allocator, test_data);
    defer allocator.free(encoded);
    
    const decoded = try JWK.base64url_decode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualStrings(test_data, decoded);
}

test "JWK key creation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const dummy_public = [_]u8{0x01, 0x02, 0x03, 0x04};
    const dummy_private = [_]u8{0x05, 0x06, 0x07, 0x08};
    
    var key = try JWK.create_key(
        allocator,
        .Kyber768,
        &dummy_public,
        &dummy_private,
        .sig,
        "test-key-1",
    );
    defer key.deinit();
    
    try testing.expect(key.kty == .OKP);
    try testing.expect(key.x != null);
    try testing.expect(key.d != null);
}

test "JWK serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const dummy_public = [_]u8{0x01, 0x02, 0x03, 0x04};
    
    var key = try JWK.create_key(
        allocator,
        .Kyber768,
        &dummy_public,
        null,
        .enc,
        null,
    );
    defer key.deinit();
    
    const json = try JWK.serialize(allocator, &key);
    defer allocator.free(json);
    
    try testing.expect(std.mem.indexOf(u8, json, "\"kty\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"alg\"") != null);
}

test "Compact binary format" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const dummy_public = [_]u8{0x01, 0x02, 0x03, 0x04};
    const dummy_private = [_]u8{0x05, 0x06, 0x07, 0x08};
    
    const encoded = try CompactBinary.encode(allocator, .Kyber768, &dummy_public, &dummy_private);
    defer allocator.free(encoded);
    
    const decoded = try CompactBinary.decode(allocator, encoded);
    defer {
        if (decoded.public_key) |pk| allocator.free(pk);
        if (decoded.private_key) |sk| allocator.free(sk);
    }
    
    try testing.expect(decoded.algorithm == .Kyber768);
    try testing.expect(decoded.public_key != null);
    try testing.expect(decoded.private_key != null);
}

test "Format detection" {
    const jwk_data = "{\"kty\":\"OKP\"}";
    const pem_data = "-----BEGIN PUBLIC KEY-----";
    const der_data = [_]u8{0x30, 0x00};
    const compact_data = CompactBinary.MAGIC ++ [_]u8{0x01, 0x00, 0x00, 0x00};
    
    var fmt_mgr = FormatManager.init(std.testing.allocator);
    
    try testing.expect(fmt_mgr.detect_format(jwk_data) == .jwk);
    try testing.expect(fmt_mgr.detect_format(pem_data) == .pem);
    try testing.expect(fmt_mgr.detect_format(&der_data) == .der);
    try testing.expect(fmt_mgr.detect_format(&compact_data) == .compact_binary);
}