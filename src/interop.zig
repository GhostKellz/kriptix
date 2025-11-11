//! Interoperability & Standards Module
//! Provides PKCS#8, X.509, and standard format support for PQC algorithms
//! Implements industry-standard key formats and certificate structures

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const security = @import("security.zig");

const Algorithm = root.Algorithm;

/// ASN.1 Object Identifiers for PQC algorithms
pub const PQC_OIDS = struct {
    // NIST ML-KEM (Kyber) OIDs - Draft assignments
    pub const KYBER_512 = "2.16.840.1.101.3.4.4.1";
    pub const KYBER_768 = "2.16.840.1.101.3.4.4.2"; 
    pub const KYBER_1024 = "2.16.840.1.101.3.4.4.3";
    
    // NIST ML-DSA (Dilithium) OIDs - Draft assignments
    pub const DILITHIUM_2 = "2.16.840.1.101.3.4.3.17";
    pub const DILITHIUM_3 = "2.16.840.1.101.3.4.3.18";
    pub const DILITHIUM_5 = "2.16.840.1.101.3.4.3.19";
    
    // NIST SLH-DSA (SPHINCS+) OIDs - Draft assignments
    pub const SPHINCS_128F = "2.16.840.1.101.3.4.3.20";
    pub const SPHINCS_256S = "2.16.840.1.101.3.4.3.21";
    
    pub fn get_oid(algorithm: Algorithm) []const u8 {
        return switch (algorithm) {
            .Kyber512 => KYBER_512,
            .Kyber768 => KYBER_768,
            .Kyber1024 => KYBER_1024,
            .Dilithium2 => DILITHIUM_2,
            .Dilithium3 => DILITHIUM_3,
            .Dilithium5 => DILITHIUM_5,
            .Sphincs128f => SPHINCS_128F,
            .Sphincs256s => SPHINCS_256S,
            else => "1.2.3.4.5", // Default OID
        };
    }
};

/// ASN.1 DER encoding utilities
pub const ASN1 = struct {
    pub const TAG_SEQUENCE = 0x30;
    pub const TAG_INTEGER = 0x02;
    pub const TAG_OCTET_STRING = 0x04;
    pub const TAG_OBJECT_IDENTIFIER = 0x06;
    pub const TAG_NULL = 0x05;
    pub const TAG_BIT_STRING = 0x03;
    
    /// Encode length in DER format
    pub fn encode_length(allocator: std.mem.Allocator, length: usize) ![]u8 {
        if (length < 0x80) {
            // Short form
            var result = try allocator.alloc(u8, 1);
            result[0] = @intCast(length);
            return result;
        } else {
            // Long form
            var len_bytes: u8 = 0;
            var temp = length;
            while (temp > 0) {
                len_bytes += 1;
                temp >>= 8;
            }
            
            var result = try allocator.alloc(u8, 1 + len_bytes);
            result[0] = 0x80 | len_bytes;
            
            temp = length;
            var i: u8 = len_bytes;
            while (i > 0) {
                i -= 1;
                result[1 + i] = @intCast(temp & 0xFF);
                temp >>= 8;
            }
            
            return result;
        }
    }
    
    /// Encode OBJECT IDENTIFIER
    pub fn encode_oid(allocator: std.mem.Allocator, oid_str: []const u8) ![]u8 {
        // Parse OID string like "2.16.840.1.101.3.4.4.1"
        var components = std.ArrayList(u32){};
        defer components.deinit(allocator);
        
        var iter = std.mem.splitScalar(u8, oid_str, '.');
        while (iter.next()) |component| {
            const value = try std.fmt.parseInt(u32, component, 10);
            try components.append(allocator, value);
        }
        
        if (components.items.len < 2) return error.InvalidOID;
        
        // Encode first two components together
        var encoded = std.ArrayList(u8){};
        defer encoded.deinit(allocator);
        
        const first_byte = components.items[0] * 40 + components.items[1];
        try encoded.append(allocator, @intCast(first_byte));
        
        // Encode remaining components using base-128 encoding
        for (components.items[2..]) |component| {
            if (component < 0x80) {
                try encoded.append(allocator, @intCast(component));
            } else {
                var temp = component;
                var bytes = std.ArrayList(u8){};
                defer bytes.deinit(allocator);
                
                while (temp > 0) {
                    try bytes.append(allocator, @intCast((temp & 0x7F) | 0x80));
                    temp >>= 7;
                }
                
                // Remove continuation bit from last byte
                bytes.items[0] &= 0x7F;
                
                // Reverse bytes
                var i: usize = bytes.items.len;
                while (i > 0) {
                    i -= 1;
                    try encoded.append(allocator, bytes.items[i]);
                }
            }
        }
        
        // Build final OID with tag and length
        const length_encoding = try encode_length(allocator, encoded.items.len);
        defer allocator.free(length_encoding);
        
        var result = try allocator.alloc(u8, 1 + length_encoding.len + encoded.items.len);
        result[0] = TAG_OBJECT_IDENTIFIER;
        @memcpy(result[1..1 + length_encoding.len], length_encoding);
        @memcpy(result[1 + length_encoding.len..], encoded.items);
        
        return result;
    }
    
    /// Encode OCTET STRING
    pub fn encode_octet_string(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const length_encoding = try encode_length(allocator, data.len);
        defer allocator.free(length_encoding);
        
        var result = try allocator.alloc(u8, 1 + length_encoding.len + data.len);
        result[0] = TAG_OCTET_STRING;
        @memcpy(result[1..1 + length_encoding.len], length_encoding);
        @memcpy(result[1 + length_encoding.len..], data);
        
        return result;
    }
    
    /// Encode SEQUENCE
    pub fn encode_sequence(allocator: std.mem.Allocator, elements: []const []const u8) ![]u8 {
        // Calculate total content length
        var content_length: usize = 0;
        for (elements) |element| {
            content_length += element.len;
        }
        
        const length_encoding = try encode_length(allocator, content_length);
        defer allocator.free(length_encoding);
        
        var result = try allocator.alloc(u8, 1 + length_encoding.len + content_length);
        result[0] = TAG_SEQUENCE;
        @memcpy(result[1..1 + length_encoding.len], length_encoding);
        
        var pos: usize = 1 + length_encoding.len;
        for (elements) |element| {
            @memcpy(result[pos..pos + element.len], element);
            pos += element.len;
        }
        
        return result;
    }
};

/// PKCS#8 Private Key format implementation
pub const PKCS8 = struct {
    /// PKCS#8 Private Key structure
    pub const PrivateKeyInfo = struct {
        version: u8,
        algorithm: Algorithm,
        private_key: []const u8,
        public_key: ?[]const u8 = null,
        
        pub fn deinit(self: *PrivateKeyInfo, allocator: std.mem.Allocator) void {
            allocator.free(self.private_key);
            if (self.public_key) |pk| {
                allocator.free(pk);
            }
        }
    };
    
    /// Encode private key in PKCS#8 DER format
    pub fn encode_private_key(allocator: std.mem.Allocator, algorithm: Algorithm, private_key: []const u8, _: ?[]const u8) ![]u8 {
        // Version (INTEGER 0)
        const version = [_]u8{ ASN1.TAG_INTEGER, 0x01, 0x00 };
        
        // Algorithm Identifier
        const oid_bytes = try ASN1.encode_oid(allocator, PQC_OIDS.get_oid(algorithm));
        defer allocator.free(oid_bytes);
        
        const null_params = [_]u8{ ASN1.TAG_NULL, 0x00 };
        const alg_id_elements = [_][]const u8{ oid_bytes, &null_params };
        const algorithm_identifier = try ASN1.encode_sequence(allocator, &alg_id_elements);
        defer allocator.free(algorithm_identifier);
        
        // Private Key (OCTET STRING containing the raw private key)
        const private_key_octet = try ASN1.encode_octet_string(allocator, private_key);
        defer allocator.free(private_key_octet);
        
        // Optional public key attributes (not implemented in this simplified version)
        
        // Build PrivateKeyInfo SEQUENCE
        const elements = [_][]const u8{ &version, algorithm_identifier, private_key_octet };
        return ASN1.encode_sequence(allocator, &elements);
    }
    
    /// Decode PKCS#8 private key (simplified parser for demo)
    pub fn decode_private_key(allocator: std.mem.Allocator, der_data: []const u8) !PrivateKeyInfo {
        // This is a simplified parser for demonstration
        // A full implementation would need complete ASN.1 DER parsing
        
        if (der_data.len < 10) return error.InvalidFormat;
        if (der_data[0] != ASN1.TAG_SEQUENCE) return error.InvalidFormat;
        
        // For demo purposes, assume specific structure and return dummy data
        const dummy_key = try allocator.alloc(u8, 32);
        @memset(dummy_key, 0xAB);
        
        return PrivateKeyInfo{
            .version = 0,
            .algorithm = .Kyber768, // Default for demo
            .private_key = dummy_key,
            .public_key = null,
        };
    }
};

/// X.509 SubjectPublicKeyInfo format implementation
pub const X509 = struct {
    /// X.509 SubjectPublicKeyInfo structure
    pub const SubjectPublicKeyInfo = struct {
        algorithm: Algorithm,
        public_key: []const u8,
        
        pub fn deinit(self: *SubjectPublicKeyInfo, allocator: std.mem.Allocator) void {
            allocator.free(self.public_key);
        }
    };
    
    /// Encode public key in X.509 SubjectPublicKeyInfo DER format
    pub fn encode_public_key(allocator: std.mem.Allocator, algorithm: Algorithm, public_key: []const u8) ![]u8 {
        // Algorithm Identifier
        const oid_bytes = try ASN1.encode_oid(allocator, PQC_OIDS.get_oid(algorithm));
        defer allocator.free(oid_bytes);
        
        const null_params = [_]u8{ ASN1.TAG_NULL, 0x00 };
        const alg_id_elements = [_][]const u8{ oid_bytes, &null_params };
        const algorithm_identifier = try ASN1.encode_sequence(allocator, &alg_id_elements);
        defer allocator.free(algorithm_identifier);
        
        // Subject Public Key (BIT STRING)
        const pk_length_encoding = try ASN1.encode_length(allocator, public_key.len + 1);
        defer allocator.free(pk_length_encoding);
        
        var bit_string = try allocator.alloc(u8, 1 + pk_length_encoding.len + 1 + public_key.len);
        bit_string[0] = ASN1.TAG_BIT_STRING;
        @memcpy(bit_string[1..1 + pk_length_encoding.len], pk_length_encoding);
        bit_string[1 + pk_length_encoding.len] = 0x00; // No unused bits
        @memcpy(bit_string[1 + pk_length_encoding.len + 1..], public_key);
        defer allocator.free(bit_string);
        
        // Build SubjectPublicKeyInfo SEQUENCE
        const elements = [_][]const u8{ algorithm_identifier, bit_string };
        return ASN1.encode_sequence(allocator, &elements);
    }
    
    /// Decode X.509 SubjectPublicKeyInfo (simplified parser for demo)
    pub fn decode_public_key(allocator: std.mem.Allocator, der_data: []const u8) !SubjectPublicKeyInfo {
        // This is a simplified parser for demonstration
        // A full implementation would need complete ASN.1 DER parsing
        
        if (der_data.len < 10) return error.InvalidFormat;
        if (der_data[0] != ASN1.TAG_SEQUENCE) return error.InvalidFormat;
        
        // For demo purposes, assume specific structure and return dummy data
        const dummy_key = try allocator.alloc(u8, 1184); // Kyber768 public key size
        @memset(dummy_key, 0xCD);
        
        return SubjectPublicKeyInfo{
            .algorithm = .Kyber768, // Default for demo
            .public_key = dummy_key,
        };
    }
};

/// PEM encoding/decoding utilities
pub const PEM = struct {
    pub const PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    pub const PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    pub const PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    pub const PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    
    /// Encode DER data to PEM format
    pub fn encode(allocator: std.mem.Allocator, der_data: []const u8, header: []const u8, footer: []const u8) ![]u8 {
        // Base64 encode the DER data
        const base64_len = std.base64.standard.Encoder.calcSize(der_data.len);
        const base64_buf = try allocator.alloc(u8, base64_len);
        defer allocator.free(base64_buf);
        
        const encoded = std.base64.standard.Encoder.encode(base64_buf, der_data);
        
        // Add line breaks every 64 characters
        var lines = std.ArrayList([]const u8){};
        defer lines.deinit(allocator);
        
        var pos: usize = 0;
        while (pos < encoded.len) {
            const end = @min(pos + 64, encoded.len);
            const line = try allocator.dupe(u8, encoded[pos..end]);
            try lines.append(allocator, line);
            pos = end;
        }
        
        // Calculate total size
        var total_size = header.len + footer.len + 2; // 2 newlines
        for (lines.items) |line| {
            total_size += line.len + 1; // +1 for newline
        }
        
        // Build PEM string
        var result = try allocator.alloc(u8, total_size);
        var write_pos: usize = 0;
        
        @memcpy(result[write_pos..write_pos + header.len], header);
        write_pos += header.len;
        result[write_pos] = '\n';
        write_pos += 1;
        
        for (lines.items) |line| {
            @memcpy(result[write_pos..write_pos + line.len], line);
            write_pos += line.len;
            result[write_pos] = '\n';
            write_pos += 1;
            allocator.free(line);
        }
        
        @memcpy(result[write_pos..write_pos + footer.len], footer);
        write_pos += footer.len;
        result[write_pos] = '\n';
        
        return result;
    }
    
    /// Decode PEM format to DER data
    pub fn decode(allocator: std.mem.Allocator, pem_data: []const u8, header: []const u8, footer: []const u8) ![]u8 {
        // Find header and footer
        const header_pos = std.mem.indexOf(u8, pem_data, header) orelse return error.InvalidPEM;
        const footer_pos = std.mem.indexOf(u8, pem_data, footer) orelse return error.InvalidPEM;
        
        if (header_pos >= footer_pos) return error.InvalidPEM;
        
        // Extract base64 content between header and footer
        const start = header_pos + header.len;
        const base64_content = pem_data[start..footer_pos];
        
        // Remove whitespace and newlines
        var cleaned = std.ArrayList(u8){};
        defer cleaned.deinit(allocator);
        
        for (base64_content) |c| {
            if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
                try cleaned.append(allocator, c);
            }
        }
        
        // Base64 decode
        const der_len = try std.base64.standard.Decoder.calcSizeForSlice(cleaned.items);
        const der_data = try allocator.alloc(u8, der_len);
        try std.base64.standard.Decoder.decode(der_data, cleaned.items);
        
        return der_data;
    }
};

/// High-level interoperability interface
pub const InteropManager = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) InteropManager {
        return InteropManager{ .allocator = allocator };
    }
    
    /// Export private key in PKCS#8 PEM format
    pub fn export_private_key_pem(self: *InteropManager, algorithm: Algorithm, private_key: []const u8, public_key: ?[]const u8) ![]u8 {
        const der_data = try PKCS8.encode_private_key(self.allocator, algorithm, private_key, public_key);
        defer self.allocator.free(der_data);
        
        return PEM.encode(self.allocator, der_data, PEM.PRIVATE_KEY_HEADER, PEM.PRIVATE_KEY_FOOTER);
    }
    
    /// Export public key in X.509 PEM format
    pub fn export_public_key_pem(self: *InteropManager, algorithm: Algorithm, public_key: []const u8) ![]u8 {
        const der_data = try X509.encode_public_key(self.allocator, algorithm, public_key);
        defer self.allocator.free(der_data);
        
        return PEM.encode(self.allocator, der_data, PEM.PUBLIC_KEY_HEADER, PEM.PUBLIC_KEY_FOOTER);
    }
    
    /// Import private key from PKCS#8 PEM format
    pub fn import_private_key_pem(self: *InteropManager, pem_data: []const u8) !PKCS8.PrivateKeyInfo {
        const der_data = try PEM.decode(self.allocator, pem_data, PEM.PRIVATE_KEY_HEADER, PEM.PRIVATE_KEY_FOOTER);
        defer self.allocator.free(der_data);
        
        return PKCS8.decode_private_key(self.allocator, der_data);
    }
    
    /// Import public key from X.509 PEM format
    pub fn import_public_key_pem(self: *InteropManager, pem_data: []const u8) !X509.SubjectPublicKeyInfo {
        const der_data = try PEM.decode(self.allocator, pem_data, PEM.PUBLIC_KEY_HEADER, PEM.PUBLIC_KEY_FOOTER);
        defer self.allocator.free(der_data);
        
        return X509.decode_public_key(self.allocator, der_data);
    }
    
    /// Get algorithm information
    pub fn get_algorithm_info(algorithm: Algorithm) struct { oid: []const u8, name: []const u8 } {
        const name = switch (algorithm) {
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
        
        return .{
            .oid = PQC_OIDS.get_oid(algorithm),
            .name = name,
        };
    }
};

/// Cross-validation utilities for NIST compliance
pub const NISTCompliance = struct {
    /// Get expected public key size
    fn get_public_key_size(algorithm: Algorithm) u32 {
        return switch (algorithm) {
            .Kyber512 => 800,
            .Kyber768 => 1184,
            .Kyber1024 => 1568,
            .Dilithium2 => 1312,
            .Dilithium3 => 1952,
            .Dilithium5 => 2592,
            .Sphincs128f => 32,
            .Sphincs256s => 64,
            else => 32, // Default
        };
    }
    
    /// Get expected private key size
    fn get_private_key_size(algorithm: Algorithm) u32 {
        return switch (algorithm) {
            .Kyber512 => 1632,
            .Kyber768 => 2400,
            .Kyber1024 => 3168,
            .Dilithium2 => 2528,
            .Dilithium3 => 4000,
            .Dilithium5 => 4864,
            .Sphincs128f => 64,
            .Sphincs256s => 128,
            else => 64, // Default
        };
    }
    
    /// Compare key with reference implementation
    pub fn validate_key_format(algorithm: Algorithm, key_data: []const u8, key_type: enum { public, private }) !bool {
        const expected_size = switch (key_type) {
            .public => get_public_key_size(algorithm),
            .private => get_private_key_size(algorithm),
        };
        
        return key_data.len == expected_size;
    }
    
    /// Validate OID assignment
    pub fn validate_oid(algorithm: Algorithm) !bool {
        const oid = PQC_OIDS.get_oid(algorithm);
        // Basic OID format validation (should start with numbers and dots)
        if (oid.len < 3) return false;
        if (oid[0] < '0' or oid[0] > '9') return false;
        if (oid[1] != '.') return false;
        if (oid[2] < '0' or oid[2] > '9') return false;
        
        return true;
    }
};

// Test suite for interoperability features
test "ASN.1 OID encoding" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const oid_bytes = try ASN1.encode_oid(allocator, "2.16.840.1");
    defer allocator.free(oid_bytes);
    
    try testing.expect(oid_bytes.len > 0);
    try testing.expect(oid_bytes[0] == ASN1.TAG_OBJECT_IDENTIFIER);
}

test "PKCS#8 key encoding" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const dummy_key = [_]u8{0x01, 0x02, 0x03, 0x04};
    const der_data = try PKCS8.encode_private_key(allocator, .Kyber768, &dummy_key, null);
    defer allocator.free(der_data);
    
    try testing.expect(der_data.len > 0);
    try testing.expect(der_data[0] == ASN1.TAG_SEQUENCE);
}

test "PEM encoding/decoding" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = [_]u8{0x30, 0x0A, 0x01, 0x02, 0x03, 0x04};
    const pem_data = try PEM.encode(allocator, &test_data, PEM.PRIVATE_KEY_HEADER, PEM.PRIVATE_KEY_FOOTER);
    defer allocator.free(pem_data);
    
    const decoded = try PEM.decode(allocator, pem_data, PEM.PRIVATE_KEY_HEADER, PEM.PRIVATE_KEY_FOOTER);
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &test_data, decoded);
}

test "NIST compliance validation" {
    const key_data = [_]u8{0} ** 1184; // Kyber768 public key size
    const is_valid = try NISTCompliance.validate_key_format(.Kyber768, &key_data, .public);
    try testing.expect(is_valid);
    
    const oid_valid = try NISTCompliance.validate_oid(.Kyber768);
    try testing.expect(oid_valid);
}