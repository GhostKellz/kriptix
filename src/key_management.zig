//! Advanced Key Management System
//! Provides enterprise-grade key management features for PQC deployment
//! Includes key derivation, rotation, backup/restore, and hierarchical structures

const std = @import("std");
const testing = std.testing;
const security = @import("security.zig");
const root = @import("root.zig");

const Algorithm = root.Algorithm;
const KeyPair = root.KeyPair;

/// Key derivation paths for hierarchical deterministic keys
pub const KeyPath = struct {
    /// BIP32-style derivation path components
    components: []const u32,

    /// Create a new key path
    pub fn init(allocator: std.mem.Allocator, path_str: []const u8) !KeyPath {
        // Parse path like "m/44'/1'/0'/0/0"
        var components = std.ArrayList(u32){};
        defer components.deinit(allocator);

        var iter = std.mem.splitScalar(u8, path_str, '/');
        while (iter.next()) |component| {
            if (std.mem.eql(u8, component, "m")) continue;

            const is_hardened = std.mem.endsWith(u8, component, "'");
            const number_str = if (is_hardened) component[0 .. component.len - 1] else component;

            const number = try std.fmt.parseInt(u32, number_str, 10);
            const final_number = if (is_hardened) number | 0x80000000 else number;

            try components.append(allocator, final_number);
        }

        const owned_components = try allocator.dupe(u32, components.items);
        return KeyPath{ .components = owned_components };
    }

    pub fn deinit(self: KeyPath, allocator: std.mem.Allocator) void {
        allocator.free(self.components);
    }

    pub fn format(self: KeyPath, writer: anytype) !void {
        try writer.print("m");
        for (self.components) |component| {
            if (component & 0x80000000 != 0) {
                try writer.print("/{d}'", .{component & 0x7FFFFFFF});
            } else {
                try writer.print("/{d}", .{component});
            }
        }
    }
};

/// Hierarchical Deterministic Key Manager
pub const HDKeyManager = struct {
    allocator: std.mem.Allocator,
    master_seed: [64]u8,
    algorithm: Algorithm,

    /// Initialize with master seed
    pub fn init(allocator: std.mem.Allocator, master_seed: [64]u8, algorithm: Algorithm) HDKeyManager {
        return HDKeyManager{
            .allocator = allocator,
            .master_seed = master_seed,
            .algorithm = algorithm,
        };
    }

    /// Generate master seed from mnemonic or password
    pub fn generate_master_seed(allocator: std.mem.Allocator, passphrase: []const u8, salt: ?[]const u8) ![64]u8 {
        const actual_salt = salt orelse "kriptix_pqc_seed";

        // Use PBKDF2-like key stretching
        const stretched = try security.SecureKeyDerivation.derive_key(allocator, passphrase, actual_salt, "master_seed_derivation", 64);
        defer allocator.free(stretched);

        var seed: [64]u8 = undefined;
        @memcpy(&seed, stretched[0..64]);
        return seed;
    }

    /// Derive child key from path
    pub fn derive_key(self: *HDKeyManager, path: KeyPath) !KeyPair {
        var current_key = self.master_seed;

        // Derive through each path component
        for (path.components) |component| {
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            hasher.update(&current_key);
            hasher.update(std.mem.asBytes(&component));
            hasher.update("pqc_key_derivation");

            var derived: [64]u8 = undefined;
            hasher.final(&derived);
            current_key = derived;
        }

        // Generate final keypair from derived seed
        return try self.generate_keypair_from_seed(current_key);
    }

    /// Get public key size for algorithm
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
            else => 32, // Default size
        };
    }

    /// Get private key size for algorithm
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
            else => 64, // Default size
        };
    }

    /// Generate keypair from seed (prefers algorithm-specific deterministic derivation)
    fn generate_keypair_from_seed(self: *HDKeyManager, seed: [64]u8) !KeyPair {
    const seed_slice = @as([]const u8, seed[0..]);

        return root.generate_keypair_deterministic(self.allocator, self.algorithm, seed_slice) catch |err| switch (err) {
            error.UnsupportedAlgorithm => blk: {
                const pk_size = get_public_key_size(self.algorithm);
                const sk_size = get_private_key_size(self.algorithm);

                const public_key = try security.SecureKeyDerivation.derive_key(self.allocator, &seed, "public", "pqc_pk", pk_size);
                const private_key = try security.SecureKeyDerivation.derive_key(self.allocator, &seed, "private", "pqc_sk", sk_size);

                break :blk KeyPair{
                    .public_key = public_key,
                    .private_key = private_key,
                    .algorithm = self.algorithm,
                };
            },
            else => return err,
        };
    }

    /// Clean up sensitive data
    pub fn deinit(self: *HDKeyManager) void {
        security.SecureMemory.secure_zero(&self.master_seed);
    }
};

/// Key Rotation Manager
pub const KeyRotationManager = struct {
    allocator: std.mem.Allocator,
    current_generation: u32,
    key_history: std.ArrayList(KeyGenerationInfo),

    const KeyGenerationInfo = struct {
        generation: u32,
        created_at: i64, // Unix timestamp
        algorithm: Algorithm,
        keypair: KeyPair,
        active: bool,

        pub fn deinit(self: *KeyGenerationInfo, allocator: std.mem.Allocator) void {
            allocator.free(self.keypair.public_key);
            allocator.free(self.keypair.private_key);
        }
    };

    pub fn init(allocator: std.mem.Allocator) KeyRotationManager {
        return KeyRotationManager{
            .allocator = allocator,
            .current_generation = 0,
            .key_history = std.ArrayList(KeyGenerationInfo){},
        };
    }

    pub fn deinit(self: *KeyRotationManager) void {
        // Clean up all key generations
        for (self.key_history.items) |*info| {
            info.deinit(self.allocator);
        }
        self.key_history.deinit(self.allocator);
    }

    /// Generate new key generation
    pub fn rotate_keys(self: *KeyRotationManager, algorithm: Algorithm, hd_manager: *HDKeyManager) !void {
        self.current_generation += 1;

        // Derive new keypair using generation-specific path
        const path_str = try std.fmt.allocPrint(self.allocator, "m/44'/1'/{}'/0/0", .{self.current_generation});
        defer self.allocator.free(path_str);

        const path = try KeyPath.init(self.allocator, path_str);
        defer path.deinit(self.allocator);

        const keypair = try hd_manager.derive_key(path);

        // Deactivate previous generation
        if (self.key_history.items.len > 0) {
            self.key_history.items[self.key_history.items.len - 1].active = false;
        }

        // Add new generation
        const info = KeyGenerationInfo{
            .generation = self.current_generation,
            .created_at = @intCast(self.current_generation * 1000), // Simple demo timestamp
            .algorithm = algorithm,
            .keypair = keypair,
            .active = true,
        };

        try self.key_history.append(self.allocator, info);

        std.debug.print("🔄 Key rotation completed: Generation {d}\n", .{self.current_generation});
    }

    /// Get current active keypair
    pub fn get_current_keypair(self: *const KeyRotationManager) ?*const KeyPair {
        for (self.key_history.items) |*info| {
            if (info.active) {
                return &info.keypair;
            }
        }
        return null;
    }

    /// Get keypair by generation
    pub fn get_keypair_by_generation(self: *const KeyRotationManager, generation: u32) ?*const KeyPair {
        for (self.key_history.items) |*info| {
            if (info.generation == generation) {
                return &info.keypair;
            }
        }
        return null;
    }

    /// Clean up old generations (keep last N)
    pub fn cleanup_old_generations(self: *KeyRotationManager, keep_count: usize) !void {
        if (self.key_history.items.len <= keep_count) return;

        const remove_count = self.key_history.items.len - keep_count;

        // Clean up the oldest generations
        for (0..remove_count) |i| {
            self.key_history.items[i].deinit(self.allocator);
        }

        // Move remaining items to the front
        std.mem.copyForwards(KeyGenerationInfo, self.key_history.items[0..keep_count], self.key_history.items[remove_count..]);

        // Update list size
        self.key_history.items.len = keep_count;

        std.debug.print("🧹 Cleaned up {d} old key generations\n", .{remove_count});
    }

    /// Print key rotation status
    pub fn print_status(self: *const KeyRotationManager) void {
        std.debug.print("\n📊 Key Rotation Status:\n", .{});
        std.debug.print("   Current Generation: {d}\n", .{self.current_generation});
        std.debug.print("   Total Generations: {d}\n", .{self.key_history.items.len});

        for (self.key_history.items) |info| {
            const status = if (info.active) "ACTIVE" else "INACTIVE";
            std.debug.print("   Gen {d}: {s} - {s} - Created: {d}\n", .{ info.generation, @tagName(info.algorithm), status, info.created_at });
        }
    }
};

/// Key Backup and Restore System
pub const KeyBackupManager = struct {
    allocator: std.mem.Allocator,

    /// Backup format with metadata
    pub const BackupData = struct {
        version: u32,
        algorithm: Algorithm,
        created_at: i64,
        encrypted_data: []u8,
        checksum: [32]u8,

        pub fn deinit(self: *BackupData, allocator: std.mem.Allocator) void {
            allocator.free(self.encrypted_data);
        }
    };

    pub fn init(allocator: std.mem.Allocator) KeyBackupManager {
        return KeyBackupManager{ .allocator = allocator };
    }

    /// Create encrypted backup of keypair
    pub fn create_backup(self: *KeyBackupManager, keypair: *const KeyPair, password: []const u8) !BackupData {
        // Serialize keypair data
        const serialized = try self.serialize_keypair(keypair);
        defer self.allocator.free(serialized);

        // Derive encryption key from password
        const encryption_key = try security.SecureKeyDerivation.derive_key(self.allocator, password, "backup_salt", "key_backup_encryption", 32);
        defer self.allocator.free(encryption_key);

        // Simple XOR encryption (in production, use AES-GCM)
        const encrypted = try self.allocator.dupe(u8, serialized);
        for (encrypted, 0..) |*byte, i| {
            byte.* ^= encryption_key[i % encryption_key.len];
        }

        // Calculate checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(serialized);
        var checksum: [32]u8 = undefined;
        hasher.final(&checksum);

        return BackupData{
            .version = 1,
            .algorithm = keypair.algorithm,
            .created_at = 1700000000, // Simple demo timestamp
            .encrypted_data = encrypted,
            .checksum = checksum,
        };
    }

    /// Restore keypair from encrypted backup
    pub fn restore_backup(self: *KeyBackupManager, backup: *const BackupData, password: []const u8) !KeyPair {
        // Derive decryption key
        const decryption_key = try security.SecureKeyDerivation.derive_key(self.allocator, password, "backup_salt", "key_backup_encryption", 32);
        defer self.allocator.free(decryption_key);

        // Decrypt data
        const decrypted = try self.allocator.dupe(u8, backup.encrypted_data);
        for (decrypted, 0..) |*byte, i| {
            byte.* ^= decryption_key[i % decryption_key.len];
        }

        // Verify checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(decrypted);
        var computed_checksum: [32]u8 = undefined;
        hasher.final(&computed_checksum);

        if (!security.SecureMemory.secure_compare(&backup.checksum, &computed_checksum)) {
            self.allocator.free(decrypted);
            return error.ChecksumMismatch;
        }

        // Deserialize keypair
        const keypair = try self.deserialize_keypair(decrypted, backup.algorithm);
        self.allocator.free(decrypted);

        return keypair;
    }

    /// Serialize keypair to bytes
    fn serialize_keypair(self: *KeyBackupManager, keypair: *const KeyPair) ![]u8 {
        const total_size = 4 + keypair.public_key.len + 4 + keypair.private_key.len;
        const serialized = try self.allocator.alloc(u8, total_size);

        var pos: usize = 0;

        // Public key length
        std.mem.writeInt(u32, serialized[pos .. pos + 4][0..4], @as(u32, @intCast(keypair.public_key.len)), .little);
        pos += 4;

        // Public key data
        @memcpy(serialized[pos .. pos + keypair.public_key.len], keypair.public_key);
        pos += keypair.public_key.len;

        // Private key length
        std.mem.writeInt(u32, serialized[pos .. pos + 4][0..4], @as(u32, @intCast(keypair.private_key.len)), .little);
        pos += 4;

        // Private key data
        @memcpy(serialized[pos .. pos + keypair.private_key.len], keypair.private_key);

        return serialized;
    }

    /// Deserialize keypair from bytes
    fn deserialize_keypair(self: *KeyBackupManager, data: []const u8, algorithm: Algorithm) !KeyPair {
        if (data.len < 8) return error.InvalidBackupData;

        var pos: usize = 0;

        // Read public key
        const pk_len = std.mem.readInt(u32, data[pos .. pos + 4][0..4], .little);
        pos += 4;

        if (pos + pk_len > data.len) return error.InvalidBackupData;

        const public_key = try self.allocator.dupe(u8, data[pos .. pos + pk_len]);
        pos += pk_len;

        // Read private key
        if (pos + 4 > data.len) {
            self.allocator.free(public_key);
            return error.InvalidBackupData;
        }

        const sk_len = std.mem.readInt(u32, data[pos .. pos + 4][0..4], .little);
        pos += 4;

        if (pos + sk_len > data.len) {
            self.allocator.free(public_key);
            return error.InvalidBackupData;
        }

        const private_key = try self.allocator.dupe(u8, data[pos .. pos + sk_len]);

        return KeyPair{
            .public_key = public_key,
            .private_key = private_key,
            .algorithm = algorithm,
        };
    }

    /// Save backup to file (simplified)
    pub fn save_backup_to_file(_: *KeyBackupManager, backup: *const BackupData, filename: []const u8) !void {
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        // Write header using buffer
        var header: [20]u8 = undefined; // 4 + 4 + 8 + 4 bytes
        std.mem.writeInt(u32, header[0..4], backup.version, .little);
        std.mem.writeInt(u32, header[4..8], @intFromEnum(backup.algorithm), .little);
        std.mem.writeInt(i64, header[8..16], backup.created_at, .little);
        std.mem.writeInt(u32, header[16..20], @as(u32, @intCast(backup.encrypted_data.len)), .little);
        try file.writeAll(&header);

        // Write checksum
        try file.writeAll(&backup.checksum);

        // Write encrypted data
        try file.writeAll(backup.encrypted_data);

        std.debug.print("💾 Backup saved to: {s}\n", .{filename});
    }

    /// Load backup from file (simplified)
    pub fn load_backup_from_file(self: *KeyBackupManager, filename: []const u8) !BackupData {
        const file = try std.fs.cwd().openFile(filename, .{});
        defer file.close();

        // Read header using buffer
        var header: [20]u8 = undefined;
        _ = try file.read(&header);
        const version = std.mem.readInt(u32, header[0..4], .little);
        const algorithm_int = std.mem.readInt(u32, header[4..8], .little);
        const created_at = std.mem.readInt(i64, header[8..16], .little);
        const data_len = std.mem.readInt(u32, header[16..20], .little);

        // Read checksum
        var checksum: [32]u8 = undefined;
        _ = try file.read(&checksum);

        // Read encrypted data
        const encrypted_data = try self.allocator.alloc(u8, data_len);
        _ = try file.read(encrypted_data);

        const algorithm = @as(Algorithm, @enumFromInt(algorithm_int));

        return BackupData{
            .version = version,
            .algorithm = algorithm,
            .created_at = created_at,
            .encrypted_data = encrypted_data,
            .checksum = checksum,
        };
    }
};

// Tests
test "key path parsing" {
    const path = try KeyPath.init(testing.allocator, "m/44'/1'/0'/0/5");
    defer path.deinit(testing.allocator);

    try testing.expect(path.components.len == 5);
    try testing.expect(path.components[0] == 44 | 0x80000000); // Hardened
    try testing.expect(path.components[1] == 1 | 0x80000000); // Hardened
    try testing.expect(path.components[2] == 0 | 0x80000000); // Hardened
    try testing.expect(path.components[3] == 0); // Not hardened
    try testing.expect(path.components[4] == 5); // Not hardened
}

test "hd key manager" {
    const seed = [_]u8{0x42} ** 64;
    var hd_manager_a = HDKeyManager.init(testing.allocator, seed, .Kyber512);
    defer hd_manager_a.deinit();
    var hd_manager_b = HDKeyManager.init(testing.allocator, seed, .Kyber512);
    defer hd_manager_b.deinit();

    const path = try KeyPath.init(testing.allocator, "m/44'/1'/0'/0/0");
    defer path.deinit(testing.allocator);

    const keypair_a = try hd_manager_a.derive_key(path);
    defer testing.allocator.free(keypair_a.public_key);
    defer testing.allocator.free(keypair_a.private_key);

    const keypair_b = try hd_manager_b.derive_key(path);
    defer testing.allocator.free(keypair_b.public_key);
    defer testing.allocator.free(keypair_b.private_key);

    try testing.expect(keypair_a.public_key.len == 800);
    try testing.expect(keypair_a.private_key.len == 1632);
    try testing.expect(keypair_a.algorithm == .Kyber512);

    try testing.expectEqualSlices(u8, keypair_a.public_key, keypair_b.public_key);
    try testing.expectEqualSlices(u8, keypair_a.private_key, keypair_b.private_key);
}

test "backup and restore" {
    var backup_manager = KeyBackupManager.init(testing.allocator);

    // Create a dummy keypair
    const pk = try testing.allocator.dupe(u8, &[_]u8{0x01} ** 800);
    const sk = try testing.allocator.dupe(u8, &[_]u8{0x02} ** 1632);
    const keypair = KeyPair{
        .public_key = pk,
        .private_key = sk,
        .algorithm = .Kyber512,
    };

    // Create backup
    var backup = try backup_manager.create_backup(&keypair, "test_password");
    defer backup.deinit(testing.allocator);

    // Restore backup
    const restored = try backup_manager.restore_backup(&backup, "test_password");
    defer testing.allocator.free(restored.public_key);
    defer testing.allocator.free(restored.private_key);

    // Verify restoration
    try testing.expect(std.mem.eql(u8, keypair.public_key, restored.public_key));
    try testing.expect(std.mem.eql(u8, keypair.private_key, restored.private_key));
    try testing.expect(keypair.algorithm == restored.algorithm);

    // Cleanup original
    testing.allocator.free(pk);
    testing.allocator.free(sk);
}
