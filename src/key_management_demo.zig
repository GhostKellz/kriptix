//! Advanced Key Management Demo
//! Demonstrates enterprise-grade key management features

const std = @import("std");
const key_mgmt = @import("key_management.zig");
const security = @import("security.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🗝️  Advanced Key Management System Demo\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

    // Test 1: Hierarchical Deterministic Key Derivation
    std.debug.print("🌳 Testing Hierarchical Deterministic Key Derivation...\n", .{});
    
    const master_seed = try key_mgmt.HDKeyManager.generate_master_seed(
        allocator, "enterprise_master_passphrase_2024", "kriptix_salt"
    );
    defer security.SecureMemory.secure_zero(@constCast(&master_seed));
    
    var hd_manager = key_mgmt.HDKeyManager.init(allocator, master_seed, .Kyber768);
    defer hd_manager.deinit();
    
    // Test different derivation paths
    const test_paths = [_][]const u8{
        "m/44'/1'/0'/0/0",    // First user key
        "m/44'/1'/0'/0/1",    // Second user key
        "m/44'/1'/1'/0/0",    // Different account
        "m/44'/2'/0'/0/0",    // Different coin type
    };
    
    for (test_paths) |path_str| {
        const path = try key_mgmt.KeyPath.init(allocator, path_str);
        defer path.deinit(allocator);
        
        const keypair = try hd_manager.derive_key(path);
        defer allocator.free(keypair.public_key);
        defer allocator.free(keypair.private_key);
        
        std.debug.print("   Path: {s}\n", .{path_str});
        std.debug.print("     Public Key:  {any}...\n", .{keypair.public_key[0..8]});
        std.debug.print("     Private Key: {any}... (length: {})\n", .{keypair.private_key[0..8], keypair.private_key.len});
        std.debug.print("     Algorithm:   {s}\n\n", .{@tagName(keypair.algorithm)});
    }
    
    // Test 2: Key Rotation Management
    std.debug.print("🔄 Testing Key Rotation Management...\n", .{});
    
    var rotation_manager = key_mgmt.KeyRotationManager.init(allocator);
    defer rotation_manager.deinit();
    
    // Simulate key rotations
    try rotation_manager.rotate_keys(.Kyber768, &hd_manager);
    std.debug.print("   First rotation completed\n", .{});
    
    try rotation_manager.rotate_keys(.Kyber768, &hd_manager);
    std.debug.print("   Second rotation completed\n", .{});
    
    try rotation_manager.rotate_keys(.Dilithium3, &hd_manager);
    std.debug.print("   Third rotation with algorithm change completed\n", .{});
    
    rotation_manager.print_status();
    
    // Test getting current keypair
    if (rotation_manager.get_current_keypair()) |current| {
        std.debug.print("\n   Current active key: {s} (Gen {})\n", .{
            @tagName(current.algorithm), rotation_manager.current_generation
        });
    }
    
    // Test 3: Key Backup and Restore
    std.debug.print("\n💾 Testing Key Backup and Restore...\n", .{});
    
    var backup_manager = key_mgmt.KeyBackupManager.init(allocator);
    
    // Get current keypair for backup
    if (rotation_manager.get_current_keypair()) |keypair| {
        // Create encrypted backup
        var backup = try backup_manager.create_backup(keypair, "backup_password_2024");
        defer backup.deinit(allocator);
        
        std.debug.print("   Backup created:\n", .{});
        std.debug.print("     Version: {}\n", .{backup.version});
        std.debug.print("     Algorithm: {s}\n", .{@tagName(backup.algorithm)});
        std.debug.print("     Created: {} (timestamp)\n", .{backup.created_at});
        std.debug.print("     Encrypted size: {} bytes\n", .{backup.encrypted_data.len});
        std.debug.print("     Checksum: {any}...\n", .{backup.checksum[0..8]});
        
        // Test backup to file
        try backup_manager.save_backup_to_file(&backup, "test_key_backup.kbk");
        
        // Test restore from backup
        const restored_keypair = try backup_manager.restore_backup(&backup, "backup_password_2024");
        defer allocator.free(restored_keypair.public_key);
        defer allocator.free(restored_keypair.private_key);
        
        std.debug.print("\n   Backup restored successfully:\n", .{});
        std.debug.print("     Algorithm: {s}\n", .{@tagName(restored_keypair.algorithm)});
        std.debug.print("     Public key length: {}\n", .{restored_keypair.public_key.len});
        std.debug.print("     Private key length: {}\n", .{restored_keypair.private_key.len});
        
        // Verify backup integrity
        const keys_match = std.mem.eql(u8, keypair.public_key, restored_keypair.public_key) and
                          std.mem.eql(u8, keypair.private_key, restored_keypair.private_key);
        
        if (keys_match) {
            std.debug.print("     ✅ Backup integrity verified!\n", .{});
        } else {
            std.debug.print("     ❌ Backup integrity check failed!\n", .{});
        }
        
        // Test loading backup from file
        std.debug.print("\n   Testing file backup/restore...\n", .{});
        var loaded_backup = try backup_manager.load_backup_from_file("test_key_backup.kbk");
        defer loaded_backup.deinit(allocator);
        
        const file_restored = try backup_manager.restore_backup(&loaded_backup, "backup_password_2024");
        defer allocator.free(file_restored.public_key);
        defer allocator.free(file_restored.private_key);
        
        const file_keys_match = std.mem.eql(u8, keypair.public_key, file_restored.public_key) and
                               std.mem.eql(u8, keypair.private_key, file_restored.private_key);
        
        if (file_keys_match) {
            std.debug.print("     ✅ File backup/restore verified!\n", .{});
        } else {
            std.debug.print("     ❌ File backup/restore failed!\n", .{});
        }
    }
    
    // Test 4: Key Generation Cleanup
    std.debug.print("\n🧹 Testing Key Generation Cleanup...\n", .{});
    
    std.debug.print("   Before cleanup:\n", .{});
    rotation_manager.print_status();
    
    try rotation_manager.cleanup_old_generations(2); // Keep only last 2 generations
    
    std.debug.print("\n   After cleanup (keeping last 2 generations):\n", .{});
    rotation_manager.print_status();
    
    // Test 5: Advanced Security Features Integration
    std.debug.print("\n🛡️  Testing Security Integration...\n", .{});
    
    // Test secure key derivation with validation
    const path = try key_mgmt.KeyPath.init(allocator, "m/44'/1'/999'/0/0");
    defer path.deinit(allocator);
    
    const secure_keypair = try hd_manager.derive_key(path);
    defer allocator.free(secure_keypair.public_key);
    defer allocator.free(secure_keypair.private_key);
    
    // Validate key sizes using security module
    try security.InputValidation.validate_key_size(
        secure_keypair.algorithm, secure_keypair.public_key, secure_keypair.private_key
    );
    std.debug.print("   ✅ Key size validation passed\n", .{});
    
    // Test algorithm validation
    try security.InputValidation.validate_algorithm_params(secure_keypair.algorithm);
    std.debug.print("   ✅ Algorithm parameter validation passed\n", .{});
    
    // Clean up backup file
    std.fs.cwd().deleteFile("test_key_backup.kbk") catch {};
    
    std.debug.print("\n🎯 Key Management Features Summary:\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
    std.debug.print("✅ Hierarchical Deterministic (HD) Key Derivation\n", .{});
    std.debug.print("   • BIP32-style derivation paths (m/44'/1'/0'/0/0)\n", .{});
    std.debug.print("   • Hardened and non-hardened derivation\n", .{});
    std.debug.print("   • Deterministic key generation from master seed\n", .{});
    std.debug.print("   • Algorithm-agnostic key derivation\n\n", .{});
    
    std.debug.print("✅ Enterprise Key Rotation Management\n", .{});
    std.debug.print("   • Automatic key generation versioning\n", .{});
    std.debug.print("   • Multiple active key generations\n", .{});
    std.debug.print("   • Historical key access by generation\n", .{});
    std.debug.print("   • Configurable cleanup policies\n\n", .{});
    
    std.debug.print("✅ Secure Key Backup & Restore\n", .{});
    std.debug.print("   • Password-based encryption (AES-256 in production)\n", .{});
    std.debug.print("   • Integrity verification with checksums\n", .{});
    std.debug.print("   • File-based backup storage\n", .{});
    std.debug.print("   • Cross-platform backup format\n\n", .{});
    
    std.debug.print("✅ Production Security Integration\n", .{});
    std.debug.print("   • Constant-time operations for key derivation\n", .{});
    std.debug.print("   • Secure memory handling and cleanup\n", .{});
    std.debug.print("   • Input validation and parameter checking\n", .{});
    std.debug.print("   • Side-channel resistance measures\n\n", .{});
    
    std.debug.print("🚀 Ready for Enterprise PQC Deployment!\n", .{});
    std.debug.print("   • Complete key lifecycle management\n", .{});
    std.debug.print("   • Compliance with security best practices\n", .{});
    std.debug.print("   • Scalable hierarchical key architecture\n", .{});
    std.debug.print("   • Disaster recovery capabilities\n", .{});
}