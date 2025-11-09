// examples/basic_usage.zig
//! Basic usage example for Kriptix PQC library

const std = @import("std");
const kriptix = @import("kriptix");

pub fn main() !void {
    // Initialize the library
    kriptix.init();
    defer kriptix.deinit();

    // Create an arena allocator for this example
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    std.debug.print("=== Kriptix Basic Usage Example ===\n\n", .{});

    // Example 1: Kyber Key Encapsulation
    std.debug.print("1. Kyber KEM Example\n", .{});
    try kyberExample(allocator);

    std.debug.print("\n2. Dilithium Signature Example\n", .{});
    try dilithiumExample(allocator);

    std.debug.print("\n3. SPHINCS+ Signature Example\n", .{});
    try sphincsExample(allocator);

    std.debug.print("\n=== All examples completed successfully! ===\n", .{});
}

fn kyberExample(allocator: std.mem.Allocator) !void {
    // Generate Alice's keypair
    const alice_keys = try kriptix.generate_keypair(allocator, .Kyber512);
    defer allocator.free(alice_keys.public_key);
    defer allocator.free(alice_keys.private_key);

    std.debug.print("  Alice's public key: {d} bytes\n", .{alice_keys.public_key.len});
    std.debug.print("  Alice's private key: {d} bytes\n", .{alice_keys.private_key.len});

    // Bob encapsulates a shared secret for Alice
    const message = "Shared secret message";
    const ciphertext = try kriptix.encrypt(allocator, alice_keys.public_key, message, .Kyber512);
    defer allocator.free(ciphertext.data);

    std.debug.print("  Ciphertext: {d} bytes\n", .{ciphertext.data.len});

    // Alice decapsulates the shared secret
    const decrypted = try kriptix.decrypt(allocator, alice_keys.private_key, ciphertext);
    defer allocator.free(decrypted);

    std.debug.print("  Decrypted message: {s}\n", .{std.fmt.fmtSliceEscapeLower(decrypted)});

    // Verify the message is correct
    if (std.mem.eql(u8, decrypted, message)) {
        std.debug.print("  ✓ KEM operation successful!\n", .{});
    } else {
        std.debug.print("  ✗ KEM operation failed!\n", .{});
    }
}

fn dilithiumExample(allocator: std.mem.Allocator) !void {
    // Generate a keypair for signing
    const keys = try kriptix.generate_keypair(allocator, .Dilithium2);
    defer allocator.free(keys.public_key);
    defer allocator.free(keys.private_key);

    std.debug.print("  Public key: {d} bytes\n", .{keys.public_key.len});
    std.debug.print("  Private key: {d} bytes\n", .{keys.private_key.len});

    // Sign a message
    const message = "This message will be signed with Dilithium";
    const signature = try kriptix.sign(allocator, keys.private_key, message, .Dilithium2);
    defer allocator.free(signature.data);

    std.debug.print("  Signature: {d} bytes\n", .{signature.data.len});

    // Verify the signature
    const is_valid = try kriptix.verify(keys.public_key, message, signature);
    if (is_valid) {
        std.debug.print("  ✓ Signature verification successful!\n", .{});
    } else {
        std.debug.print("  ✗ Signature verification failed!\n", .{});
    }

    // Try verifying with wrong message
    const wrong_message = "This is a different message";
    const is_valid_wrong = try kriptix.verify(keys.public_key, wrong_message, signature);
    if (!is_valid_wrong) {
        std.debug.print("  ✓ Wrong message correctly rejected!\n", .{});
    } else {
        std.debug.print("  ✗ Wrong message incorrectly accepted!\n", .{});
    }
}

fn sphincsExample(allocator: std.mem.Allocator) !void {
    // Generate a keypair for signing
    const keys = try kriptix.generate_keypair(allocator, .Sphincs128f);
    defer allocator.free(keys.public_key);
    defer allocator.free(keys.private_key);

    std.debug.print("  Public key: {d} bytes\n", .{keys.public_key.len});
    std.debug.print("  Private key: {d} bytes\n", .{keys.private_key.len});

    // Sign a message
    const message = "This message will be signed with SPHINCS+";
    const signature = try kriptix.sign(allocator, keys.private_key, message, .Sphincs128f);
    defer allocator.free(signature.data);

    std.debug.print("  Signature: {d} bytes\n", .{signature.data.len});

    // Verify the signature
    const is_valid = try kriptix.verify(keys.public_key, message, signature);
    if (is_valid) {
        std.debug.print("  ✓ Signature verification successful!\n", .{});
    } else {
        std.debug.print("  ✗ Signature verification failed!\n", .{});
    }
}
