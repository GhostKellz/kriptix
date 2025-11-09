// examples/benchmark.zig
//! Performance benchmarking example for Kriptix algorithms

const std = @import("std");
const kriptix = @import("kriptix");

pub fn main() !void {
    kriptix.init();
    defer kriptix.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    std.debug.print("=== Kriptix Performance Benchmark ===\n\n", .{});

    // Benchmark Kyber
    try benchmarkKyber(allocator);

    // Benchmark Dilithium
    try benchmarkDilithium(allocator);

    // Benchmark SPHINCS+
    try benchmarkSphincs(allocator);
}

fn benchmarkKyber(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking Kyber KEM operations...\n", .{});

    const iterations = 10;

    // Key generation
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        keys[i] = try kriptix.generate_keypair(allocator, .Kyber512);
        const end = std.time.nanoTimestamp();
        keygen_times[i] = @intCast(end - start);
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    // Encapsulation
    var enc_times: [iterations]u64 = undefined;
    var ciphertexts: [iterations]kriptix.Ciphertext = undefined;
    const message = "Benchmark test message";

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        ciphertexts[i] = try kriptix.encrypt(allocator, keys[i].public_key, message, .Kyber512);
        const end = std.time.nanoTimestamp();
        enc_times[i] = @intCast(end - start);
    }

    const avg_enc = average(&enc_times);
    std.debug.print("  Encapsulation: {d:.2} μs\n", .{avg_enc / 1_000.0});

    // Decapsulation
    var dec_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        const decrypted = try kriptix.decrypt(allocator, keys[i].private_key, ciphertexts[i]);
        const end = std.time.nanoTimestamp();
        dec_times[i] = @intCast(end - start);
        allocator.free(decrypted);
    }

    const avg_dec = average(&dec_times);
    std.debug.print("  Decapsulation: {d:.2} μs\n", .{avg_dec / 1_000.0});

    // Cleanup
    for (keys) |key| {
        allocator.free(key.public_key);
        allocator.free(key.private_key);
    }
    for (ciphertexts) |ct| {
        allocator.free(ct.data);
    }
}

fn benchmarkDilithium(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking Dilithium signature operations...\n", .{});

    const iterations = 5; // Fewer iterations due to computational cost

    // Key generation
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        keys[i] = try kriptix.generate_keypair(allocator, .Dilithium2);
        const end = std.time.nanoTimestamp();
        keygen_times[i] = @intCast(end - start);
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    // Signing
    var sign_times: [iterations]u64 = undefined;
    var signatures: [iterations]kriptix.Signature = undefined;
    const message = "Benchmark test message for Dilithium signatures";

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        signatures[i] = try kriptix.sign(allocator, keys[i].private_key, message, .Dilithium2);
        const end = std.time.nanoTimestamp();
        sign_times[i] = @intCast(end - start);
    }

    const avg_sign = average(&sign_times);
    std.debug.print("  Signing: {d:.2} ms\n", .{avg_sign / 1_000_000.0});

    // Verification
    var verify_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        const is_valid = try kriptix.verify(keys[i].public_key, message, signatures[i]);
        const end = std.time.nanoTimestamp();
        verify_times[i] = @intCast(end - start);

        if (!is_valid) {
            std.debug.print("  Warning: Signature verification failed!\n", .{});
        }
    }

    const avg_verify = average(&verify_times);
    std.debug.print("  Verification: {d:.2} μs\n", .{avg_verify / 1_000.0});

    // Cleanup
    for (keys) |key| {
        allocator.free(key.public_key);
        allocator.free(key.private_key);
    }
    for (signatures) |sig| {
        allocator.free(sig.data);
    }
}

fn benchmarkSphincs(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking SPHINCS+ signature operations...\n", .{});

    const iterations = 3; // Very few due to high computational cost

    // Key generation
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        keys[i] = try kriptix.generate_keypair(allocator, .Sphincs128f);
        const end = std.time.nanoTimestamp();
        keygen_times[i] = @intCast(end - start);
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} μs\n", .{avg_keygen / 1_000.0});

    // Signing
    var sign_times: [iterations]u64 = undefined;
    var signatures: [iterations]kriptix.Signature = undefined;
    const message = "Benchmark test message for SPHINCS+ signatures";

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        signatures[i] = try kriptix.sign(allocator, keys[i].private_key, message, .Sphincs128f);
        const end = std.time.nanoTimestamp();
        sign_times[i] = @intCast(end - start);
    }

    const avg_sign = average(&sign_times);
    std.debug.print("  Signing: {d:.2} ms\n", .{avg_sign / 1_000_000.0});

    // Verification
    var verify_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        const start = std.time.nanoTimestamp();
        const is_valid = try kriptix.verify(keys[i].public_key, message, signatures[i]);
        const end = std.time.nanoTimestamp();
        verify_times[i] = @intCast(end - start);

        if (!is_valid) {
            std.debug.print("  Warning: Signature verification failed!\n", .{});
        }
    }

    const avg_verify = average(&verify_times);
    std.debug.print("  Verification: {d:.2} μs\n", .{avg_verify / 1_000.0});

    // Cleanup
    for (keys) |key| {
        allocator.free(key.public_key);
        allocator.free(key.private_key);
    }
    for (signatures) |sig| {
        allocator.free(sig.data);
    }
}

fn average(times: []const u64) f64 {
    var sum: u64 = 0;
    for (times) |t| {
        sum += t;
    }
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(times.len));
}
