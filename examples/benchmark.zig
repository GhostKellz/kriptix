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
    try benchmarkDeterministicKyber(allocator);

    // Benchmark Dilithium
    try benchmarkDilithium(allocator);
    try benchmarkDeterministicDilithium(allocator);

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
        var timer = try std.time.Timer.start();
        keys[i] = try kriptix.generate_keypair(allocator, .Kyber512);
        keygen_times[i] = timer.read();
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    // Encapsulation
    var enc_times: [iterations]u64 = undefined;
    var ciphertexts: [iterations]kriptix.Ciphertext = undefined;
    const message = "Benchmark test message";

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        ciphertexts[i] = try kriptix.encrypt(allocator, keys[i].public_key, message, .Kyber512);
        enc_times[i] = timer.read();
    }

    const avg_enc = average(&enc_times);
    std.debug.print("  Encapsulation: {d:.2} μs\n", .{avg_enc / 1_000.0});

    // Decapsulation
    var dec_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        const decrypted = try kriptix.decrypt(allocator, keys[i].private_key, ciphertexts[i]);
        dec_times[i] = timer.read();
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

fn benchmarkDeterministicKyber(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking deterministic Kyber key generation...\n", .{});

    const iterations = 10;
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        var seed_buf: [64]u8 = undefined;
        const seed = try std.fmt.bufPrint(&seed_buf, "kriptix::det-seed::kyber::{d}", .{i});

        var timer = try std.time.Timer.start();
        keys[i] = try kriptix.generate_keypair_deterministic(allocator, .Kyber512, seed);
        keygen_times[i] = timer.read();

        const control = try kriptix.generate_keypair_deterministic(allocator, .Kyber512, seed);

        if (!std.mem.eql(u8, keys[i].public_key, control.public_key) or
            !std.mem.eql(u8, keys[i].private_key, control.private_key))
        {
            std.debug.print("  Warning: Deterministic Kyber mismatch for seed index {d}\n", .{i});
        }

        allocator.free(control.public_key);
        allocator.free(control.private_key);
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Deterministic keygen: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    for (keys) |key| {
        allocator.free(key.public_key);
        allocator.free(key.private_key);
    }
}

fn benchmarkDilithium(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking Dilithium signature operations...\n", .{});

    const iterations = 5; // Fewer iterations due to computational cost

    // Key generation
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        keys[i] = try kriptix.generate_keypair(allocator, .Dilithium2);
        keygen_times[i] = timer.read();
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    // Signing
    var sign_times: [iterations]u64 = undefined;
    var signatures: [iterations]kriptix.Signature = undefined;
    const message = "Benchmark test message for Dilithium signatures";

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        signatures[i] = try kriptix.sign(allocator, keys[i].private_key, message, .Dilithium2);
        sign_times[i] = timer.read();
    }

    const avg_sign = average(&sign_times);
    std.debug.print("  Signing: {d:.2} ms\n", .{avg_sign / 1_000_000.0});

    // Verification
    var verify_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        const is_valid = try kriptix.verify(keys[i].public_key, message, signatures[i]);
        verify_times[i] = timer.read();

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

fn benchmarkDeterministicDilithium(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking deterministic Dilithium key generation...\n", .{});

    const iterations = 5;
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        var seed_buf: [64]u8 = undefined;
        const seed = try std.fmt.bufPrint(&seed_buf, "kriptix::det-seed::dilithium::{d}", .{i});

        var timer = try std.time.Timer.start();
        keys[i] = try kriptix.generate_keypair_deterministic(allocator, .Dilithium2, seed);
        keygen_times[i] = timer.read();

        const control = try kriptix.generate_keypair_deterministic(allocator, .Dilithium2, seed);

        if (!std.mem.eql(u8, keys[i].public_key, control.public_key) or
            !std.mem.eql(u8, keys[i].private_key, control.private_key))
        {
            std.debug.print("  Warning: Deterministic Dilithium mismatch for seed index {d}\n", .{i});
        }

        allocator.free(control.public_key);
        allocator.free(control.private_key);
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Deterministic keygen: {d:.2} ms\n", .{avg_keygen / 1_000_000.0});

    for (keys) |key| {
        allocator.free(key.public_key);
        allocator.free(key.private_key);
    }
}

fn benchmarkSphincs(allocator: std.mem.Allocator) !void {
    std.debug.print("Benchmarking SPHINCS+ signature operations...\n", .{});

    const iterations = 3; // Very few due to high computational cost

    // Key generation
    var keygen_times: [iterations]u64 = undefined;
    var keys: [iterations]kriptix.KeyPair = undefined;

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        keys[i] = try kriptix.generate_keypair(allocator, .Sphincs128f);
        keygen_times[i] = timer.read();
    }

    const avg_keygen = average(&keygen_times);
    std.debug.print("  Key generation: {d:.2} μs\n", .{avg_keygen / 1_000.0});

    // Signing
    var sign_times: [iterations]u64 = undefined;
    var signatures: [iterations]kriptix.Signature = undefined;
    const message = "Benchmark test message for SPHINCS+ signatures";

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        signatures[i] = try kriptix.sign(allocator, keys[i].private_key, message, .Sphincs128f);
        sign_times[i] = timer.read();
    }

    const avg_sign = average(&sign_times);
    std.debug.print("  Signing: {d:.2} ms\n", .{avg_sign / 1_000_000.0});

    // Verification
    var verify_times: [iterations]u64 = undefined;

    for (0..iterations) |i| {
        var timer = try std.time.Timer.start();
        const is_valid = try kriptix.verify(keys[i].public_key, message, signatures[i]);
        verify_times[i] = timer.read();

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
