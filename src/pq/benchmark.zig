//! Performance Benchmarking Suite for Post-Quantum Cryptography
//! Comprehensive benchmarks for all PQC algorithms and parameter sets
//! Measures key generation, signing/encryption, verification/decryption, and memory usage

const std = @import("std");
const time = std.time;
const testing = std.testing;

const kyber = @import("kyber.zig");
const dilithium = @import("dilithium.zig");
const sphincs = @import("sphincs.zig");
const hybrid = @import("hybrid.zig");
const Algorithm = @import("../root.zig").Algorithm;

/// Benchmark results for a specific operation
pub const BenchmarkResult = struct {
    algorithm: Algorithm,
    operation: []const u8,
    iterations: u32,
    total_time_ns: u64,
    avg_time_ns: u64,
    min_time_ns: u64,
    max_time_ns: u64,
    memory_used: usize,

    /// Calculate operations per second
    pub fn ops_per_second(self: BenchmarkResult) f64 {
        if (self.avg_time_ns == 0) return 0.0;
        return 1_000_000_000.0 / @as(f64, @floatFromInt(self.avg_time_ns));
    }

    /// Format result for display
    pub fn format(self: BenchmarkResult, writer: anytype) !void {
        try writer.print("{s} - {s}:\n", .{ @tagName(self.algorithm), self.operation });
        try writer.print("  Iterations: {d}\n", .{self.iterations});
        try writer.print("  Average: {d} ns ({d:.2} ops/sec)\n", .{ self.avg_time_ns, self.ops_per_second() });
        try writer.print("  Min: {d} ns, Max: {d} ns\n", .{ self.min_time_ns, self.max_time_ns });
        try writer.print("  Memory: {d} bytes\n", .{self.memory_used});
        try writer.print("\n");
    }
};

/// Comprehensive benchmark suite
pub const BenchmarkSuite = struct {
    allocator: std.mem.Allocator,
    results: std.ArrayList(BenchmarkResult),

    pub fn init(allocator: std.mem.Allocator) BenchmarkSuite {
        return BenchmarkSuite{
            .allocator = allocator,
            .results = std.ArrayList(BenchmarkResult).init(allocator),
        };
    }

    pub fn deinit(self: *BenchmarkSuite) void {
        self.results.deinit();
    }

    /// Run all benchmarks
    pub fn run_all(self: *BenchmarkSuite) !void {
        try self.benchmark_kyber();
        try self.benchmark_dilithium();
        try self.benchmark_sphincs();
        try self.benchmark_hybrid();
    }

    /// Benchmark Kyber KEM algorithms
    pub fn benchmark_kyber(self: *BenchmarkSuite) !void {
        const kyber_algos = [_]Algorithm{ .Kyber512, .Kyber768, .Kyber1024 };

        for (kyber_algos) |algo| {
            // Benchmark key generation
            try self.benchmark_kyber_keygen(algo, 100);

            // Benchmark encapsulation/decapsulation
            try self.benchmark_kyber_kem(algo, 1000);
        }
    }

    fn benchmark_kyber_keygen(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        var times = std.ArrayList(u64).init(self.allocator);
        defer times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            const start = time.nanoTimestamp();

            const keypair = kyber.generate_keypair(self.allocator, algo) catch continue;
            total_memory += keypair.public_key.len + keypair.private_key.len;
            keypair.deinit(self.allocator);

            const end = time.nanoTimestamp();
            try times.append(@intCast(end - start));
        }

        const result = self.calculate_stats(algo, "Kyber KeyGen", times.items, total_memory / iterations);
        try self.results.append(result);
    }

    fn benchmark_kyber_kem(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        // Generate keypair once
        const keypair = kyber.generate_keypair(self.allocator, algo) catch return;
        defer keypair.deinit(self.allocator);

        var encap_times = std.ArrayList(u64).init(self.allocator);
        var decap_times = std.ArrayList(u64).init(self.allocator);
        defer encap_times.deinit();
        defer decap_times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            // Benchmark encapsulation
            const encap_start = time.nanoTimestamp();
            const kem_result = kyber.encapsulate(self.allocator, keypair.public_key, algo) catch continue;
            const encap_end = time.nanoTimestamp();

            total_memory += kem_result.ciphertext.len + kem_result.shared_secret.len;

            // Benchmark decapsulation
            const decap_start = time.nanoTimestamp();
            const shared_secret = kyber.decapsulate(self.allocator, keypair.private_key, kem_result.ciphertext, algo) catch {
                self.allocator.free(kem_result.ciphertext);
                self.allocator.free(kem_result.shared_secret);
                continue;
            };
            const decap_end = time.nanoTimestamp();

            // Cleanup
            self.allocator.free(kem_result.ciphertext);
            self.allocator.free(kem_result.shared_secret);
            self.allocator.free(shared_secret);

            try encap_times.append(@intCast(encap_end - encap_start));
            try decap_times.append(@intCast(decap_end - decap_start));
        }

        const encap_result = self.calculate_stats(algo, "Kyber Encaps", encap_times.items, total_memory / (2 * iterations));
        const decap_result = self.calculate_stats(algo, "Kyber Decaps", decap_times.items, 0);

        try self.results.append(encap_result);
        try self.results.append(decap_result);
    }

    /// Benchmark Dilithium signatures
    pub fn benchmark_dilithium(self: *BenchmarkSuite) !void {
        const dilithium_algos = [_]Algorithm{ .Dilithium2, .Dilithium3, .Dilithium5 };

        for (dilithium_algos) |algo| {
            try self.benchmark_dilithium_keygen(algo, 100);
            try self.benchmark_dilithium_sign(algo, 1000);
        }
    }

    fn benchmark_dilithium_keygen(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        var times = std.ArrayList(u64).init(self.allocator);
        defer times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            const start = time.nanoTimestamp();

            const keypair = dilithium.generate_keypair(self.allocator, algo) catch continue;
            total_memory += keypair.public_key.len + keypair.private_key.len;
            keypair.deinit(self.allocator);

            const end = time.nanoTimestamp();
            try times.append(@intCast(end - start));
        }

        const result = self.calculate_stats(algo, "Dilithium KeyGen", times.items, total_memory / iterations);
        try self.results.append(result);
    }

    fn benchmark_dilithium_sign(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        const keypair = dilithium.generate_keypair(self.allocator, algo) catch return;
        defer keypair.deinit(self.allocator);

        const test_message = "Hello, Post-Quantum World! This is a test message for benchmarking.";

        var sign_times = std.ArrayList(u64).init(self.allocator);
        var verify_times = std.ArrayList(u64).init(self.allocator);
        defer sign_times.deinit();
        defer verify_times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            // Benchmark signing
            const sign_start = time.nanoTimestamp();
            const signature = dilithium.sign(self.allocator, keypair.private_key, test_message, algo) catch continue;
            const sign_end = time.nanoTimestamp();

            total_memory += signature.data.len;

            // Benchmark verification
            const verify_start = time.nanoTimestamp();
            const valid = dilithium.verify(keypair.public_key, test_message, signature.data) catch false;
            const verify_end = time.nanoTimestamp();

            if (!valid) {
                signature.deinit(self.allocator);
                continue;
            }

            signature.deinit(self.allocator);

            try sign_times.append(@intCast(sign_end - sign_start));
            try verify_times.append(@intCast(verify_end - verify_start));
        }

        const sign_result = self.calculate_stats(algo, "Dilithium Sign", sign_times.items, total_memory / iterations);
        const verify_result = self.calculate_stats(algo, "Dilithium Verify", verify_times.items, 0);

        try self.results.append(sign_result);
        try self.results.append(verify_result);
    }

    /// Benchmark SPHINCS+ signatures
    pub fn benchmark_sphincs(self: *BenchmarkSuite) !void {
        const sphincs_algos = [_]Algorithm{ .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s };

        for (sphincs_algos) |algo| {
            try self.benchmark_sphincs_keygen(algo, 10); // Fewer iterations due to computational cost
            try self.benchmark_sphincs_sign(algo, 100);
        }
    }

    fn benchmark_sphincs_keygen(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        var times = std.ArrayList(u64).init(self.allocator);
        defer times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            const start = time.nanoTimestamp();

            const keypair = sphincs.generate_keypair(self.allocator, algo) catch continue;
            total_memory += keypair.public_key.len + keypair.private_key.len;
            keypair.deinit(self.allocator);

            const end = time.nanoTimestamp();
            try times.append(@intCast(end - start));
        }

        const result = self.calculate_stats(algo, "SPHINCS+ KeyGen", times.items, total_memory / iterations);
        try self.results.append(result);
    }

    fn benchmark_sphincs_sign(self: *BenchmarkSuite, algo: Algorithm, iterations: u32) !void {
        const keypair = sphincs.generate_keypair(self.allocator, algo) catch return;
        defer keypair.deinit(self.allocator);

        const test_message = "SPHINCS+ benchmark message";

        var sign_times = std.ArrayList(u64).init(self.allocator);
        var verify_times = std.ArrayList(u64).init(self.allocator);
        defer sign_times.deinit();
        defer verify_times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            const sign_start = time.nanoTimestamp();
            const signature = sphincs.sign(self.allocator, keypair.private_key, test_message, algo) catch continue;
            const sign_end = time.nanoTimestamp();

            total_memory += signature.data.len;

            const verify_start = time.nanoTimestamp();
            const valid = sphincs.verify(keypair.public_key, test_message, signature.data) catch false;
            const verify_end = time.nanoTimestamp();

            if (!valid) {
                signature.deinit(self.allocator);
                continue;
            }

            signature.deinit(self.allocator);

            try sign_times.append(@intCast(sign_end - sign_start));
            try verify_times.append(@intCast(verify_end - verify_start));
        }

        const sign_result = self.calculate_stats(algo, "SPHINCS+ Sign", sign_times.items, total_memory / iterations);
        const verify_result = self.calculate_stats(algo, "SPHINCS+ Verify", verify_times.items, 0);

        try self.results.append(sign_result);
        try self.results.append(verify_result);
    }

    /// Benchmark hybrid schemes
    pub fn benchmark_hybrid(self: *BenchmarkSuite) !void {
        try self.benchmark_hybrid_kem();
        try self.benchmark_hybrid_signatures();
    }

    fn benchmark_hybrid_kem(self: *BenchmarkSuite) !void {
        const iterations = 100;

        var keygen_times = std.ArrayList(u64).init(self.allocator);
        var encap_times = std.ArrayList(u64).init(self.allocator);
        var decap_times = std.ArrayList(u64).init(self.allocator);
        defer keygen_times.deinit();
        defer encap_times.deinit();
        defer decap_times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            // Benchmark key generation
            const keygen_start = time.nanoTimestamp();
            var hybrid_kem = hybrid.HybridKEM.generate(self.allocator, .Kyber768) catch continue;
            const keygen_end = time.nanoTimestamp();

            total_memory += hybrid_kem.kyber_keypair.public_key.len + hybrid_kem.kyber_keypair.private_key.len;
            total_memory += hybrid_kem.ecdh_keypair.public_key.len + hybrid_kem.ecdh_keypair.private_key.len;

            // Benchmark encapsulation
            const encap_start = time.nanoTimestamp();
            const kem_result = hybrid_kem.encapsulate(self.allocator) catch {
                hybrid_kem.deinit(self.allocator);
                continue;
            };
            const encap_end = time.nanoTimestamp();

            // Benchmark decapsulation
            const decap_start = time.nanoTimestamp();
            const shared_secret = hybrid_kem.decapsulate(self.allocator, kem_result.ciphertext) catch {
                self.allocator.free(kem_result.ciphertext);
                self.allocator.free(kem_result.shared_secret);
                hybrid_kem.deinit(self.allocator);
                continue;
            };
            const decap_end = time.nanoTimestamp();

            // Cleanup
            self.allocator.free(kem_result.ciphertext);
            self.allocator.free(kem_result.shared_secret);
            self.allocator.free(shared_secret);
            hybrid_kem.deinit(self.allocator);

            try keygen_times.append(@intCast(keygen_end - keygen_start));
            try encap_times.append(@intCast(encap_end - encap_start));
            try decap_times.append(@intCast(decap_end - decap_start));
        }

        const keygen_result = self.calculate_stats(.Kyber768, "Hybrid KEM KeyGen", keygen_times.items, total_memory / iterations);
        const encap_result = self.calculate_stats(.Kyber768, "Hybrid KEM Encaps", encap_times.items, 0);
        const decap_result = self.calculate_stats(.Kyber768, "Hybrid KEM Decaps", decap_times.items, 0);

        try self.results.append(keygen_result);
        try self.results.append(encap_result);
        try self.results.append(decap_result);
    }

    fn benchmark_hybrid_signatures(self: *BenchmarkSuite) !void {
        const iterations = 100;
        const test_message = "Hybrid signature benchmark";

        var keygen_times = std.ArrayList(u64).init(self.allocator);
        var sign_times = std.ArrayList(u64).init(self.allocator);
        var verify_times = std.ArrayList(u64).init(self.allocator);
        defer keygen_times.deinit();
        defer sign_times.deinit();
        defer verify_times.deinit();

        var total_memory: usize = 0;

        for (0..iterations) |_| {
            // Benchmark key generation
            const keygen_start = time.nanoTimestamp();
            var hybrid_sig = hybrid.HybridSignature.generate(self.allocator, .Dilithium3) catch continue;
            const keygen_end = time.nanoTimestamp();

            total_memory += hybrid_sig.dilithium_keypair.public_key.len + hybrid_sig.dilithium_keypair.private_key.len;
            total_memory += hybrid_sig.ecdsa_keypair.public_key.len + hybrid_sig.ecdsa_keypair.private_key.len;

            // Benchmark signing
            const sign_start = time.nanoTimestamp();
            var signature = hybrid_sig.sign(self.allocator, test_message) catch {
                hybrid_sig.deinit(self.allocator);
                continue;
            };
            const sign_end = time.nanoTimestamp();

            // Benchmark verification
            const verify_start = time.nanoTimestamp();
            const valid = hybrid_sig.verify(test_message, signature) catch false;
            const verify_end = time.nanoTimestamp();

            if (!valid) {
                signature.deinit(self.allocator);
                hybrid_sig.deinit(self.allocator);
                continue;
            }

            signature.deinit(self.allocator);
            hybrid_sig.deinit(self.allocator);

            try keygen_times.append(@intCast(keygen_end - keygen_start));
            try sign_times.append(@intCast(sign_end - sign_start));
            try verify_times.append(@intCast(verify_end - verify_start));
        }

        const keygen_result = self.calculate_stats(.Dilithium3, "Hybrid Sig KeyGen", keygen_times.items, total_memory / iterations);
        const sign_result = self.calculate_stats(.Dilithium3, "Hybrid Sig Sign", sign_times.items, 0);
        const verify_result = self.calculate_stats(.Dilithium3, "Hybrid Sig Verify", verify_times.items, 0);

        try self.results.append(keygen_result);
        try self.results.append(sign_result);
        try self.results.append(verify_result);
    }

    /// Calculate statistics from timing data
    fn calculate_stats(self: *BenchmarkSuite, algo: Algorithm, operation: []const u8, times: []const u64, memory: usize) BenchmarkResult {
        _ = self;

        if (times.len == 0) {
            return BenchmarkResult{
                .algorithm = algo,
                .operation = operation,
                .iterations = 0,
                .total_time_ns = 0,
                .avg_time_ns = 0,
                .min_time_ns = 0,
                .max_time_ns = 0,
                .memory_used = memory,
            };
        }

        var total: u64 = 0;
        var min_time: u64 = times[0];
        var max_time: u64 = times[0];

        for (times) |t| {
            total += t;
            if (t < min_time) min_time = t;
            if (t > max_time) max_time = t;
        }

        return BenchmarkResult{
            .algorithm = algo,
            .operation = operation,
            .iterations = @intCast(times.len),
            .total_time_ns = total,
            .avg_time_ns = total / @as(u64, @intCast(times.len)),
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .memory_used = memory,
        };
    }

    /// Print all benchmark results
    pub fn print_results(self: *BenchmarkSuite, writer: anytype) !void {
        try writer.print("=== Post-Quantum Cryptography Benchmark Results ===\n\n");

        for (self.results.items) |result| {
            try result.format(writer);
        }

        try writer.print("=== Summary ===\n");
        try self.print_summary(writer);
    }

    /// Print summary statistics
    fn print_summary(self: *BenchmarkSuite, writer: anytype) !void {
        // Group results by algorithm
        var kyber_results = std.ArrayList(BenchmarkResult).init(self.allocator);
        var dilithium_results = std.ArrayList(BenchmarkResult).init(self.allocator);
        var sphincs_results = std.ArrayList(BenchmarkResult).init(self.allocator);
        var hybrid_results = std.ArrayList(BenchmarkResult).init(self.allocator);

        defer kyber_results.deinit();
        defer dilithium_results.deinit();
        defer sphincs_results.deinit();
        defer hybrid_results.deinit();

        for (self.results.items) |result| {
            switch (result.algorithm) {
                .Kyber512, .Kyber768, .Kyber1024 => try kyber_results.append(result),
                .Dilithium2, .Dilithium3, .Dilithium5 => try dilithium_results.append(result),
                .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => try sphincs_results.append(result),
                else => try hybrid_results.append(result),
            }
        }

        try writer.print("Kyber KEM Performance:\n");
        try self.print_group_average(writer, kyber_results.items);

        try writer.print("\nDilithium Signature Performance:\n");
        try self.print_group_average(writer, dilithium_results.items);

        try writer.print("\nSPHINCS+ Signature Performance:\n");
        try self.print_group_average(writer, sphincs_results.items);

        if (hybrid_results.items.len > 0) {
            try writer.print("\nHybrid Scheme Performance:\n");
            try self.print_group_average(writer, hybrid_results.items);
        }
    }

    fn print_group_average(self: *BenchmarkSuite, writer: anytype, results: []const BenchmarkResult) !void {
        _ = self;

        if (results.len == 0) return;

        var total_ops_per_sec: f64 = 0;
        var count: u32 = 0;

        for (results) |result| {
            if (result.avg_time_ns > 0) {
                total_ops_per_sec += result.ops_per_second();
                count += 1;
            }
        }

        if (count > 0) {
            const avg_ops_per_sec = total_ops_per_sec / @as(f64, @floatFromInt(count));
            try writer.print("  Average performance: {d:.2} operations/second\n", .{avg_ops_per_sec});
        }
    }

    /// Export results to JSON
    pub fn export_json(self: *BenchmarkSuite, writer: anytype) !void {
        try writer.print("{\n");
        try writer.print("  \"benchmark_results\": [\n");

        for (self.results.items, 0..) |result, i| {
            try writer.print("    {\n");
            try writer.print("      \"algorithm\": \"{s}\",\n", .{@tagName(result.algorithm)});
            try writer.print("      \"operation\": \"{s}\",\n", .{result.operation});
            try writer.print("      \"iterations\": {d},\n", .{result.iterations});
            try writer.print("      \"avg_time_ns\": {d},\n", .{result.avg_time_ns});
            try writer.print("      \"min_time_ns\": {d},\n", .{result.min_time_ns});
            try writer.print("      \"max_time_ns\": {d},\n", .{result.max_time_ns});
            try writer.print("      \"ops_per_second\": {d:.2},\n", .{result.ops_per_second()});
            try writer.print("      \"memory_used\": {d}\n", .{result.memory_used});
            try writer.print("    }");

            if (i < self.results.items.len - 1) {
                try writer.print(",");
            }
            try writer.print("\n");
        }

        try writer.print("  ]\n");
        try writer.print("}\n");
    }
};

/// Quick benchmark function
pub fn run_quick_benchmark(allocator: std.mem.Allocator) !void {
    var suite = BenchmarkSuite.init(allocator);
    defer suite.deinit();

    std.debug.print("Running Post-Quantum Cryptography Benchmarks...\n");

    try suite.run_all();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();
    try suite.print_results(writer);

    std.debug.print("{s}", .{buffer.items});
}

/// Benchmark specific algorithm
pub fn benchmark_algorithm(allocator: std.mem.Allocator, algo: Algorithm, iterations: u32) !BenchmarkResult {
    var suite = BenchmarkSuite.init(allocator);
    defer suite.deinit();

    switch (algo) {
        .Kyber512, .Kyber768, .Kyber1024 => {
            try suite.benchmark_kyber_keygen(algo, iterations);
        },
        .Dilithium2, .Dilithium3, .Dilithium5 => {
            try suite.benchmark_dilithium_keygen(algo, iterations);
        },
        .Sphincs128f, .Sphincs128s, .Sphincs192f, .Sphincs192s, .Sphincs256f, .Sphincs256s => {
            try suite.benchmark_sphincs_keygen(algo, iterations);
        },
        else => return error.UnsupportedAlgorithm,
    }

    if (suite.results.items.len > 0) {
        return suite.results.items[0];
    } else {
        return error.BenchmarkFailed;
    }
}

// Tests
test "benchmark suite initialization" {
    var suite = BenchmarkSuite.init(testing.allocator);
    defer suite.deinit();

    try testing.expect(suite.results.items.len == 0);
}

test "benchmark result calculations" {
    const times = [_]u64{ 1000, 2000, 3000, 4000, 5000 };

    var suite = BenchmarkSuite.init(testing.allocator);
    defer suite.deinit();

    const result = suite.calculate_stats(.Kyber512, "Test", &times, 1024);

    try testing.expect(result.avg_time_ns == 3000);
    try testing.expect(result.min_time_ns == 1000);
    try testing.expect(result.max_time_ns == 5000);
    try testing.expect(result.memory_used == 1024);
    try testing.expect(result.ops_per_second() > 0);
}
