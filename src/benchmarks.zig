//! Comprehensive Performance Benchmarking Suite
//! Provides detailed performance analysis for all PQC algorithms
//! Includes microbenchmarks, memory analysis, and comparative benchmarks

const std = @import("std");
const print = std.debug.print;
const Timer = std.time.Timer;
const ArrayList = std.ArrayList;

const root = @import("root.zig");
const kyber = @import("pq/kyber.zig");
const dilithium = @import("pq/dilithium.zig");
const sphincs = @import("pq/sphincs.zig");
const hybrid = @import("pq/hybrid.zig");
const Algorithm = root.Algorithm;

/// Performance metrics for a single operation
pub const PerformanceMetric = struct {
    algorithm: Algorithm,
    operation: []const u8,
    iterations: u32,
    total_time_ns: u64,
    min_time_ns: u64,
    max_time_ns: u64,
    avg_time_ns: u64,
    throughput_ops_per_sec: f64,
    memory_bytes: usize,

    pub fn format(self: PerformanceMetric, writer: anytype) !void {
        try writer.print("📊 {s} - {s}\n", .{ @tagName(self.algorithm), self.operation });
        try writer.print("   Iterations: {d}\n", .{self.iterations});
        try writer.print("   Average:    {d:.2} ms\n", .{@as(f64, @floatFromInt(self.avg_time_ns)) / 1_000_000.0});
        try writer.print("   Min:        {d:.2} ms\n", .{@as(f64, @floatFromInt(self.min_time_ns)) / 1_000_000.0});
        try writer.print("   Max:        {d:.2} ms\n", .{@as(f64, @floatFromInt(self.max_time_ns)) / 1_000_000.0});
        try writer.print("   Throughput: {d:.1} ops/sec\n", .{self.throughput_ops_per_sec});
        try writer.print("   Memory:     {d:.2} KB\n\n", .{@as(f64, @floatFromInt(self.memory_bytes)) / 1024.0});
    }
};

/// Comprehensive benchmark suite
pub const BenchmarkSuite = struct {
    allocator: std.mem.Allocator,
    results: ArrayList(PerformanceMetric),
    iterations: u32,

    pub fn init(allocator: std.mem.Allocator, iterations: u32) BenchmarkSuite {
        return BenchmarkSuite{
            .allocator = allocator,
            .results = ArrayList(PerformanceMetric){},
            .iterations = iterations,
        };
    }

    pub fn deinit(self: *BenchmarkSuite) void {
        self.results.deinit(self.allocator);
    }

    /// Run all benchmarks
    pub fn run_all_benchmarks(self: *BenchmarkSuite) !void {
        print("🚀 Starting Comprehensive PQC Performance Benchmarks\n", .{});
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

        // Benchmark Kyber (ML-KEM) algorithms
        try self.benchmark_kem_algorithms();

        // Benchmark Dilithium (ML-DSA) algorithms
        try self.benchmark_signature_algorithms();

        // Benchmark SPHINCS+ (SLH-DSA) algorithms
        try self.benchmark_stateless_signatures();

        // Benchmark Hybrid schemes
        try self.benchmark_hybrid_schemes();

        // Print comprehensive results
        try self.print_results();
        try self.print_comparative_analysis();
    }

    /// Benchmark KEM algorithms (Kyber)
    pub fn benchmark_kem_algorithms(self: *BenchmarkSuite) !void {
        const kem_algorithms = [_]Algorithm{ .Kyber512, .Kyber768, .Kyber1024 };

        for (kem_algorithms) |algo| {
            print("🔐 Benchmarking {s}...\n", .{@tagName(algo)});

            // Key Generation Benchmark
            try self.benchmark_kem_keygen(algo);

            // Encapsulation Benchmark
            try self.benchmark_kem_encrypt(algo);

            // Decapsulation Benchmark
            try self.benchmark_kem_decrypt(algo);
        }
    }

    /// Benchmark KEM key generation
    fn benchmark_kem_keygen(self: *BenchmarkSuite, algo: Algorithm) !void {
        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const keypair = kyber.generate_keypair(self.allocator, algo) catch |err| {
                print("❌ Key generation failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += keypair.public_key.len + keypair.private_key.len;

            // Cleanup
            self.allocator.free(keypair.public_key);
            self.allocator.free(keypair.private_key);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Key Generation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark KEM encapsulation
    fn benchmark_kem_encrypt(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate a keypair for testing
        const keypair = kyber.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for KEM encapsulation";

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const ciphertext = kyber.encrypt(self.allocator, keypair.public_key, test_message, algo) catch |err| {
                print("❌ Encryption failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += ciphertext.data.len;

            // Cleanup
            self.allocator.free(ciphertext.data);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Encapsulation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark KEM decapsulation
    fn benchmark_kem_decrypt(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair and ciphertext for testing
        const keypair = kyber.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for KEM decapsulation";
        const ciphertext = kyber.encrypt(self.allocator, keypair.public_key, test_message, algo) catch return;
        defer self.allocator.free(ciphertext.data);

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const decrypted = kyber.decrypt(self.allocator, keypair.private_key, ciphertext.data) catch |err| {
                print("❌ Decryption failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += decrypted.len;

            // Cleanup
            self.allocator.free(decrypted);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Decapsulation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark signature algorithms (Dilithium)
    pub fn benchmark_signature_algorithms(self: *BenchmarkSuite) !void {
        const sig_algorithms = [_]Algorithm{ .Dilithium2, .Dilithium3, .Dilithium5 };

        for (sig_algorithms) |algo| {
            print("✍️  Benchmarking {s}...\n", .{@tagName(algo)});

            // Key Generation Benchmark
            try self.benchmark_sig_keygen(algo);

            // Signing Benchmark
            try self.benchmark_signing(algo);

            // Verification Benchmark
            try self.benchmark_verification(algo);
        }
    }

    /// Benchmark signature key generation
    fn benchmark_sig_keygen(self: *BenchmarkSuite, algo: Algorithm) !void {
        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const keypair = dilithium.generate_keypair(self.allocator, algo) catch |err| {
                print("❌ Key generation failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += keypair.public_key.len + keypair.private_key.len;

            // Cleanup
            self.allocator.free(keypair.public_key);
            self.allocator.free(keypair.private_key);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Key Generation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark signing operation
    fn benchmark_signing(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair for testing
        const keypair = dilithium.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for digital signature signing";

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const signature = dilithium.sign(self.allocator, keypair.private_key, test_message, algo) catch |err| {
                print("❌ Signing failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += signature.data.len;

            // Cleanup
            self.allocator.free(signature.data);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Signing",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark signature verification
    fn benchmark_verification(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair and signature for testing
        const keypair = dilithium.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for digital signature verification";
        const signature = dilithium.sign(self.allocator, keypair.private_key, test_message, algo) catch return;
        defer self.allocator.free(signature.data);

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const is_valid = dilithium.verify(keypair.public_key, test_message, signature.data) catch |err| {
                print("❌ Verification failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Ensure verification succeeded
            if (!is_valid) {
                print("❌ Signature verification returned false for {s}\n", .{@tagName(algo)});
                return;
            }
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Verification",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = 0, // Verification doesn't allocate memory
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark stateless signature algorithms (SPHINCS+)
    pub fn benchmark_stateless_signatures(self: *BenchmarkSuite) !void {
        const sphincs_algorithms = [_]Algorithm{ .Sphincs128f, .Sphincs256s };

        for (sphincs_algorithms) |algo| {
            print("🌳 Benchmarking {s}...\n", .{@tagName(algo)});

            // SPHINCS+ is slower, so use fewer iterations
            const original_iterations = self.iterations;
            self.iterations = @max(1, self.iterations / 10);

            // Key Generation Benchmark
            try self.benchmark_sphincs_keygen(algo);

            // Signing Benchmark
            try self.benchmark_sphincs_signing(algo);

            // Verification Benchmark
            try self.benchmark_sphincs_verification(algo);

            // Restore original iteration count
            self.iterations = original_iterations;
        }
    }

    /// Benchmark SPHINCS+ key generation
    fn benchmark_sphincs_keygen(self: *BenchmarkSuite, algo: Algorithm) !void {
        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const keypair = sphincs.generate_keypair(self.allocator, algo) catch |err| {
                print("❌ SPHINCS+ key generation failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += keypair.public_key.len + keypair.private_key.len;

            // Cleanup
            self.allocator.free(keypair.public_key);
            self.allocator.free(keypair.private_key);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Key Generation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark SPHINCS+ signing
    fn benchmark_sphincs_signing(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair for testing
        const keypair = sphincs.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for SPHINCS+ stateless signatures";

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const signature = sphincs.sign(self.allocator, keypair.private_key, test_message, algo) catch |err| {
                print("❌ SPHINCS+ signing failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += signature.data.len;

            // Cleanup
            self.allocator.free(signature.data);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Signing",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark SPHINCS+ verification
    fn benchmark_sphincs_verification(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair and signature for testing
        const keypair = sphincs.generate_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for SPHINCS+ verification";
        const signature = sphincs.sign(self.allocator, keypair.private_key, test_message, algo) catch return;
        defer self.allocator.free(signature.data);

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const is_valid = sphincs.verify(keypair.public_key, test_message, signature.data) catch |err| {
                print("❌ SPHINCS+ verification failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Ensure verification succeeded
            if (!is_valid) {
                print("❌ SPHINCS+ signature verification returned false for {s}\n", .{@tagName(algo)});
                return;
            }
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Verification",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = 0, // Verification doesn't allocate memory
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark hybrid schemes
    pub fn benchmark_hybrid_schemes(self: *BenchmarkSuite) !void {
        const hybrid_algorithms = [_]Algorithm{ .Kyber512_AES256, .Kyber768_AES256, .Kyber1024_AES256 };

        for (hybrid_algorithms) |algo| {
            print("🔗 Benchmarking {s}...\n", .{@tagName(algo)});

            // Key Generation Benchmark
            try self.benchmark_hybrid_keygen(algo);

            // Encryption Benchmark
            try self.benchmark_hybrid_encrypt(algo);

            // Decryption Benchmark
            try self.benchmark_hybrid_decrypt(algo);
        }
    }

    /// Benchmark hybrid key generation
    fn benchmark_hybrid_keygen(self: *BenchmarkSuite, algo: Algorithm) !void {
        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const keypair = hybrid.generate_hybrid_kem_keypair(self.allocator, algo) catch |err| {
                print("❌ Hybrid key generation failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += keypair.public_key.len + keypair.private_key.len;

            // Cleanup
            self.allocator.free(keypair.public_key);
            self.allocator.free(keypair.private_key);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Key Generation",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark hybrid encryption
    fn benchmark_hybrid_encrypt(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair for testing
        const keypair = hybrid.generate_hybrid_kem_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for hybrid PQC+Classical encryption";

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const ciphertext = hybrid.encrypt_hybrid(self.allocator, keypair.public_key, test_message, algo) catch |err| {
                print("❌ Hybrid encryption failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += ciphertext.data.len;

            // Cleanup
            self.allocator.free(ciphertext.data);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Encryption",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Benchmark hybrid decryption
    fn benchmark_hybrid_decrypt(self: *BenchmarkSuite, algo: Algorithm) !void {
        // Pre-generate keypair and ciphertext for testing
        const keypair = hybrid.generate_hybrid_kem_keypair(self.allocator, algo) catch return;
        defer self.allocator.free(keypair.public_key);
        defer self.allocator.free(keypair.private_key);

        const test_message = "Performance benchmark test message for hybrid PQC+Classical decryption";
        const ciphertext = hybrid.encrypt_hybrid(self.allocator, keypair.public_key, test_message, algo) catch return;
        defer self.allocator.free(ciphertext.data);

        var timer = try Timer.start();
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;
        var total_time: u64 = 0;
        var total_memory: usize = 0;

        var i: u32 = 0;
        while (i < self.iterations) : (i += 1) {
            const start = timer.read();

            const decrypted = hybrid.decrypt_hybrid(self.allocator, keypair.private_key, ciphertext) catch |err| {
                print("❌ Hybrid decryption failed for {s}: {}\n", .{ @tagName(algo), err });
                return;
            };

            const end = timer.read();
            const elapsed = end - start;

            // Track timing
            total_time += elapsed;
            min_time = @min(min_time, elapsed);
            max_time = @max(max_time, elapsed);

            // Track memory usage
            total_memory += decrypted.len;

            // Cleanup
            self.allocator.free(decrypted);
        }

        const avg_time = total_time / self.iterations;
        const throughput = @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);

        const metric = PerformanceMetric{
            .algorithm = algo,
            .operation = "Decryption",
            .iterations = self.iterations,
            .total_time_ns = total_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .avg_time_ns = avg_time,
            .throughput_ops_per_sec = throughput,
            .memory_bytes = total_memory / self.iterations,
        };

        try self.results.append(self.allocator, metric);
    }

    /// Print detailed benchmark results
    pub fn print_results(self: *const BenchmarkSuite) !void {
        print("\n\n📈 DETAILED PERFORMANCE RESULTS\n", .{});
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

        for (self.results.items) |result| {
            const status = if (result.avg_time_ns > 0) "📊" else "❌";
            print("{s} {s} - {s}\n", .{ status, @tagName(result.algorithm), result.operation });
            print("   Iterations: {d}\n", .{result.iterations});
            print("   Average:    {d:.2} ms\n", .{@as(f64, @floatFromInt(result.avg_time_ns)) / 1_000_000.0});
            print("   Min:        {d:.2} ms\n", .{@as(f64, @floatFromInt(result.min_time_ns)) / 1_000_000.0});
            print("   Max:        {d:.2} ms\n", .{@as(f64, @floatFromInt(result.max_time_ns)) / 1_000_000.0});
            print("   Throughput: {d:.1} ops/sec\n", .{result.throughput_ops_per_sec});
            if (result.memory_bytes > 0) {
                print("   Memory:     {d:.2} KB\n", .{@as(f64, @floatFromInt(result.memory_bytes)) / 1024.0});
            }
            print("\n", .{});
        }
    }

    /// Print comparative analysis
    pub fn print_comparative_analysis(self: *const BenchmarkSuite) !void {
        print("\n🏆 COMPARATIVE ANALYSIS\n", .{});
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

        // Find fastest algorithms for each operation type
        var fastest_keygen: ?PerformanceMetric = null;
        var fastest_encrypt_sign: ?PerformanceMetric = null;
        var fastest_decrypt_verify: ?PerformanceMetric = null;

        for (self.results.items) |result| {
            if (std.mem.eql(u8, result.operation, "Key Generation")) {
                if (fastest_keygen == null or result.avg_time_ns < fastest_keygen.?.avg_time_ns) {
                    fastest_keygen = result;
                }
            } else if (std.mem.eql(u8, result.operation, "Encapsulation") or
                std.mem.eql(u8, result.operation, "Signing") or
                std.mem.eql(u8, result.operation, "Encryption"))
            {
                if (fastest_encrypt_sign == null or result.avg_time_ns < fastest_encrypt_sign.?.avg_time_ns) {
                    fastest_encrypt_sign = result;
                }
            } else if (std.mem.eql(u8, result.operation, "Decapsulation") or
                std.mem.eql(u8, result.operation, "Verification") or
                std.mem.eql(u8, result.operation, "Decryption"))
            {
                if (fastest_decrypt_verify == null or result.avg_time_ns < fastest_decrypt_verify.?.avg_time_ns) {
                    fastest_decrypt_verify = result;
                }
            }
        }

        if (fastest_keygen) |fastest| {
            print("🥇 Fastest Key Generation:\n", .{});
            print("   {s} - {d:.2} ms ({d:.1} ops/sec)\n\n", .{ @tagName(fastest.algorithm), @as(f64, @floatFromInt(fastest.avg_time_ns)) / 1_000_000.0, fastest.throughput_ops_per_sec });
        }

        if (fastest_encrypt_sign) |fastest| {
            print("🥇 Fastest Encrypt/Sign Operation:\n", .{});
            print("   {s} {s} - {d:.2} ms ({d:.1} ops/sec)\n\n", .{ @tagName(fastest.algorithm), fastest.operation, @as(f64, @floatFromInt(fastest.avg_time_ns)) / 1_000_000.0, fastest.throughput_ops_per_sec });
        }

        if (fastest_decrypt_verify) |fastest| {
            print("🥇 Fastest Decrypt/Verify Operation:\n", .{});
            print("   {s} {s} - {d:.2} ms ({d:.1} ops/sec)\n\n", .{ @tagName(fastest.algorithm), fastest.operation, @as(f64, @floatFromInt(fastest.avg_time_ns)) / 1_000_000.0, fastest.throughput_ops_per_sec });
        }

        // Performance recommendations
        print("💡 PERFORMANCE RECOMMENDATIONS\n", .{});
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
        print("• For HIGH-SPEED applications: Use Kyber512 for KEM, Dilithium2 for signatures\n", .{});
        print("• For BALANCED security/performance: Use Kyber768 + Dilithium3\n", .{});
        print("• For MAXIMUM security: Use Kyber1024 + Dilithium5 + SPHINCS+-256s\n", .{});
        print("• For HYBRID security: Use Kyber768_AES256 for transition period\n", .{});
        print("• SPHINCS+ is ideal for long-term signatures but slower for real-time use\n\n", .{});

        print("✅ Benchmarking Complete! Total tests: {d}\n", .{self.results.items.len});
    }
};

/// Run comprehensive benchmarks
pub fn run_benchmarks(allocator: std.mem.Allocator, iterations: u32) !void {
    var suite = BenchmarkSuite.init(allocator, iterations);
    defer suite.deinit();

    try suite.run_all_benchmarks();
}

// Example usage
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Run benchmarks with moderate iteration count
    try run_benchmarks(allocator, 10);
}
