const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // === FEATURE FLAGS FOR MODULAR COMPILATION ===
    const features = .{
        // Post-Quantum Key Encapsulation Mechanisms
        .ml_kem = b.option(bool, "ml-kem", "Enable ML-KEM (FIPS 203)") orelse false,
        .kyber = b.option(bool, "kyber", "Enable Kyber (legacy)") orelse false,

        // Post-Quantum Digital Signatures
        .ml_dsa = b.option(bool, "ml-dsa", "Enable ML-DSA (FIPS 204)") orelse false,
        .dilithium = b.option(bool, "dilithium", "Enable Dilithium (legacy)") orelse false,
        .slh_dsa = b.option(bool, "slh-dsa", "Enable SLH-DSA (FIPS 205)") orelse false,
        .sphincs = b.option(bool, "sphincs", "Enable SPHINCS+ (legacy)") orelse false,

        // Hybrid Schemes
        .hybrid = b.option(bool, "hybrid", "Enable hybrid PQC+Classical schemes") orelse false,

        // Additional Features
        .blockchain = b.option(bool, "blockchain", "Enable blockchain-specific features") orelse false,
        .interop = b.option(bool, "interop", "Enable interoperability features") orelse false,
        .benchmarks = b.option(bool, "benchmarks", "Build benchmark suite") orelse false,
        .tests = b.option(bool, "tests", "Build and run tests") orelse false,
        .examples = b.option(bool, "examples", "Build example programs") orelse false,

        // Build Options
        .all_features = b.option(bool, "all-features", "Enable all features") orelse false,
        .minimal = b.option(bool, "minimal", "Minimal build (core only)") orelse false,
        .fast_build = b.option(bool, "fast-build", "Optimize for build speed") orelse false,
    };

    // Apply feature combinations
    const final_features = struct {
        ml_kem: bool,
        kyber: bool,
        ml_dsa: bool,
        dilithium: bool,
        slh_dsa: bool,
        sphincs: bool,
        hybrid: bool,
        blockchain: bool,
        interop: bool,
        benchmarks: bool,
        tests: bool,
        examples: bool,
        minimal: bool,
    }{
        .ml_kem = if (features.all_features or features.benchmarks) true else features.ml_kem,
        .kyber = if (features.all_features) true else features.kyber,
        .ml_dsa = if (features.all_features or features.benchmarks) true else features.ml_dsa,
        .dilithium = if (features.all_features) true else features.dilithium,
        .slh_dsa = if (features.all_features) true else features.slh_dsa,
        .sphincs = if (features.all_features or features.benchmarks) true else features.sphincs,
        .hybrid = if (features.all_features) true else features.hybrid,
        .blockchain = if (features.all_features) true else features.blockchain,
        .interop = if (features.all_features) true else features.interop,
        .benchmarks = if (features.all_features) features.benchmarks else if (features.minimal) false else features.benchmarks,
        .tests = if (features.all_features) features.tests else if (features.minimal) false else features.tests,
        .examples = if (features.all_features) features.examples else if (features.minimal) false else features.examples,
        .minimal = if (features.all_features) false else if (features.benchmarks) false else features.minimal,
    };

    // Optional dependencies (only if needed)
    const enable_ffibuild = b.option(bool, "enable-ffibuild", "Enable FFI/C binding builds") orelse false;

    // === MODULAR IMPORTS ===
    var imports = std.ArrayList(std.Build.Module.Import){};
    defer imports.deinit(b.allocator);

    // === FEATURE-BASED BUILD OPTIONS ===
    const build_options = b.addOptions();
    build_options.addOption(bool, "ml_kem_enabled", final_features.ml_kem);
    build_options.addOption(bool, "kyber_enabled", final_features.kyber);
    build_options.addOption(bool, "ml_dsa_enabled", final_features.ml_dsa);
    build_options.addOption(bool, "dilithium_enabled", final_features.dilithium);
    build_options.addOption(bool, "slh_dsa_enabled", final_features.slh_dsa);
    build_options.addOption(bool, "sphincs_enabled", final_features.sphincs);
    build_options.addOption(bool, "hybrid_enabled", final_features.hybrid);
    build_options.addOption(bool, "blockchain_enabled", final_features.blockchain);
    build_options.addOption(bool, "interop_enabled", final_features.interop);
    build_options.addOption(bool, "minimal_enabled", final_features.minimal);

    imports.append(b.allocator, .{ .name = "build_options", .module = build_options.createModule() }) catch @panic("OOM");

    // === CORE MODULE ===
    const mod = b.addModule("kriptix", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports.items,
    });

    // === GRANULAR ALGORITHM MODULES ===
    if (final_features.ml_kem or final_features.kyber) {
        _ = b.addModule("ml-kem", .{
            .root_source_file = b.path("src/modules/ml_kem.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "build_options", .module = build_options.createModule() },
            },
        });
    }

    if (final_features.ml_dsa or final_features.dilithium) {
        _ = b.addModule("ml-dsa", .{
            .root_source_file = b.path("src/modules/ml_dsa.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "build_options", .module = build_options.createModule() },
            },
        });
    }

    if (final_features.slh_dsa or final_features.sphincs) {
        _ = b.addModule("slh-dsa", .{
            .root_source_file = b.path("src/modules/slh_dsa.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "build_options", .module = build_options.createModule() },
            },
        });
    }

    if (final_features.interop) {
        _ = b.addModule("interop", .{
            .root_source_file = b.path("src/interop.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports.items,
        });
    }

    // === LIBRARY TARGETS ===
    const lib = b.addLibrary(.{
        .name = "kriptix",
        .root_module = mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // FFI target (optional)
    if (enable_ffibuild) {
        const c_lib = b.addLibrary(.{
            .name = "kriptix_c",
            .root_module = mod,
            .linkage = .dynamic,
        });
        b.installArtifact(c_lib);

        const ffi_step = b.step("ffi", "Build C FFI library");
        ffi_step.dependOn(&b.addInstallArtifact(c_lib, .{}).step);
    }

    // WASM target (optional)
    if (!features.minimal) {
        const wasm_mod = b.addModule("kriptix-wasm", .{
            .root_source_file = b.path("src/root.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .freestanding,
            }),
            .optimize = optimize,
            .imports = imports.items,
        });

        const wasm_lib = b.addLibrary(.{
            .name = "kriptix",
            .root_module = wasm_mod,
            .linkage = .static,
        });
        b.installArtifact(wasm_lib);

        const wasm_step = b.step("wasm", "Build WebAssembly module");
        wasm_step.dependOn(&b.addInstallArtifact(wasm_lib, .{}).step);
    }

    // === CLI EXECUTABLE (Optional) ===
    if (final_features.examples or !features.fast_build) {
        var cli_imports = std.ArrayList(std.Build.Module.Import){};
        defer cli_imports.deinit(b.allocator);

        cli_imports.append(b.allocator, .{ .name = "kriptix", .module = mod }) catch @panic("OOM");

        const cli_exe = b.addExecutable(.{
            .name = "kriptix-cli",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = cli_imports.items,
            }),
        });
        b.installArtifact(cli_exe);

        // Run step
        const run_step = b.step("run", "Run the CLI");
        const run_cmd = b.addRunArtifact(cli_exe);
        run_step.dependOn(&run_cmd.step);

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
    }

    // === CONDITIONAL TESTING SYSTEM ===
    if (final_features.tests) {
        // Fast unit tests (< 1 second)
        const unit_tests = b.addTest(.{
            .name = "unit-tests",
            .root_module = mod,
        });

        const run_unit_tests = b.addRunArtifact(unit_tests);

        // Slow integration tests (only if explicitly requested)
        const integration_tests = b.addTest(.{
            .name = "integration-tests",
            .root_module = mod,
        });

        const run_integration_tests = b.addRunArtifact(integration_tests);

        // Test steps
        const test_unit_step = b.step("test-unit", "Run fast unit tests only");
        test_unit_step.dependOn(&run_unit_tests.step);

        const test_integration_step = b.step("test-integration", "Run slow integration tests");
        test_integration_step.dependOn(&run_integration_tests.step);

        const test_all_step = b.step("test", "Run all tests");
        test_all_step.dependOn(&run_unit_tests.step);
        test_all_step.dependOn(&run_integration_tests.step);
    }

    // === BENCHMARK SYSTEM ===
    if (final_features.benchmarks) {
        const bench_exe = b.addExecutable(.{
            .name = "kriptix-bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/benchmark.zig"),
                .target = target,
                .optimize = .ReleaseFast, // Always optimize benchmarks
                .imports = &.{
                    .{ .name = "kriptix", .module = mod },
                },
            }),
        });

        const bench_step = b.step("bench", "Run performance benchmarks");
        const run_bench = b.addRunArtifact(bench_exe);
        bench_step.dependOn(&run_bench.step);
    }

    // === BUILD TARGETS ===
    const lib_step = b.step("lib", "Build static library");
    lib_step.dependOn(&b.addInstallArtifact(lib, .{}).step);

    // === EXAMPLES ===
    if (final_features.examples) {
        const examples = [_][]const u8{
            "basic_usage",
        };

        for (examples) |example| {
            const example_exe = b.addExecutable(.{
                .name = example,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example})),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "kriptix", .module = mod },
                    },
                }),
            });

            const example_step = b.step(b.fmt("example-{s}", .{example}), b.fmt("Run {s} example", .{example}));
            const run_example = b.addRunArtifact(example_exe);
            example_step.dependOn(&run_example.step);
        }
    }

    // === BUILD INFO ===
    if (!features.fast_build) {
        // Print build configuration
        const config_step = b.step("config", "Show build configuration");
        const config_exe = b.addExecutable(.{
            .name = "show-config",
            .root_module = b.createModule(.{
                .root_source_file = b.path("build_config.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = build_options.createModule() },
                },
            }),
        });

        const run_config = b.addRunArtifact(config_exe);
        config_step.dependOn(&run_config.step);
    }
}
