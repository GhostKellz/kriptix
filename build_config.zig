//! Build Configuration Display Utility

const std = @import("std");
const build_options = @import("build_options");
const print = std.debug.print;

pub fn main() !void {
    print("🔧 Kriptix Build Configuration\n", .{});
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

    print("Post-Quantum Algorithms:\n", .{});
    print("  ML-KEM (FIPS 203):     {s}\n", .{if (build_options.ml_kem_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  Kyber (Legacy):        {s}\n", .{if (build_options.kyber_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  ML-DSA (FIPS 204):     {s}\n", .{if (build_options.ml_dsa_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  Dilithium (Legacy):    {s}\n", .{if (build_options.dilithium_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  SLH-DSA (FIPS 205):    {s}\n", .{if (build_options.slh_dsa_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  SPHINCS+ (Legacy):     {s}\n", .{if (build_options.sphincs_enabled) "✅ Enabled" else "❌ Disabled"});

    print("\nFeatures:\n", .{});
    print("  Hybrid Schemes:        {s}\n", .{if (build_options.hybrid_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  Blockchain Support:    {s}\n", .{if (build_options.blockchain_enabled) "✅ Enabled" else "❌ Disabled"});
    print("  Interoperability:      {s}\n", .{if (build_options.interop_enabled) "✅ Enabled" else "❌ Disabled"});

    print("\nEstimated Build Time:\n", .{});
    const enabled_algorithms =
        @as(u8, if (build_options.ml_kem_enabled) 1 else 0) +
        @as(u8, if (build_options.kyber_enabled) 1 else 0) +
        @as(u8, if (build_options.ml_dsa_enabled) 1 else 0) +
        @as(u8, if (build_options.dilithium_enabled) 1 else 0) +
        @as(u8, if (build_options.slh_dsa_enabled) 1 else 0) +
        @as(u8, if (build_options.sphincs_enabled) 1 else 0);

    const estimated_time = switch (enabled_algorithms) {
        0 => "< 3 seconds (minimal build)",
        1...2 => "5-15 seconds (selective build)",
        3...4 => "15-30 seconds (moderate build)",
        5...6 => "30-60 seconds (full build)",
        else => "60+ seconds (complete build)",
    };

    print("  {s}\n", .{estimated_time});

    print("\nBuild Commands:\n", .{});
    print("  zig build lib                     # Build library only\n", .{});
    print("  zig build -Dml-kem=true         # Enable ML-KEM\n", .{});
    print("  zig build -Dminimal=true         # Minimal build\n", .{});
    print("  zig build -Dall-features=true   # Full-featured build\n", .{});
    print("  zig build -Dfast-build=true     # Optimize for build speed\n", .{});
}
