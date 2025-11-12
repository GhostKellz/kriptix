const std = @import("std");
const kriptix = @import("kriptix");

pub fn main() !void {
    std.debug.print("Kriptix - Post-Quantum Cryptography Library\n", .{});

    // Initialize the library
    kriptix.init();
    defer kriptix.deinit();

    // Example usage
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Try to use modular API first (available in all builds)
    if (@hasDecl(kriptix, "modules")) {
        std.debug.print("Using modular API:\n", .{});

        // Use ML-KEM if available
        if (@hasDecl(kriptix.modules, "ml_kem") and @hasDecl(kriptix.modules.ml_kem, "MlKem512")) {
            const ml_kem = kriptix.modules.ml_kem;
            const keypair = try ml_kem.MlKem512.keygen(allocator);
            defer allocator.free(keypair.public_key);
            defer allocator.free(keypair.private_key);

            std.debug.print("Generated ML-KEM-512 keypair: pub={}, priv={}\n", .{
                keypair.public_key.len,
                keypair.private_key.len,
            });
            return;
        }

        // Use ML-DSA if available
        if (@hasDecl(kriptix.modules, "ml_dsa") and @hasDecl(kriptix.modules.ml_dsa, "MlDsa44")) {
            const ml_dsa = kriptix.modules.ml_dsa;
            const keypair = try ml_dsa.MlDsa44.keygen(allocator);
            defer keypair.deinit(allocator);

            std.debug.print("Generated ML-DSA-44 keypair: pub={}, priv={}\n", .{
                keypair.public_key.len,
                keypair.private_key.len,
            });
            return;
        }

        std.debug.print("No algorithms enabled. Use -Dml-kem=true, -Dml-dsa=true, etc.\n", .{});
    } else {
        std.debug.print("Modules not available - this shouldn't happen.\n", .{});
    }
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
