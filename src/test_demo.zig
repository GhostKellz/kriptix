const std = @import("std");
const test_vectors = @import("pq/test_vectors.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🧪 Running NIST Test Vector Validation...\n", .{});

    try test_vectors.run_nist_validation(allocator);
}
