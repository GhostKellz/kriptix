const std = @import("std");

pub fn main() !void {
    // Test available timing functions
    const time_info = @typeInfo(@TypeOf(std.time));
    std.debug.print("Time module info: {}\n", .{time_info});
}
