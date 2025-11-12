//! Classic (pre-quantum) cryptography helpers implemented with Zig std.crypto

pub const ed25519 = @import("ed25519.zig");
pub const x25519 = @import("x25519.zig");
pub const aead = @import("aead.zig");
