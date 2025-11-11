//! Gossip Protocol - Efficient message propagation across the network
//!
//! This module implements an epidemic gossip protocol for broadcasting
//! blocks, transactions, and other network messages across the Kriptix
//! blockchain network with anti-entropy mechanisms and duplicate detection.

const std = @import("std");
const kriptix = @import("../../root.zig");
const NetworkConfig = @import("root.zig").NetworkConfig;
const NetworkError = @import("root.zig").NetworkError;
const p2p = @import("p2p.zig");

/// Gossip message types
pub const GossipMessageType = enum(u8) {
    // Blockchain data
    transaction = 0x01,
    block = 0x02,
    block_header = 0x03,

    // Network announcements
    peer_announcement = 0x10,
    topology_update = 0x11,

    // Gossip protocol control
    gossip_hello = 0x20,
    gossip_sync = 0x21,
    gossip_ack = 0x22,

    // Custom application messages
    custom = 0xFF,
};

/// Gossip message with metadata
pub const GossipMessage = struct {
    /// Message identification
    message_id: u64,
    message_type: GossipMessageType,
    originator: [32]u8,

    /// Propagation metadata
    hop_count: u8 = 0,
    max_hops: u8 = 6, // Default TTL
    timestamp: u64,

    /// Content
    payload: []u8,
    payload_hash: [32]u8,

    /// Gossip routing
    seen_by: std.ArrayList([32]u8),

    /// Message priority (higher = more important)
    priority: u8 = 128,

    pub fn init(allocator: std.mem.Allocator, msg_type: GossipMessageType, originator: [32]u8, payload: []const u8) !GossipMessage {
        const message_id = generate_message_id();
        const payload_hash = calculate_hash(payload);

        return GossipMessage{
            .message_id = message_id,
            .message_type = msg_type,
            .originator = originator,
            .timestamp = @intCast(std.time.timestamp()),
            .payload = try allocator.dupe(u8, payload),
            .payload_hash = payload_hash,
            .seen_by = std.ArrayList([32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *GossipMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.seen_by.deinit();
    }

    pub fn clone(self: GossipMessage, allocator: std.mem.Allocator) !GossipMessage {
        var cloned = GossipMessage{
            .message_id = self.message_id,
            .message_type = self.message_type,
            .originator = self.originator,
            .hop_count = self.hop_count,
            .max_hops = self.max_hops,
            .timestamp = self.timestamp,
            .payload = try allocator.dupe(u8, self.payload),
            .payload_hash = self.payload_hash,
            .seen_by = std.ArrayList([32]u8).init(allocator),
            .priority = self.priority,
        };

        try cloned.seen_by.appendSlice(self.seen_by.items);
        return cloned;
    }

    pub fn should_propagate(self: GossipMessage, node_id: [32]u8) bool {
        // Don't propagate if hop count exceeded
        if (self.hop_count >= self.max_hops) return false;

        // Don't propagate if already seen by this node
        for (self.seen_by.items) |seen_node| {
            if (std.mem.eql(u8, &seen_node, &node_id)) return false;
        }

        // Check age (don't propagate very old messages)
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        const age_seconds = current_time - self.timestamp;
        return age_seconds < 3600; // 1 hour max age
    }

    pub fn add_seen_by(self: *GossipMessage, node_id: [32]u8) !void {
        try self.seen_by.append(node_id);
    }

    pub fn increment_hop_count(self: *GossipMessage) void {
        self.hop_count += 1;
    }

    fn generate_message_id() u64 {
        return @intCast(std.time.timestamp() * 1000000 + std.crypto.random.int(u32));
    }

    fn calculate_hash(data: []const u8) [32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(data);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }
};

/// Message cache for duplicate detection
pub const MessageCache = struct {
    allocator: std.mem.Allocator,
    messages: std.HashMap(u64, CachedMessage, u64, std.hash_map.default_max_load_percentage), // message_id -> cached_message
    max_size: usize,
    cleanup_interval: u64 = 300, // 5 minutes
    last_cleanup: u64 = 0,

    const CachedMessage = struct {
        message_hash: [32]u8,
        timestamp: u64,
        seen_count: u32,
    };

    pub fn init(allocator: std.mem.Allocator, max_size: usize) MessageCache {
        return MessageCache{
            .allocator = allocator,
            .messages = std.HashMap(u64, CachedMessage, std.array_hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .max_size = max_size,
            .last_cleanup = @intCast(@divExact(@as(u64, @intCast(std.time.milliTimestamp())), 1000)),
        };
    }

    pub fn deinit(self: *MessageCache) void {
        self.messages.deinit();
    }

    pub fn is_duplicate(self: *MessageCache, message: GossipMessage) bool {
        if (self.messages.get(message.message_id)) |cached| {
            return std.mem.eql(u8, &cached.message_hash, &message.payload_hash);
        }
        return false;
    }

    pub fn add_message(self: *MessageCache, message: GossipMessage) !void {
        const cached_msg = CachedMessage{
            .message_hash = message.payload_hash,
            .timestamp = message.timestamp,
            .seen_count = 1,
        };

        try self.messages.put(message.message_id, cached_msg);

        // Cleanup if needed
        if (self.messages.count() > self.max_size) {
            try self.cleanup_old_messages();
        }
    }

    pub fn increment_seen_count(self: *MessageCache, message_id: u64) void {
        if (self.messages.getPtr(message_id)) |cached| {
            cached.seen_count += 1;
        }
    }

    fn cleanup_old_messages(self: *MessageCache) !void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));

        // Only cleanup if enough time has passed
        if (current_time - self.last_cleanup < self.cleanup_interval) return;

        var messages_to_remove = std.ArrayList(u64).init(self.allocator);
        defer messages_to_remove.deinit();

        var iter = self.messages.iterator();
        while (iter.next()) |entry| {
            const age = current_time - entry.value_ptr.timestamp;
            if (age > 3600) { // Remove messages older than 1 hour
                try messages_to_remove.append(entry.key_ptr.*);
            }
        }

        for (messages_to_remove.items) |message_id| {
            _ = self.messages.remove(message_id);
        }

        self.last_cleanup = current_time;
    }
};

/// Anti-entropy mechanism for ensuring message consistency
pub const AntiEntropy = struct {
    allocator: std.mem.Allocator,
    node_id: [32]u8,

    /// Digest of known messages for synchronization
    message_digest: std.HashMap(u64, MessageDigest, u64, std.hash_map.default_max_load_percentage),

    /// Synchronization state
    sync_interval: u64 = 60, // 1 minute
    last_sync: u64 = 0,

    const MessageDigest = struct {
        message_id: u64,
        message_hash: [32]u8,
        timestamp: u64,
        hop_count: u8,
    };

    pub fn init(allocator: std.mem.Allocator, node_id: [32]u8) AntiEntropy {
        return AntiEntropy{
            .allocator = allocator,
            .node_id = node_id,
            .message_digest = std.HashMap(u64, MessageDigest, std.array_hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .last_sync = @intCast(@divExact(@as(u64, @intCast(std.time.milliTimestamp())), 1000)),
        };
    }

    pub fn deinit(self: *AntiEntropy) void {
        self.message_digest.deinit();
    }

    pub fn add_message_digest(self: *AntiEntropy, message: GossipMessage) !void {
        const digest = MessageDigest{
            .message_id = message.message_id,
            .message_hash = message.payload_hash,
            .timestamp = message.timestamp,
            .hop_count = message.hop_count,
        };

        try self.message_digest.put(message.message_id, digest);
    }

    pub fn needs_sync(self: AntiEntropy) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time - self.last_sync >= self.sync_interval;
    }

    pub fn create_sync_digest(self: AntiEntropy, allocator: std.mem.Allocator) ![]u8 {
        // Create a compact digest of known messages
        var digest_list = std.ArrayList(MessageDigest).init(allocator);
        defer digest_list.deinit();

        var iter = self.message_digest.iterator();
        while (iter.next()) |entry| {
            try digest_list.append(entry.value_ptr.*);
        }

        // Serialize digest list
        const serialized_size = digest_list.items.len * @sizeOf(MessageDigest);
        var serialized = try allocator.alloc(u8, serialized_size);

        for (digest_list.items, 0..) |digest, i| {
            const offset = i * @sizeOf(MessageDigest);
            @memcpy(serialized[offset .. offset + @sizeOf(MessageDigest)], std.mem.asBytes(&digest));
        }

        return serialized;
    }

    pub fn compare_digests(self: *AntiEntropy, peer_digest: []const u8, allocator: std.mem.Allocator) ![]u64 {
        var missing_messages = std.ArrayList(u64).init(allocator);
        defer missing_messages.deinit();

        // Parse peer digest
        const digest_size = @sizeOf(MessageDigest);
        var i: usize = 0;

        while (i + digest_size <= peer_digest.len) {
            const peer_msg_digest = @as(*const MessageDigest, @ptrCast(@alignCast(peer_digest[i .. i + digest_size].ptr))).*;

            if (!self.message_digest.contains(peer_msg_digest.message_id)) {
                try missing_messages.append(peer_msg_digest.message_id);
            }

            i += digest_size;
        }

        return try missing_messages.toOwnedSlice();
    }

    pub fn update_sync_time(self: *AntiEntropy) void {
        self.last_sync = @intCast(std.time.timestamp());
    }
};

/// Gossip Protocol Manager
pub const GossipProtocol = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,
    node_id: [32]u8,

    /// Protocol components
    message_cache: MessageCache,
    anti_entropy: AntiEntropy,

    /// Active messages being gossiped
    active_messages: std.ArrayList(GossipMessage),

    /// Gossip statistics
    stats: GossipStats,

    /// Peer selection for gossip
    gossip_fanout: u8,

    const GossipStats = struct {
        messages_originated: u64 = 0,
        messages_received: u64 = 0,
        messages_forwarded: u64 = 0,
        messages_dropped: u64 = 0,
        duplicates_detected: u64 = 0,
        sync_operations: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .node_id = config.node_id,
            .message_cache = MessageCache.init(allocator, 10000), // Cache up to 10k messages
            .anti_entropy = AntiEntropy.init(allocator, config.node_id),
            .active_messages = std.ArrayList(GossipMessage){},
            .stats = GossipStats{},
            .gossip_fanout = config.gossip_fanout,
        };
    }

    pub fn deinit(self: *Self) void {
        self.message_cache.deinit();
        self.anti_entropy.deinit();

        for (self.active_messages.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.active_messages.deinit();
    }

    pub fn start(self: *Self) !void {
        _ = self;
        std.log.info("Gossip Protocol starting...", .{});
    }

    pub fn stop(self: *Self) !void {
        _ = self;
        std.log.info("Gossip Protocol stopping...", .{});
    }

    /// Broadcast a new message to the network
    pub fn broadcast_message(self: *Self, msg_type: GossipMessageType, payload: []const u8) !void {
        var message = try GossipMessage.init(self.allocator, msg_type, self.node_id, payload);
        try message.add_seen_by(self.node_id);

        // Add to cache and anti-entropy
        try self.message_cache.add_message(message);
        try self.anti_entropy.add_message_digest(message);

        // Add to active messages for gossip propagation
        try self.active_messages.append(message);

        self.stats.messages_originated += 1;

        std.log.info("Broadcasting message type {} with {} bytes", .{ @intFromEnum(msg_type), payload.len });
    }

    /// Process incoming gossip message
    pub fn receive_message(self: *Self, sender_id: [32]u8, raw_message: []const u8) !bool {
        // Deserialize message (simplified for demo)
        var message = try self.deserialize_message(raw_message);
        defer message.deinit(self.allocator);

        // Check for duplicates
        if (self.message_cache.is_duplicate(message)) {
            self.stats.duplicates_detected += 1;
            return false;
        }

        // Check if should propagate
        if (!message.should_propagate(self.node_id)) {
            self.stats.messages_dropped += 1;
            return false;
        }

        // Add to cache and mark as seen
        try self.message_cache.add_message(message);
        try self.anti_entropy.add_message_digest(message);

        // Create propagation copy
        var propagation_message = try message.clone(self.allocator);
        try propagation_message.add_seen_by(self.node_id);
        propagation_message.increment_hop_count();

        // Add to active messages for further propagation
        try self.active_messages.append(propagation_message);

        self.stats.messages_received += 1;

        std.log.info("Received gossip message from {any}, type {}, {} hops", .{ sender_id[0..4], @intFromEnum(message.message_type), message.hop_count });

        return true;
    }

    /// Process gossip rounds - select peers and forward messages
    pub fn process_gossip_round(self: *Self, peer_manager: *p2p.P2PManager) !void {
        // Process each active message
        var messages_to_remove = std.ArrayList(usize).init(self.allocator);
        defer messages_to_remove.deinit();

        for (self.active_messages.items, 0..) |*message, i| {
            const propagated = try self.propagate_message(message, peer_manager);

            if (!propagated or message.hop_count >= message.max_hops) {
                try messages_to_remove.append(i);
            }
        }

        // Remove completed messages
        var j = messages_to_remove.items.len;
        while (j > 0) {
            j -= 1;
            const index = messages_to_remove.items[j];
            var msg = self.active_messages.swapRemove(index);
            msg.deinit(self.allocator);
        }

        // Anti-entropy synchronization
        if (self.anti_entropy.needs_sync()) {
            try self.perform_anti_entropy_sync(peer_manager);
        }
    }

    /// Propagate message to selected peers
    fn propagate_message(self: *Self, message: *GossipMessage, peer_manager: *p2p.P2PManager) !bool {
        // Select random peers for gossip (simplified peer selection)
        const peer_count = peer_manager.get_connected_peer_count();
        if (peer_count == 0) return false;

        const fanout = @min(self.gossip_fanout, peer_count);
        var propagated = false;

        // In a real implementation, would select random subset of peers
        // For now, just indicate successful propagation
        _ = message;
        _ = fanout;

        if (peer_count > 0) {
            self.stats.messages_forwarded += 1;
            propagated = true;
        }

        return propagated;
    }

    /// Perform anti-entropy synchronization with peers
    fn perform_anti_entropy_sync(self: *Self, peer_manager: *p2p.P2PManager) !void {
        _ = peer_manager;

        // Create digest of known messages
        const digest = try self.anti_entropy.create_sync_digest(self.allocator);
        defer self.allocator.free(digest);

        // In real implementation, would send digest to random peer and
        // compare with their digest to identify missing messages

        self.anti_entropy.update_sync_time();
        self.stats.sync_operations += 1;

        std.log.debug("Performed anti-entropy sync with {} message digests", .{self.anti_entropy.message_digest.count()});
    }

    /// Clean up old messages from active list
    pub fn cleanup_old_messages(self: *Self) !void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        var messages_to_remove = std.ArrayList(usize).init(self.allocator);
        defer messages_to_remove.deinit();

        for (self.active_messages.items, 0..) |message, i| {
            const age = current_time - message.timestamp;
            if (age > 1800) { // 30 minutes
                try messages_to_remove.append(i);
            }
        }

        // Remove old messages
        var j = messages_to_remove.items.len;
        while (j > 0) {
            j -= 1;
            const index = messages_to_remove.items[j];
            var msg = self.active_messages.swapRemove(index);
            msg.deinit(self.allocator);
        }
    }

    /// Serialize message for network transmission
    fn serialize_message(self: *Self, message: GossipMessage) ![]u8 {
        // Simplified serialization - in real implementation would use proper encoding
        const header_size = 64; // Fixed header size
        const total_size = header_size + message.payload.len;

        var serialized = try self.allocator.alloc(u8, total_size);

        // Pack header (simplified)
        @memcpy(serialized[0..8], &@as([8]u8, @bitCast(message.message_id)));
        @memcpy(serialized[8..16], &@as([8]u8, @bitCast(message.timestamp)));
        @memcpy(serialized[16..48], &message.originator);
        @memcpy(serialized[48..56], &@as([8]u8, @bitCast(@as(u64, message.hop_count))));

        // Pack payload
        @memcpy(serialized[header_size..], message.payload);

        return serialized;
    }

    /// Deserialize message from network data
    fn deserialize_message(self: *Self, data: []const u8) !GossipMessage {
        if (data.len < 64) return NetworkError.InvalidMessage;

        const message_id = @as(u64, @bitCast(data[0..8].*));
        const timestamp = @as(u64, @bitCast(data[8..16].*));
        const originator = data[16..48].*;
        const hop_count = @as(u8, @intCast(@as(u64, @bitCast(data[48..56].*)) & 0xFF));

        const payload = try self.allocator.dupe(u8, data[64..]);

        const message = GossipMessage{
            .message_id = message_id,
            .message_type = .custom, // Would parse from header
            .originator = originator,
            .hop_count = hop_count,
            .timestamp = timestamp,
            .payload = payload,
            .payload_hash = GossipMessage.calculate_hash(payload),
            .seen_by = std.ArrayList([32]u8).init(self.allocator),
            .priority = 128,
            .max_hops = 6,
        };

        return message;
    }

    /// Get gossip protocol statistics
    pub fn get_stats(self: Self) GossipStats {
        return self.stats;
    }

    /// Get active message count
    pub fn get_active_message_count(self: Self) usize {
        return self.active_messages.items.len;
    }
};

test "gossip protocol basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = NetworkConfig{
        .node_id = [_]u8{1} ** 32,
        .bootstrap_nodes = &[_]NetworkConfig.BootstrapNode{},
        .gossip_fanout = 3,
    };

    var gossip = try GossipProtocol.init(allocator, config);
    defer gossip.deinit();

    // Test message broadcasting
    const test_payload = "Hello, Kriptix Network!";
    try gossip.broadcast_message(.custom, test_payload);

    const stats = gossip.get_stats();
    std.testing.expect(stats.messages_originated == 1) catch unreachable;
    std.testing.expect(gossip.get_active_message_count() == 1) catch unreachable;
}
