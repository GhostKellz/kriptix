//! P2P Manager - Core peer-to-peer connection and message handling
//!
//! This module manages peer connections, message routing, and maintains
//! the network topology for the Kriptix blockchain network using post-quantum
//! secure communications.

const std = @import("std");
const kriptix = @import("../../root.zig");
const NetworkConfig = @import("root.zig").NetworkConfig;
const NetworkError = @import("root.zig").NetworkError;

/// Message handler callback type
pub const MessageHandler = *const fn (sender: [32]u8, message_type: u8, payload: []const u8) void;

/// Peer information and status
pub const PeerInfo = struct {
    /// Unique peer identifier
    id: [32]u8,

    /// Network address information
    address: []u8,
    port: u16,

    /// Cryptographic keys
    public_key: []u8,
    signature_algorithm: kriptix.Algorithm,
    kem_algorithm: kriptix.Algorithm,

    /// Connection status
    status: PeerStatus = .disconnected,
    connection_time: u64 = 0,
    last_activity: u64 = 0,

    /// Performance metrics
    latency_ms: u32 = 0,
    throughput_bps: u64 = 0,
    reliability_score: u8 = 100, // 0-100

    /// Protocol information
    protocol_version: u32 = 1,
    supported_features: []u8,

    /// Connection metadata
    is_inbound: bool = false,
    connection_attempts: u8 = 0,
    last_error: ?NetworkError = null,

    const PeerStatus = enum(u8) {
        disconnected,
        connecting,
        handshaking,
        authenticating,
        connected,
        peer_error,
    };

    pub fn init(allocator: std.mem.Allocator, id: [32]u8, address: []const u8, port: u16) !PeerInfo {
        return PeerInfo{
            .id = id,
            .address = try allocator.dupe(u8, address),
            .port = port,
            .public_key = try allocator.alloc(u8, 0), // Empty initially
            .signature_algorithm = .Dilithium3,
            .kem_algorithm = .Kyber768,
            .supported_features = try allocator.alloc(u8, 0), // Empty initially
        };
    }

    pub fn deinit(self: *PeerInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        allocator.free(self.public_key);
        allocator.free(self.supported_features);
    }

    pub fn is_connected(self: PeerInfo) bool {
        return self.status == .connected;
    }

    pub fn is_healthy(self: PeerInfo) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return self.is_connected() and
            self.reliability_score >= 70 and
            current_time - self.last_activity < 300; // 5 minutes
    }

    pub fn update_activity(self: *PeerInfo) void {
        self.last_activity = @intCast(std.time.timestamp());
    }
};

/// Secure connection to a peer
pub const PeerConnection = struct {
    allocator: std.mem.Allocator,
    peer_info: PeerInfo,

    /// Shared secret for encryption
    shared_secret: [32]u8,
    encryption_key: [32]u8,
    decryption_key: [32]u8,

    /// Message sequencing for replay protection
    send_sequence: u64 = 0,
    recv_sequence: u64 = 0,

    /// Connection state
    established: bool = false,
    authenticated: bool = false,

    /// Message queues
    outbound_queue: std.ArrayList(QueuedMessage),
    pending_messages: std.HashMap(u64, PendingMessage, u64, std.hash_map.default_max_load_percentage),

    const QueuedMessage = struct {
        message_type: u8,
        payload: []u8,
        timestamp: u64,
        retry_count: u8 = 0,
        message_id: u64,
    };

    const PendingMessage = struct {
        message: QueuedMessage,
        callback: ?*const fn (success: bool) void = null,
        timeout: u64,
    };

    pub fn init(allocator: std.mem.Allocator, peer_info: PeerInfo) PeerConnection {
        return PeerConnection{
            .allocator = allocator,
            .peer_info = peer_info,
            .shared_secret = [_]u8{0} ** 32,
            .encryption_key = [_]u8{0} ** 32,
            .decryption_key = [_]u8{0} ** 32,
            .outbound_queue = std.ArrayList(QueuedMessage).init(allocator),
            .pending_messages = std.HashMap(u64, PendingMessage, std.array_hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
        };
    }

    pub fn deinit(self: *PeerConnection) void {
        // Clean up outbound queue
        for (self.outbound_queue.items) |*msg| {
            self.allocator.free(msg.payload);
        }
        self.outbound_queue.deinit();

        // Clean up pending messages
        var pending_iter = self.pending_messages.iterator();
        while (pending_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.message.payload);
        }
        self.pending_messages.deinit();

        self.peer_info.deinit(self.allocator);
    }

    /// Establish secure connection using post-quantum key exchange
    pub fn establish_connection(self: *PeerConnection, local_private_key: []const u8) !void {
        _ = local_private_key; // TODO: Use for authentication
        // Generate ephemeral Kyber keypair
        const ephemeral_keypair = try kriptix.generate_keypair(self.allocator, .Kyber768);
        defer {
            self.allocator.free(ephemeral_keypair.public_key);
            self.allocator.free(ephemeral_keypair.private_key);
        }

        // Perform key exchange with peer's public key
        if (self.peer_info.public_key.len > 0) {
            const ciphertext = try kriptix.encrypt(self.allocator, self.peer_info.public_key, &[_]u8{0} ** 32, .Kyber768);
            defer self.allocator.free(ciphertext.data);

            // Derive shared secret (simplified for demo)
            std.crypto.random.bytes(&self.shared_secret);
            self.derive_encryption_keys();

            self.established = true;
            self.peer_info.status = .connected;
            self.peer_info.connection_time = @intCast(std.time.timestamp());
        }
    }

    /// Derive encryption keys from shared secret
    fn derive_encryption_keys(self: *PeerConnection) void {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.shared_secret);
        hasher.update(&self.peer_info.id);
        hasher.update("encrypt");
        hasher.final(&self.encryption_key);

        hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.shared_secret);
        hasher.update(&self.peer_info.id);
        hasher.update("decrypt");
        hasher.final(&self.decryption_key);
    }

    /// Queue message for sending
    pub fn queue_message(self: *PeerConnection, message_type: u8, payload: []const u8) !u64 {
        const message_id = self.generate_message_id();
        const queued_message = QueuedMessage{
            .message_type = message_type,
            .payload = try self.allocator.dupe(u8, payload),
            .timestamp = @intCast(std.time.timestamp()),
            .message_id = message_id,
        };

        try self.outbound_queue.append(queued_message);
        return message_id;
    }

    /// Process outbound message queue
    pub fn process_outbound_queue(self: *PeerConnection) !void {
        if (!self.established) return;

        var messages_to_remove = std.ArrayList(usize).init(self.allocator);
        defer messages_to_remove.deinit();

        for (self.outbound_queue.items, 0..) |*msg, i| {
            const success = try self.send_message_internal(msg);

            if (success) {
                try messages_to_remove.append(i);
            } else {
                msg.retry_count += 1;
                if (msg.retry_count > 3) {
                    try messages_to_remove.append(i);
                }
            }
        }

        // Remove processed messages in reverse order
        var j = messages_to_remove.items.len;
        while (j > 0) {
            j -= 1;
            const index = messages_to_remove.items[j];
            var msg = self.outbound_queue.swapRemove(index);
            self.allocator.free(msg.payload);
        }
    }

    /// Internal message sending with encryption
    fn send_message_internal(self: *PeerConnection, message: *QueuedMessage) !bool {
        // Encrypt message payload
        const encrypted_payload = try self.encrypt_payload(message.payload);
        defer self.allocator.free(encrypted_payload);

        // In a real implementation, this would send over network
        // For now, simulate successful send
        self.send_sequence += 1;
        return true;
    }

    /// Encrypt message payload
    fn encrypt_payload(self: *PeerConnection, payload: []const u8) ![]u8 {
        // Simple XOR encryption for demonstration
        var encrypted = try self.allocator.alloc(u8, payload.len + 8); // +8 for sequence

        // Add sequence number
        @memcpy(encrypted[0..8], &@as([8]u8, @bitCast(self.send_sequence)));

        // Encrypt payload
        for (payload, 0..) |byte, i| {
            encrypted[8 + i] = byte ^ self.encryption_key[i % 32];
        }

        return encrypted;
    }

    /// Decrypt message payload
    pub fn decrypt_payload(self: *PeerConnection, encrypted: []const u8) ![]u8 {
        if (encrypted.len < 8) return NetworkError.InvalidMessage;

        // Extract sequence number
        const sequence = @as(u64, @bitCast(encrypted[0..8].*));
        if (sequence != self.recv_sequence) return NetworkError.InvalidMessage;

        // Decrypt payload
        var decrypted = try self.allocator.alloc(u8, encrypted.len - 8);
        for (encrypted[8..], 0..) |byte, i| {
            decrypted[i] = byte ^ self.decryption_key[i % 32];
        }

        self.recv_sequence += 1;
        return decrypted;
    }

    fn generate_message_id(self: *PeerConnection) u64 {
        _ = self;
        return @intCast(std.time.timestamp() * 1000 + std.crypto.random.int(u16));
    }
};

/// P2P Manager - Main peer management and messaging coordinator
pub const P2PManager = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,

    /// Peer management
    peers: std.HashMap([32]u8, PeerConnection, [32]u8, std.hash_map.default_max_load_percentage),
    peer_discovery_list: std.ArrayList(PeerInfo),

    /// Message handling
    message_handlers: std.HashMap(u8, MessageHandler, u8, std.hash_map.default_max_load_percentage),
    message_id_counter: u64 = 0,

    /// Connection management
    inbound_connections: u32 = 0,
    outbound_connections: u32 = 0,

    /// Statistics
    stats: P2PStats,

    const P2PStats = struct {
        connections_established: u64 = 0,
        connections_failed: u64 = 0,
        messages_sent: u64 = 0,
        messages_received: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .peers = std.HashMap([32]u8, PeerConnection, std.array_hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage).init(allocator),
            .peer_discovery_list = std.ArrayList(PeerInfo){},
            .message_handlers = std.HashMap(u8, MessageHandler, std.array_hash_map.AutoContext(u8), std.hash_map.default_max_load_percentage).init(allocator),
            .stats = P2PStats{},
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up peer connections
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.peers.deinit();

        // Clean up discovery list
        for (self.peer_discovery_list.items) |*peer| {
            peer.deinit(self.allocator);
        }
        self.peer_discovery_list.deinit();

        self.message_handlers.deinit();
    }

    pub fn start(self: *Self) !void {
        _ = self;
        std.log.info("P2P Manager starting...", .{});
        // Start listening for connections
        // In real implementation, would bind to socket and start accepting connections
    }

    pub fn stop(self: *Self) !void {
        std.log.info("P2P Manager stopping...", .{});
        // Close all connections
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            entry.value_ptr.established = false;
        }
    }

    /// Add a peer to the discovery list
    pub fn add_peer(self: *Self, peer_info: PeerInfo) !void {
        try self.peer_discovery_list.append(peer_info);
    }

    /// Connect to a specific peer
    pub fn connect_to_peer(self: *Self, peer_id: [32]u8, local_private_key: []const u8) !void {
        if (self.peers.contains(peer_id)) return; // Already connected

        // Find peer in discovery list
        var peer_info_opt: ?PeerInfo = null;
        for (self.peer_discovery_list.items) |peer| {
            if (std.mem.eql(u8, &peer.id, &peer_id)) {
                peer_info_opt = peer;
                break;
            }
        }

        const peer_info = peer_info_opt orelse return NetworkError.PeerNotFound;

        // Check connection limits
        if (self.outbound_connections >= self.config.max_outbound_peers) {
            return NetworkError.MaxPeersReached;
        }

        // Create connection
        var connection = PeerConnection.init(self.allocator, peer_info);
        try connection.establish_connection(local_private_key);

        try self.peers.put(peer_id, connection);
        self.outbound_connections += 1;
        self.stats.connections_established += 1;

        std.log.info("Connected to peer {any}", .{peer_id[0..8]});
    }

    /// Send message to specific peer
    pub fn send_message(self: *Self, peer_id: [32]u8, message_type: u8, payload: []const u8) !void {
        const connection = self.peers.getPtr(peer_id) orelse return NetworkError.PeerNotFound;

        _ = try connection.queue_message(message_type, payload);
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += payload.len;
    }

    /// Register message handler for specific message type
    pub fn register_handler(self: *Self, message_type: u8, handler: MessageHandler) !void {
        try self.message_handlers.put(message_type, handler);
    }

    /// Process all peer connections
    pub fn process_connections(self: *Self) !void {
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            try entry.value_ptr.process_outbound_queue();
        }
    }

    /// Handle incoming message from peer
    pub fn handle_incoming_message(self: *Self, sender_id: [32]u8, message_type: u8, payload: []const u8) !void {
        if (self.message_handlers.get(message_type)) |handler| {
            handler(sender_id, message_type, payload);
            self.stats.messages_received += 1;
            self.stats.bytes_received += payload.len;
        }

        // Update peer activity
        if (self.peers.getPtr(sender_id)) |connection| {
            connection.peer_info.update_activity();
        }
    }

    /// Clean up stale connections
    pub fn cleanup_stale_connections(self: *Self) !void {
        var peers_to_remove = std.ArrayList([32]u8).init(self.allocator);
        defer peers_to_remove.deinit();

        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            if (!entry.value_ptr.peer_info.is_healthy()) {
                try peers_to_remove.append(entry.key_ptr.*);
            }
        }

        for (peers_to_remove.items) |peer_id| {
            self.disconnect_peer(peer_id);
        }
    }

    /// Disconnect from peer
    pub fn disconnect_peer(self: *Self, peer_id: [32]u8) void {
        if (self.peers.fetchRemove(peer_id)) |kv| {
            var connection = kv.value;
            if (!connection.peer_info.is_inbound) {
                self.outbound_connections -= 1;
            } else {
                self.inbound_connections -= 1;
            }
            connection.deinit();

            std.log.info("Disconnected from peer {any}", .{peer_id[0..8]});
        }
    }

    /// Get current peer count
    pub fn get_peer_count(self: Self) u32 {
        return @intCast(self.peers.count());
    }

    /// Get connected peer count
    pub fn get_connected_peer_count(self: Self) u32 {
        var count: u32 = 0;
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            if (entry.value_ptr.peer_info.is_connected()) {
                count += 1;
            }
        }
        return count;
    }

    /// Get pending connection count
    pub fn get_pending_connection_count(self: Self) u32 {
        var count: u32 = 0;
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            if (entry.value_ptr.peer_info.status == .connecting or
                entry.value_ptr.peer_info.status == .handshaking)
            {
                count += 1;
            }
        }
        return count;
    }

    /// Get P2P statistics
    pub fn get_stats(self: Self) P2PStats {
        return self.stats;
    }
};

test "p2p manager basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = NetworkConfig{
        .node_id = [_]u8{1} ** 32,
        .bootstrap_nodes = &[_]NetworkConfig.BootstrapNode{},
    };

    var p2p = try P2PManager.init(allocator, config);
    defer p2p.deinit();

    std.testing.expect(p2p.get_peer_count() == 0) catch unreachable;
}
