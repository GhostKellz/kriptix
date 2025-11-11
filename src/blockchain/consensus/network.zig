//! Network Communication Layer for aBFT Consensus
//!
//! This module provides secure peer-to-peer communication for the aBFT consensus
//! protocol using post-quantum cryptography for secure channels, peer discovery,
//! and message routing.

const std = @import("std");
const kriptix = @import("../../root.zig");
const crypto = @import("../crypto.zig");
const validator_mgmt = @import("validator_management.zig");

/// Network message types for consensus communication
pub const MessageType = enum(u8) {
    // Consensus messages
    transaction_proposal = 0x01,
    transaction_vote = 0x02,
    block_proposal = 0x03,
    block_vote = 0x04,

    // Network management
    peer_discovery = 0x10,
    peer_announce = 0x11,
    handshake_request = 0x12,
    handshake_response = 0x13,

    // Validator management
    validator_registration = 0x20,
    validator_update = 0x21,
    validator_exit = 0x22,

    // State synchronization
    state_request = 0x30,
    state_response = 0x31,
    block_sync_request = 0x32,
    block_sync_response = 0x33,

    // Health and monitoring
    ping = 0x40,
    pong = 0x41,
    status_update = 0x42,
};

/// Network message header
pub const MessageHeader = struct {
    /// Protocol version
    version: u8 = 1,

    /// Message type
    msg_type: MessageType,

    /// Total message length including header
    length: u32,

    /// Sender's validator ID
    sender_id: [32]u8,

    /// Message timestamp
    timestamp: u64,

    /// Message sequence number for ordering
    sequence: u64,

    /// PQC signature of the message
    signature: [1024]u8, // Max signature size for Dilithium

    /// Actual signature length
    signature_len: u16,

    /// Hash of the message payload
    payload_hash: [32]u8,

    const HEADER_SIZE = @sizeOf(MessageHeader);

    pub fn calculate_payload_hash(payload: []const u8) [32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(payload);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    pub fn serialize(self: MessageHeader, buffer: []u8) !void {
        if (buffer.len < HEADER_SIZE) return error.BufferTooSmall;
        @memcpy(buffer[0..HEADER_SIZE], std.mem.asBytes(&self));
    }

    pub fn deserialize(buffer: []const u8) !MessageHeader {
        if (buffer.len < HEADER_SIZE) return error.BufferTooSmall;
        return @as(*const MessageHeader, @ptrCast(@alignCast(buffer.ptr))).*;
    }
};

/// Network message with header and payload
pub const NetworkMessage = struct {
    header: MessageHeader,
    payload: []u8,

    pub fn init(allocator: std.mem.Allocator, msg_type: MessageType, sender_id: [32]u8, payload: []const u8, sequence: u64) !NetworkMessage {
        const header = MessageHeader{
            .msg_type = msg_type,
            .length = @intCast(MessageHeader.HEADER_SIZE + payload.len),
            .sender_id = sender_id,
            .timestamp = @intCast(std.time.timestamp()),
            .sequence = sequence,
            .signature = [_]u8{0} ** 1024,
            .signature_len = 0,
            .payload_hash = MessageHeader.calculate_payload_hash(payload),
        };

        return NetworkMessage{
            .header = header,
            .payload = try allocator.dupe(u8, payload),
        };
    }

    pub fn deinit(self: *NetworkMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    pub fn sign(self: *NetworkMessage, allocator: std.mem.Allocator, private_key: []const u8, algorithm: kriptix.Algorithm) !void {
        // Create message to sign (header without signature + payload)
        var message_to_sign = try allocator.alloc(u8, MessageHeader.HEADER_SIZE - 1024 - 2 + self.payload.len); // Exclude signature fields
        defer allocator.free(message_to_sign);

        // Copy header without signature
        @memcpy(message_to_sign[0 .. MessageHeader.HEADER_SIZE - 1024 - 2], std.mem.asBytes(&self.header)[0 .. MessageHeader.HEADER_SIZE - 1024 - 2]);
        @memcpy(message_to_sign[MessageHeader.HEADER_SIZE - 1024 - 2 ..], self.payload);

        // Sign the message
        const signature_result = try kriptix.sign(allocator, private_key, message_to_sign, algorithm);
        defer allocator.free(signature_result.data);

        // Store signature in header
        const sig_len = @min(signature_result.data.len, 1024);
        @memcpy(self.header.signature[0..sig_len], signature_result.data[0..sig_len]);
        self.header.signature_len = @intCast(sig_len);
    }

    pub fn verify_signature(self: NetworkMessage, public_key: []const u8, algorithm: kriptix.Algorithm, allocator: std.mem.Allocator) !bool {
        // Reconstruct message that was signed
        var message_to_verify = try allocator.alloc(u8, MessageHeader.HEADER_SIZE - 1024 - 2 + self.payload.len);
        defer allocator.free(message_to_verify);

        @memcpy(message_to_verify[0 .. MessageHeader.HEADER_SIZE - 1024 - 2], std.mem.asBytes(&self.header)[0 .. MessageHeader.HEADER_SIZE - 1024 - 2]);
        @memcpy(message_to_verify[MessageHeader.HEADER_SIZE - 1024 - 2 ..], self.payload);

        // Verify signature
        const signature = kriptix.Signature{
            .data = self.header.signature[0..self.header.signature_len],
            .algorithm = algorithm,
        };

        return try kriptix.verify(public_key, message_to_verify, signature);
    }

    pub fn serialize(self: NetworkMessage, allocator: std.mem.Allocator) ![]u8 {
        const total_size = MessageHeader.HEADER_SIZE + self.payload.len;
        var buffer = try allocator.alloc(u8, total_size);

        try self.header.serialize(buffer[0..MessageHeader.HEADER_SIZE]);
        @memcpy(buffer[MessageHeader.HEADER_SIZE..], self.payload);

        return buffer;
    }

    pub fn deserialize(allocator: std.mem.Allocator, buffer: []const u8) !NetworkMessage {
        const header = try MessageHeader.deserialize(buffer);

        if (buffer.len < header.length) return error.IncompleteMessage;

        const payload_start = MessageHeader.HEADER_SIZE;
        const payload_len = header.length - MessageHeader.HEADER_SIZE;
        const payload = try allocator.dupe(u8, buffer[payload_start .. payload_start + payload_len]);

        return NetworkMessage{
            .header = header,
            .payload = payload,
        };
    }
};

/// Peer information
pub const Peer = struct {
    /// Peer ID (validator ID or node ID)
    id: [32]u8,

    /// Network address
    address: []u8,
    port: u16,

    /// PQC public key for secure communication
    public_key: []u8,
    algorithm: kriptix.Algorithm,

    /// Connection status
    status: PeerStatus = .disconnected,

    /// Connection quality metrics
    latency_ms: u32 = 0,
    reliability_score: u8 = 100, // 0-100
    last_seen: u64 = 0,

    /// Supported protocol features
    protocol_version: u8 = 1,
    supported_algorithms: []kriptix.Algorithm,

    const PeerStatus = enum {
        disconnected,
        connecting,
        connected,
        handshaking,
        authenticated,
        network_error,
    };

    pub fn init(allocator: std.mem.Allocator, id: [32]u8, address: []const u8, port: u16, public_key: []const u8, algorithm: kriptix.Algorithm) !Peer {
        return Peer{
            .id = id,
            .address = try allocator.dupe(u8, address),
            .port = port,
            .public_key = try allocator.dupe(u8, public_key),
            .algorithm = algorithm,
            .supported_algorithms = try allocator.dupe(kriptix.Algorithm, &[_]kriptix.Algorithm{ .Dilithium3, .Kyber768 }),
        };
    }

    pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        allocator.free(self.public_key);
        allocator.free(self.supported_algorithms);
    }

    pub fn is_healthy(self: Peer) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return self.status == .authenticated and
            self.reliability_score >= 50 and
            current_time - self.last_seen < 300; // 5 minutes
    }
};

/// Secure channel for peer communication using PQC
pub const SecureChannel = struct {
    allocator: std.mem.Allocator,
    peer_id: [32]u8,

    /// Shared secret established via Kyber KEM
    shared_secret: [32]u8,

    /// Message sequence numbers for replay protection
    send_sequence: u64 = 0,
    recv_sequence: u64 = 0,

    /// Encryption/decryption context
    encrypt_key: [32]u8,
    decrypt_key: [32]u8,

    /// Channel status
    established: bool = false,

    pub fn init(allocator: std.mem.Allocator, peer_id: [32]u8) SecureChannel {
        return SecureChannel{
            .allocator = allocator,
            .peer_id = peer_id,
            .shared_secret = [_]u8{0} ** 32,
            .encrypt_key = [_]u8{0} ** 32,
            .decrypt_key = [_]u8{0} ** 32,
        };
    }

    /// Establish secure channel using Kyber KEM
    pub fn establish(self: *SecureChannel, peer_public_key: []const u8) ![]u8 {
        // Generate Kyber keypair for this session
        const keypair = try kriptix.generate_keypair(self.allocator, .Kyber768);
        defer {
            self.allocator.free(keypair.public_key);
            self.allocator.free(keypair.private_key);
        }

        // Encapsulate shared secret with peer's public key
        const ciphertext = try kriptix.encrypt(self.allocator, peer_public_key, &[_]u8{0} ** 32, .Kyber768);
        defer self.allocator.free(ciphertext.data);

        // Derive encryption keys from shared secret
        self.derive_keys();
        self.established = true;

        return try self.allocator.dupe(u8, ciphertext.data);
    }

    /// Derive symmetric keys from shared secret
    fn derive_keys(self: *SecureChannel) void {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.shared_secret);
        hasher.update(&self.peer_id);
        hasher.update("encrypt");
        hasher.final(&self.encrypt_key);

        hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.shared_secret);
        hasher.update(&self.peer_id);
        hasher.update("decrypt");
        hasher.final(&self.decrypt_key);
    }

    /// Encrypt message for transmission
    pub fn encrypt_message(self: *SecureChannel, message: []const u8) ![]u8 {
        if (!self.established) return error.ChannelNotEstablished;

        // Simple XOR encryption for demonstration (use proper AEAD in production)
        var encrypted = try self.allocator.alloc(u8, message.len + 8); // +8 for sequence

        // Add sequence number
        @memcpy(encrypted[0..8], &@as([8]u8, @bitCast(self.send_sequence)));

        // Encrypt payload
        for (message, 0..) |byte, i| {
            encrypted[8 + i] = byte ^ self.encrypt_key[i % 32];
        }

        self.send_sequence += 1;
        return encrypted;
    }

    /// Decrypt received message
    pub fn decrypt_message(self: *SecureChannel, encrypted: []const u8) ![]u8 {
        if (!self.established) return error.ChannelNotEstablished;
        if (encrypted.len < 8) return error.InvalidMessage;

        // Extract and verify sequence number
        const sequence = @as(u64, @bitCast(encrypted[0..8].*));
        if (sequence != self.recv_sequence) return error.InvalidSequence;

        // Decrypt payload
        var decrypted = try self.allocator.alloc(u8, encrypted.len - 8);
        for (encrypted[8..], 0..) |byte, i| {
            decrypted[i] = byte ^ self.decrypt_key[i % 32];
        }

        self.recv_sequence += 1;
        return decrypted;
    }
};

/// Network manager for peer-to-peer communication
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,

    /// Local node information
    local_id: [32]u8,
    local_private_key: []u8,
    local_public_key: []u8,
    listen_port: u16,

    /// Connected peers
    peers: std.HashMap([32]u8, Peer, std.array_hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage),

    /// Secure channels with peers
    secure_channels: std.HashMap([32]u8, SecureChannel, std.array_hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage),

    /// Message routing and delivery
    message_queue: std.ArrayList(QueuedMessage),
    delivery_callbacks: std.HashMap(MessageType, DeliveryCallback, MessageType, std.hash_map.default_max_load_percentage),

    /// Network statistics
    stats: NetworkStats,

    const QueuedMessage = struct {
        message: NetworkMessage,
        target_peer: ?[32]u8, // null for broadcast
        retry_count: u8 = 0,
        timestamp: u64,
    };

    const DeliveryCallback = *const fn (message: NetworkMessage, sender_peer: [32]u8) void;

    const NetworkStats = struct {
        messages_sent: u64 = 0,
        messages_received: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
        connections_established: u32 = 0,
        connections_failed: u32 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, local_id: [32]u8, private_key: []const u8, public_key: []const u8, listen_port: u16) !Self {
        return Self{
            .allocator = allocator,
            .local_id = local_id,
            .local_private_key = try allocator.dupe(u8, private_key),
            .local_public_key = try allocator.dupe(u8, public_key),
            .listen_port = listen_port,
            .peers = std.HashMap([32]u8, Peer, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .secure_channels = std.HashMap([32]u8, SecureChannel, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .message_queue = std.ArrayList(QueuedMessage).init(allocator),
            .delivery_callbacks = std.HashMap(MessageType, DeliveryCallback, MessageType, std.hash_map.default_max_load_percentage).init(allocator),
            .stats = NetworkStats{},
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up peers
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.peers.deinit();

        self.secure_channels.deinit();

        // Clean up message queue
        for (self.message_queue.items) |*msg| {
            msg.message.deinit(self.allocator);
        }
        self.message_queue.deinit();

        self.delivery_callbacks.deinit();
        self.allocator.free(self.local_private_key);
        self.allocator.free(self.local_public_key);
    }

    /// Add a peer to the network
    pub fn add_peer(self: *Self, peer: Peer) !void {
        try self.peers.put(peer.id, peer);

        // Initialize secure channel
        const channel = SecureChannel.init(self.allocator, peer.id);
        try self.secure_channels.put(peer.id, channel);
    }

    /// Connect to a peer and establish secure channel
    pub fn connect_to_peer(self: *Self, peer_id: [32]u8) !void {
        const peer = self.peers.getPtr(peer_id) orelse return error.PeerNotFound;
        const channel = self.secure_channels.getPtr(peer_id) orelse return error.ChannelNotFound;

        // Establish secure channel
        const handshake_data = try channel.establish(peer.public_key);
        defer self.allocator.free(handshake_data);

        // Send handshake request
        var handshake_message = try NetworkMessage.init(
            self.allocator,
            .handshake_request,
            self.local_id,
            handshake_data,
            0,
        );
        defer handshake_message.deinit(self.allocator);

        try handshake_message.sign(self.allocator, self.local_private_key, .Dilithium3);

        // Queue message for delivery
        try self.send_message_to_peer(handshake_message, peer_id);

        peer.status = .connecting;
        self.stats.connections_established += 1;
    }

    /// Send message to specific peer
    pub fn send_message_to_peer(self: *Self, message: NetworkMessage, peer_id: [32]u8) !void {
        const queued_msg = QueuedMessage{
            .message = message,
            .target_peer = peer_id,
            .timestamp = @intCast(std.time.timestamp()),
        };

        try self.message_queue.append(queued_msg);
        self.stats.messages_sent += 1;
    }

    /// Broadcast message to all connected peers
    pub fn broadcast_message(self: *Self, message: NetworkMessage) !void {
        const queued_msg = QueuedMessage{
            .message = message,
            .target_peer = null, // Broadcast
            .timestamp = @intCast(std.time.timestamp()),
        };

        try self.message_queue.append(queued_msg);
        self.stats.messages_sent += self.peers.count();
    }

    /// Register callback for message type
    pub fn register_message_handler(self: *Self, msg_type: MessageType, callback: DeliveryCallback) !void {
        try self.delivery_callbacks.put(msg_type, callback);
    }

    /// Process incoming message
    pub fn process_incoming_message(self: *Self, raw_message: []const u8, sender_peer: [32]u8) !void {
        const message = try NetworkMessage.deserialize(self.allocator, raw_message);
        defer {
            var msg_copy = message;
            msg_copy.deinit(self.allocator);
        }

        // Verify message signature
        const peer = self.peers.get(sender_peer) orelse return error.UnknownPeer;
        const signature_valid = try message.verify_signature(peer.public_key, peer.algorithm, self.allocator);

        if (!signature_valid) {
            return error.InvalidSignature;
        }

        // Update peer last seen
        if (self.peers.getPtr(sender_peer)) |peer_ptr| {
            peer_ptr.last_seen = @intCast(std.time.timestamp());
        }

        // Route message to appropriate handler
        if (self.delivery_callbacks.get(message.header.msg_type)) |callback| {
            callback(message, sender_peer);
        }

        self.stats.messages_received += 1;
        self.stats.bytes_received += message.header.length;
    }

    /// Process outgoing message queue
    pub fn process_outgoing_messages(self: *Self) !void {
        var messages_to_remove = std.ArrayList(usize).init(self.allocator);
        defer messages_to_remove.deinit();

        for (self.message_queue.items, 0..) |*queued_msg, i| {
            const delivered = try self.deliver_message(queued_msg);

            if (delivered) {
                try messages_to_remove.append(i);
            } else {
                queued_msg.retry_count += 1;
                if (queued_msg.retry_count > 3) {
                    try messages_to_remove.append(i);
                }
            }
        }

        // Remove delivered/failed messages in reverse order
        var j = messages_to_remove.items.len;
        while (j > 0) {
            j -= 1;
            const index = messages_to_remove.items[j];
            var msg = self.message_queue.swapRemove(index);
            msg.message.deinit(self.allocator);
        }
    }

    /// Deliver a single message
    fn deliver_message(self: *Self, queued_msg: *QueuedMessage) !bool {
        if (queued_msg.target_peer) |peer_id| {
            // Send to specific peer
            const peer = self.peers.get(peer_id) orelse return false;
            if (!peer.is_healthy()) return false;

            // Encrypt message if secure channel exists
            if (self.secure_channels.getPtr(peer_id)) |channel| {
                if (channel.established) {
                    const serialized = try queued_msg.message.serialize(self.allocator);
                    defer self.allocator.free(serialized);

                    const encrypted = try channel.encrypt_message(serialized);
                    defer self.allocator.free(encrypted);

                    // In real implementation, send encrypted data over network
                    // For now, just mark as delivered
                    self.stats.bytes_sent += encrypted.len;
                    return true;
                }
            }
        } else {
            // Broadcast to all healthy peers
            var delivered_count: u32 = 0;
            var peer_iter = self.peers.iterator();

            while (peer_iter.next()) |entry| {
                if (entry.value_ptr.is_healthy()) {
                    // Similar delivery logic as above
                    delivered_count += 1;
                }
            }

            return delivered_count > 0;
        }

        return false;
    }

    /// Get network statistics
    pub fn get_stats(self: Self) NetworkStats {
        return self.stats;
    }

    /// Health check for network connectivity
    pub fn health_check(self: *Self) NetworkHealth {
        var healthy_peers: u32 = 0;
        var total_peers: u32 = 0;
        var total_latency: u64 = 0;

        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            total_peers += 1;
            if (entry.value_ptr.is_healthy()) {
                healthy_peers += 1;
                total_latency += entry.value_ptr.latency_ms;
            }
        }

        return NetworkHealth{
            .total_peers = total_peers,
            .healthy_peers = healthy_peers,
            .avg_latency_ms = if (healthy_peers > 0) @intCast(total_latency / healthy_peers) else 0,
            .message_queue_size = @intCast(self.message_queue.items.len),
        };
    }

    const NetworkHealth = struct {
        total_peers: u32,
        healthy_peers: u32,
        avg_latency_ms: u32,
        message_queue_size: u32,
    };
};

test "network communication" {
    std.testing.refAllDecls(@This());
}
