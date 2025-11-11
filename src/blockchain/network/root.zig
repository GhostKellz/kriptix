//! Comprehensive P2P Network & Communication Layer for Kriptix Blockchain
//!
//! This module provides a complete peer-to-peer networking solution for blockchain
//! nodes, including node discovery, gossip protocols, secure communication,
//! and network health monitoring using post-quantum cryptography.

const std = @import("std");
const kriptix = @import("../../root.zig");

// Re-export network components
pub const discovery = @import("discovery.zig");
pub const gossip = @import("gossip.zig");
pub const transport = @import("transport.zig");
pub const auth = @import("auth.zig");
pub const monitoring = @import("monitoring.zig");
pub const p2p = @import("p2p.zig");

/// Network configuration for blockchain nodes
pub const NetworkConfig = struct {
    /// Node identification
    node_id: [32]u8,

    /// Network parameters
    listen_port: u16 = 8333,
    max_peers: u32 = 125,
    max_inbound_peers: u32 = 64,
    max_outbound_peers: u32 = 61,

    /// Bootstrap nodes for initial peer discovery
    bootstrap_nodes: []const BootstrapNode,

    /// Protocol configuration
    protocol_version: u32 = 1,
    network_magic: u32 = 0xD9B4BEF9, // Kriptix network magic

    /// Security settings
    require_authentication: bool = true,
    enable_encryption: bool = true,
    signature_algorithm: kriptix.Algorithm = .Dilithium3,
    kem_algorithm: kriptix.Algorithm = .Kyber768,

    /// Performance tuning
    connection_timeout_ms: u32 = 5000,
    heartbeat_interval_ms: u32 = 30000,
    message_timeout_ms: u32 = 10000,

    /// Gossip protocol settings
    gossip_fanout: u8 = 6,
    gossip_interval_ms: u32 = 1000,

    /// Network health monitoring
    enable_monitoring: bool = true,
    metrics_collection_interval_ms: u32 = 5000,

    pub const BootstrapNode = struct {
        address: []const u8,
        port: u16,
        public_key: ?[]const u8 = null,
    };
};

/// Network layer errors
pub const NetworkError = error{
    // Connection errors
    ConnectionFailed,
    ConnectionTimeout,
    PeerNotFound,
    MaxPeersReached,

    // Authentication errors
    AuthenticationFailed,
    InvalidCredentials,
    UntrustedPeer,

    // Protocol errors
    ProtocolMismatch,
    InvalidMessage,
    MessageTimeout,

    // Encryption errors
    EncryptionFailed,
    DecryptionFailed,
    KeyExchangeFailed,

    // General errors
    NetworkNotInitialized,
    ResourceExhausted,
    InternalError,
};

/// Main network layer coordinator
pub const NetworkLayer = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,

    /// Core network components
    p2p_manager: p2p.P2PManager,
    discovery_service: discovery.DiscoveryService,
    gossip_protocol: gossip.GossipProtocol,
    transport_layer: transport.TransportLayer,
    auth_manager: auth.AuthManager,
    monitor: monitoring.NetworkMonitor,

    /// Network state
    is_running: bool = false,
    local_keys: LocalKeys,

    const LocalKeys = struct {
        private_key: []u8,
        public_key: []u8,
        algorithm: kriptix.Algorithm,
    };

    const Self = @This();

    /// Initialize the network layer with configuration
    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !Self {
        // Generate local keypair for node identity
        const keypair = try kriptix.generate_keypair(allocator, config.signature_algorithm);

        // Initialize core components
        const p2p_manager = try p2p.P2PManager.init(allocator, config);
        const discovery_service = try discovery.DiscoveryService.init(allocator, config);
        const gossip_protocol = try gossip.GossipProtocol.init(allocator, config);
        const transport_layer = try transport.TransportLayer.init(allocator, config);
        const auth_manager = try auth.AuthManager.init(allocator, config);
        const monitor = try monitoring.NetworkMonitor.init(allocator, config);

        return Self{
            .allocator = allocator,
            .config = config,
            .p2p_manager = p2p_manager,
            .discovery_service = discovery_service,
            .gossip_protocol = gossip_protocol,
            .transport_layer = transport_layer,
            .auth_manager = auth_manager,
            .monitor = monitor,
            .local_keys = LocalKeys{
                .private_key = keypair.private_key,
                .public_key = keypair.public_key,
                .algorithm = config.signature_algorithm,
            },
        };
    }

    /// Clean up network layer resources
    pub fn deinit(self: *Self) void {
        if (self.is_running) {
            self.stop() catch {};
        }

        self.p2p_manager.deinit();
        self.discovery_service.deinit();
        self.gossip_protocol.deinit();
        self.transport_layer.deinit();
        self.auth_manager.deinit();
        self.monitor.deinit();

        self.allocator.free(self.local_keys.private_key);
        self.allocator.free(self.local_keys.public_key);
    }

    /// Start the network layer
    pub fn start(self: *Self) !void {
        if (self.is_running) return;

        std.log.info("Starting Kriptix Network Layer...", .{});

        // Start core services in order
        try self.transport_layer.start();
        try self.auth_manager.start();
        try self.discovery_service.start();
        try self.p2p_manager.start();
        try self.gossip_protocol.start();

        if (self.config.enable_monitoring) {
            try self.monitor.start();
        }

        self.is_running = true;
        std.log.info("Network Layer started successfully on port {}", .{self.config.listen_port});
    }

    /// Stop the network layer
    pub fn stop(self: *Self) !void {
        if (!self.is_running) return;

        std.log.info("Stopping Kriptix Network Layer...", .{});

        // Stop services in reverse order
        if (self.config.enable_monitoring) {
            try self.monitor.stop();
        }

        try self.gossip_protocol.stop();
        try self.p2p_manager.stop();
        try self.discovery_service.stop();
        try self.auth_manager.stop();
        try self.transport_layer.stop();

        self.is_running = false;
        std.log.info("Network Layer stopped", .{});
    }

    /// Connect to the network using bootstrap nodes
    pub fn connect_to_network(self: *Self) !void {
        if (!self.is_running) return NetworkError.NetworkNotInitialized;

        std.log.info("Connecting to Kriptix network...", .{});

        // Start peer discovery
        try self.discovery_service.discover_peers();

        // Wait for initial peer connections
        const max_wait_time = 30; // seconds
        var wait_time: u32 = 0;

        while (wait_time < max_wait_time) {
            const peer_count = self.p2p_manager.get_peer_count();
            if (peer_count > 0) {
                std.log.info("Connected to {} peers", .{peer_count});
                return;
            }

            std.time.sleep(1_000_000_000); // 1 second
            wait_time += 1;
        }

        return NetworkError.ConnectionTimeout;
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(self: *Self, peer_id: [32]u8, message_type: u8, payload: []const u8) !void {
        if (!self.is_running) return NetworkError.NetworkNotInitialized;

        try self.p2p_manager.send_message(peer_id, message_type, payload);
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(self: *Self, message_type: u8, payload: []const u8) !void {
        if (!self.is_running) return NetworkError.NetworkNotInitialized;

        try self.gossip_protocol.broadcast_message(message_type, payload);
    }

    /// Register a message handler for incoming messages
    pub fn register_message_handler(self: *Self, message_type: u8, handler: p2p.MessageHandler) !void {
        try self.p2p_manager.register_handler(message_type, handler);
    }

    /// Get current network status
    pub fn get_network_status(self: Self) NetworkStatus {
        return NetworkStatus{
            .is_running = self.is_running,
            .peer_count = self.p2p_manager.get_peer_count(),
            .connected_peers = self.p2p_manager.get_connected_peer_count(),
            .pending_connections = self.p2p_manager.get_pending_connection_count(),
            .network_health = self.monitor.get_health_score(),
            .bytes_sent = self.monitor.get_bytes_sent(),
            .bytes_received = self.monitor.get_bytes_received(),
            .messages_sent = self.monitor.get_messages_sent(),
            .messages_received = self.monitor.get_messages_received(),
        };
    }

    /// Get detailed network metrics
    pub fn get_network_metrics(self: Self) monitoring.NetworkMetrics {
        return self.monitor.get_metrics();
    }

    /// Perform network maintenance tasks
    pub fn maintenance(self: *Self) !void {
        if (!self.is_running) return;

        // Perform periodic maintenance
        try self.p2p_manager.cleanup_stale_connections();
        try self.discovery_service.refresh_peer_list();
        try self.gossip_protocol.cleanup_old_messages();

        if (self.config.enable_monitoring) {
            try self.monitor.collect_metrics();
        }
    }

    const NetworkStatus = struct {
        is_running: bool,
        peer_count: u32,
        connected_peers: u32,
        pending_connections: u32,
        network_health: u8, // 0-100
        bytes_sent: u64,
        bytes_received: u64,
        messages_sent: u64,
        messages_received: u64,
    };
};

/// Network event types for external handling
pub const NetworkEvent = union(enum) {
    peer_connected: PeerConnectedEvent,
    peer_disconnected: PeerDisconnectedEvent,
    message_received: MessageReceivedEvent,
    network_error: NetworkErrorEvent,

    const PeerConnectedEvent = struct {
        peer_id: [32]u8,
        peer_info: p2p.PeerInfo,
    };

    const PeerDisconnectedEvent = struct {
        peer_id: [32]u8,
        reason: []const u8,
    };

    const MessageReceivedEvent = struct {
        sender: [32]u8,
        message_type: u8,
        payload: []const u8,
    };

    const NetworkErrorEvent = struct {
        error_type: NetworkError,
        description: []const u8,
    };
};

/// Event handler callback type
pub const EventHandler = *const fn (event: NetworkEvent) void;

test "network layer initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = NetworkConfig{
        .node_id = [_]u8{1} ** 32,
        .listen_port = 8333,
        .bootstrap_nodes = &[_]NetworkConfig.BootstrapNode{},
    };

    var network = try NetworkLayer.init(allocator, config);
    defer network.deinit();

    const status = network.get_network_status();
    std.testing.expect(!status.is_running) catch unreachable;
}
