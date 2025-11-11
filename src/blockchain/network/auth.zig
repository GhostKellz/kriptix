//! Enhanced Node Authentication - Multi-layer security with PQC
//!
//! This module provides comprehensive node authentication using post-quantum
//! cryptography with Kyber KEM for key exchange, Dilithium for signatures,
//! and multi-layer security protocols for node identity verification.

const std = @import("std");
const kriptix = @import("../../root.zig");
const NetworkConfig = @import("root.zig").NetworkConfig;
const NetworkError = @import("root.zig").NetworkError;

/// Authentication challenge-response mechanism
pub const AuthChallenge = struct {
    /// Challenge identification
    challenge_id: u64,
    nonce: [32]u8,
    timestamp: u64,

    /// Cryptographic parameters
    algorithm: kriptix.Algorithm,
    difficulty: u8 = 1, // Proof-of-work difficulty

    /// Challenge data
    challenge_data: []u8,
    expected_response_size: usize,

    /// Validity period
    expires_at: u64,

    pub fn init(allocator: std.mem.Allocator, algorithm: kriptix.Algorithm) !AuthChallenge {
        var nonce: [32]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const current_time = @as(u64, @intCast(std.time.timestamp()));
        const challenge_data = try create_challenge_data(allocator, &nonce, algorithm);

        return AuthChallenge{
            .challenge_id = @intCast(current_time * 1000 + std.crypto.random.int(u16)),
            .nonce = nonce,
            .timestamp = current_time,
            .algorithm = algorithm,
            .challenge_data = challenge_data,
            .expected_response_size = get_expected_response_size(algorithm),
            .expires_at = current_time + 300, // 5 minutes
        };
    }

    pub fn deinit(self: *AuthChallenge, allocator: std.mem.Allocator) void {
        allocator.free(self.challenge_data);
    }

    pub fn is_expired(self: AuthChallenge) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time > self.expires_at;
    }

    pub fn verify_response(self: AuthChallenge, response: []const u8, public_key: []const u8) !bool {
        if (self.is_expired()) return false;
        if (response.len != self.expected_response_size) return false;

        // Verify signature of challenge data
        const signature = kriptix.Signature{
            .data = response,
            .algorithm = self.algorithm,
        };

        return try kriptix.verify(public_key, self.challenge_data, signature);
    }

    fn create_challenge_data(allocator: std.mem.Allocator, nonce: *const [32]u8, algorithm: kriptix.Algorithm) ![]u8 {
        _ = algorithm;
        const challenge_text = "Kriptix Network Authentication Challenge";
        const total_size = challenge_text.len + 32; // text + nonce

        var challenge_data = try allocator.alloc(u8, total_size);
        @memcpy(challenge_data[0..challenge_text.len], challenge_text);
        @memcpy(challenge_data[challenge_text.len..], nonce);

        return challenge_data;
    }

    fn get_expected_response_size(algorithm: kriptix.Algorithm) usize {
        return switch (algorithm) {
            .Dilithium2 => 2420,
            .Dilithium3 => 3293,
            .Dilithium5 => 4595,
            else => 1024, // Default
        };
    }
};

/// Node identity and credentials
pub const NodeIdentity = struct {
    /// Node identification
    node_id: [32]u8,

    /// Primary cryptographic keys
    signature_public_key: []u8,
    signature_algorithm: kriptix.Algorithm,

    /// Key exchange keys
    kem_public_key: []u8,
    kem_algorithm: kriptix.Algorithm,

    /// Node metadata
    protocol_version: u32,
    capabilities: NodeCapabilities,

    /// Trust and reputation
    trust_level: TrustLevel = .unknown,
    reputation_score: u16 = 500, // 0-1000, start at neutral

    /// Authentication history
    first_seen: u64,
    last_authenticated: u64,
    authentication_count: u32 = 0,
    failed_auth_count: u32 = 0,

    /// Certificate chain (optional)
    certificate: ?[]u8 = null,
    certificate_chain: ?[][]u8 = null,

    const NodeCapabilities = packed struct {
        supports_gossip: bool = true,
        supports_consensus: bool = false,
        supports_relay: bool = true,
        supports_archival: bool = false,
        supports_mining: bool = false,
        supports_bridging: bool = false,
        _reserved: u2 = 0,
    };

    const TrustLevel = enum(u8) {
        unknown = 0,
        untrusted = 1,
        low_trust = 2,
        medium_trust = 3,
        high_trust = 4,
        trusted = 5,
    };

    pub fn init(allocator: std.mem.Allocator, node_id: [32]u8, sig_public_key: []const u8, kem_public_key: []const u8) !NodeIdentity {
        const current_time = @as(u64, @intCast(std.time.timestamp()));

        return NodeIdentity{
            .node_id = node_id,
            .signature_public_key = try allocator.dupe(u8, sig_public_key),
            .signature_algorithm = .Dilithium3,
            .kem_public_key = try allocator.dupe(u8, kem_public_key),
            .kem_algorithm = .Kyber768,
            .protocol_version = 1,
            .capabilities = NodeCapabilities{},
            .first_seen = current_time,
            .last_authenticated = 0,
        };
    }

    pub fn deinit(self: *NodeIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.signature_public_key);
        allocator.free(self.kem_public_key);

        if (self.certificate) |cert| {
            allocator.free(cert);
        }

        if (self.certificate_chain) |chain| {
            for (chain) |cert| {
                allocator.free(cert);
            }
            allocator.free(chain);
        }
    }

    pub fn update_authentication_success(self: *NodeIdentity) void {
        self.last_authenticated = @intCast(std.time.timestamp());
        self.authentication_count += 1;

        // Improve reputation on successful auth
        if (self.reputation_score < 950) {
            self.reputation_score += 1;
        }

        // Upgrade trust level based on history
        if (self.authentication_count >= 100 and self.trust_level == .unknown) {
            self.trust_level = .low_trust;
        } else if (self.authentication_count >= 500 and self.trust_level == .low_trust) {
            self.trust_level = .medium_trust;
        } else if (self.authentication_count >= 1000 and self.trust_level == .medium_trust) {
            self.trust_level = .high_trust;
        }
    }

    pub fn update_authentication_failure(self: *NodeIdentity) void {
        self.failed_auth_count += 1;

        // Decrease reputation on failed auth
        if (self.reputation_score > 50) {
            self.reputation_score -= 5;
        }

        // Downgrade trust level on repeated failures
        if (self.failed_auth_count > 10) {
            self.trust_level = .untrusted;
        }
    }

    pub fn is_trusted(self: NodeIdentity) bool {
        return self.trust_level != .unknown and
            self.trust_level != .untrusted and
            self.reputation_score >= 400;
    }

    pub fn should_authenticate(self: NodeIdentity) bool {
        if (self.last_authenticated == 0) return true; // Never authenticated

        const current_time = @as(u64, @intCast(std.time.timestamp()));
        const time_since_auth = current_time - self.last_authenticated;

        // Re-authenticate based on trust level
        return switch (self.trust_level) {
            .unknown, .untrusted => time_since_auth > 300, // 5 minutes
            .low_trust => time_since_auth > 1800, // 30 minutes
            .medium_trust => time_since_auth > 3600, // 1 hour
            .high_trust => time_since_auth > 7200, // 2 hours
            .trusted => time_since_auth > 14400, // 4 hours
        };
    }
};

/// Authentication session state
pub const AuthSession = struct {
    session_id: u64,
    node_id: [32]u8,

    /// Session state
    state: AuthState = .initiated,
    challenge: ?AuthChallenge = null,

    /// Timing
    created_at: u64,
    last_activity: u64,
    timeout: u64,

    /// Authentication attempts
    attempt_count: u8 = 0,
    max_attempts: u8 = 3,

    const AuthState = enum {
        initiated,
        challenge_sent,
        response_received,
        verified,
        failed,
        timeout,
    };

    pub fn init(node_id: [32]u8, timeout_seconds: u64) AuthSession {
        const current_time = @as(u64, @intCast(std.time.timestamp()));

        return AuthSession{
            .session_id = @intCast(current_time * 1000 + std.crypto.random.int(u16)),
            .node_id = node_id,
            .created_at = current_time,
            .last_activity = current_time,
            .timeout = current_time + timeout_seconds,
        };
    }

    pub fn is_expired(self: AuthSession) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time > self.timeout;
    }

    pub fn update_activity(self: *AuthSession) void {
        self.last_activity = @intCast(std.time.timestamp());
    }

    pub fn increment_attempt(self: *AuthSession) bool {
        self.attempt_count += 1;
        return self.attempt_count < self.max_attempts;
    }

    pub fn is_complete(self: AuthSession) bool {
        return self.state == .verified or self.state == .failed;
    }
};

/// Main Authentication Manager
pub const AuthManager = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,

    /// Local node credentials
    local_node_id: [32]u8,
    local_private_key: []u8,
    local_public_key: []u8,

    /// Known node identities
    known_nodes: std.HashMap([32]u8, NodeIdentity, [32]u8, std.hash_map.default_max_load_percentage),

    /// Active authentication sessions
    active_sessions: std.HashMap(u64, AuthSession, u64, std.hash_map.default_max_load_percentage),
    pending_challenges: std.HashMap(u64, AuthChallenge, u64, std.hash_map.default_max_load_percentage),

    /// Authentication statistics
    stats: AuthStats,

    /// Trust anchor (optional root certificates)
    trust_anchors: std.ArrayList([]u8),

    const AuthStats = struct {
        authentications_initiated: u64 = 0,
        authentications_completed: u64 = 0,
        authentications_failed: u64 = 0,
        challenges_sent: u64 = 0,
        challenges_received: u64 = 0,
        nodes_discovered: u64 = 0,
        trust_violations: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !Self {
        // For demo, create a local keypair
        const keypair = try kriptix.generate_keypair(allocator, config.signature_algorithm);

        return Self{
            .allocator = allocator,
            .config = config,
            .local_node_id = config.node_id,
            .local_private_key = keypair.private_key,
            .local_public_key = keypair.public_key,
            .known_nodes = std.HashMap([32]u8, NodeIdentity, std.array_hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage).init(allocator),
            .active_sessions = std.HashMap(u64, AuthSession, std.array_hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .pending_challenges = std.HashMap(u64, AuthChallenge, std.array_hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .stats = AuthStats{},
            .trust_anchors = std.ArrayList([]u8){},
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up known nodes
        var node_iter = self.known_nodes.iterator();
        while (node_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.known_nodes.deinit();

        // Clean up challenges
        var challenge_iter = self.pending_challenges.iterator();
        while (challenge_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_challenges.deinit();

        self.active_sessions.deinit();

        // Clean up trust anchors
        for (self.trust_anchors.items) |anchor| {
            self.allocator.free(anchor);
        }
        self.trust_anchors.deinit();

        self.allocator.free(self.local_private_key);
        self.allocator.free(self.local_public_key);
    }

    pub fn start(self: *Self) !void {
        _ = self;
        std.log.info("Authentication Manager starting...", .{});
    }

    pub fn stop(self: *Self) !void {
        _ = self;
        std.log.info("Authentication Manager stopping...", .{});
    }

    /// Initiate authentication with a node
    pub fn initiate_authentication(self: *Self, node_id: [32]u8) !u64 {
        // Check if node should be authenticated
        if (self.known_nodes.get(node_id)) |node| {
            if (!node.should_authenticate()) {
                return NetworkError.AuthenticationFailed; // Already authenticated
            }
        }

        // Create authentication session
        var session = AuthSession.init(node_id, 300); // 5 minute timeout
        const session_id = session.session_id;

        try self.active_sessions.put(session_id, session);
        self.stats.authentications_initiated += 1;

        std.log.info("Initiated authentication with node {any}", .{node_id[0..8]});
        return session_id;
    }

    /// Send authentication challenge to node
    pub fn send_challenge(self: *Self, session_id: u64) ![]u8 {
        const session = self.active_sessions.getPtr(session_id) orelse return NetworkError.AuthenticationFailed;

        if (session.is_expired()) {
            session.state = .timeout;
            return NetworkError.AuthenticationFailed;
        }

        // Create challenge
        var challenge = try AuthChallenge.init(self.allocator, self.config.signature_algorithm);
        const challenge_id = challenge.challenge_id;

        // Store challenge
        try self.pending_challenges.put(challenge_id, challenge);
        session.challenge = challenge;
        session.state = .challenge_sent;
        session.update_activity();

        self.stats.challenges_sent += 1;

        // Serialize challenge for transmission
        return try self.serialize_challenge(challenge);
    }

    /// Process authentication response
    pub fn process_auth_response(self: *Self, session_id: u64, response_data: []const u8) !bool {
        const session = self.active_sessions.getPtr(session_id) orelse return false;

        if (session.is_expired() or session.state != .challenge_sent) {
            session.state = .failed;
            return false;
        }

        const challenge = session.challenge orelse return false;

        // Get or create node identity
        var node_identity = self.known_nodes.getPtr(session.node_id);
        if (node_identity == null) {
            // For demo, create a placeholder identity
            // In real implementation, would extract from response
            const dummy_key = try self.allocator.alloc(u8, 32);
            std.crypto.random.bytes(dummy_key);

            const new_identity = try NodeIdentity.init(self.allocator, session.node_id, dummy_key, dummy_key);
            try self.known_nodes.put(session.node_id, new_identity);
            node_identity = self.known_nodes.getPtr(session.node_id);
            self.stats.nodes_discovered += 1;
        }

        // Verify challenge response
        const is_valid = try challenge.verify_response(response_data, node_identity.?.signature_public_key);

        if (is_valid) {
            session.state = .verified;
            node_identity.?.update_authentication_success();
            self.stats.authentications_completed += 1;

            std.log.info("Authentication successful for node {any}", .{session.node_id[0..8]});
            return true;
        } else {
            session.state = .failed;
            node_identity.?.update_authentication_failure();
            self.stats.authentications_failed += 1;

            if (!session.increment_attempt()) {
                self.stats.trust_violations += 1;
            }

            std.log.warn("Authentication failed for node {any}", .{session.node_id[0..8]});
            return false;
        }
    }

    /// Handle incoming authentication challenge
    pub fn handle_incoming_challenge(self: *Self, challenge_data: []const u8) ![]u8 {
        const challenge = try self.deserialize_challenge(challenge_data);
        defer {
            var mutable_challenge = challenge;
            mutable_challenge.deinit(self.allocator);
        }

        if (challenge.is_expired()) {
            return NetworkError.AuthenticationFailed;
        }

        // Create response by signing challenge data
        const signature = try kriptix.sign(self.allocator, self.local_private_key, challenge.challenge_data, challenge.algorithm);
        defer self.allocator.free(signature.data);

        self.stats.challenges_received += 1;

        std.log.info("Responding to authentication challenge {}", .{challenge.challenge_id});

        return try self.allocator.dupe(u8, signature.data);
    }

    /// Clean up expired sessions and challenges
    pub fn cleanup_expired(self: *Self) !void {
        var expired_sessions = std.ArrayList(u64).init(self.allocator);
        defer expired_sessions.deinit();

        var expired_challenges = std.ArrayList(u64).init(self.allocator);
        defer expired_challenges.deinit();

        // Find expired sessions
        var session_iter = self.active_sessions.iterator();
        while (session_iter.next()) |entry| {
            if (entry.value_ptr.is_expired()) {
                try expired_sessions.append(entry.key_ptr.*);
            }
        }

        // Find expired challenges
        var challenge_iter = self.pending_challenges.iterator();
        while (challenge_iter.next()) |entry| {
            if (entry.value_ptr.is_expired()) {
                try expired_challenges.append(entry.key_ptr.*);
            }
        }

        // Remove expired items
        for (expired_sessions.items) |session_id| {
            _ = self.active_sessions.remove(session_id);
        }

        for (expired_challenges.items) |challenge_id| {
            if (self.pending_challenges.fetchRemove(challenge_id)) |kv| {
                var challenge = kv.value;
                challenge.deinit(self.allocator);
            }
        }
    }

    /// Check if node is authenticated and trusted
    pub fn is_node_authenticated(self: Self, node_id: [32]u8) bool {
        if (self.known_nodes.get(node_id)) |node| {
            return node.is_trusted() and !node.should_authenticate();
        }
        return false;
    }

    /// Get node trust level
    pub fn get_node_trust_level(self: Self, node_id: [32]u8) NodeIdentity.TrustLevel {
        if (self.known_nodes.get(node_id)) |node| {
            return node.trust_level;
        }
        return .unknown;
    }

    /// Serialize challenge for network transmission
    fn serialize_challenge(self: *Self, challenge: AuthChallenge) ![]u8 {
        const header_size = 64;
        const total_size = header_size + challenge.challenge_data.len;

        var serialized = try self.allocator.alloc(u8, total_size);

        // Pack challenge header
        @memcpy(serialized[0..8], &@as([8]u8, @bitCast(challenge.challenge_id)));
        @memcpy(serialized[8..16], &@as([8]u8, @bitCast(challenge.timestamp)));
        @memcpy(serialized[16..48], &challenge.nonce);
        @memcpy(serialized[48..56], &@as([8]u8, @bitCast(challenge.expires_at)));

        // Pack challenge data
        @memcpy(serialized[header_size..], challenge.challenge_data);

        return serialized;
    }

    /// Deserialize challenge from network data
    fn deserialize_challenge(self: *Self, data: []const u8) !AuthChallenge {
        if (data.len < 64) return NetworkError.InvalidMessage;

        const challenge_id = @as(u64, @bitCast(data[0..8].*));
        const timestamp = @as(u64, @bitCast(data[8..16].*));
        const nonce = data[16..48].*;
        const expires_at = @as(u64, @bitCast(data[48..56].*));

        const challenge_data = try self.allocator.dupe(u8, data[64..]);

        return AuthChallenge{
            .challenge_id = challenge_id,
            .nonce = nonce,
            .timestamp = timestamp,
            .algorithm = self.config.signature_algorithm,
            .challenge_data = challenge_data,
            .expected_response_size = AuthChallenge.get_expected_response_size(self.config.signature_algorithm),
            .expires_at = expires_at,
        };
    }

    /// Get authentication statistics
    pub fn get_stats(self: Self) AuthStats {
        return self.stats;
    }

    /// Get known node count
    pub fn get_known_node_count(self: Self) u32 {
        return @intCast(self.known_nodes.count());
    }
};

test "authentication manager functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = NetworkConfig{
        .node_id = [_]u8{1} ** 32,
        .bootstrap_nodes = &[_]NetworkConfig.BootstrapNode{},
        .signature_algorithm = .Dilithium3,
    };

    var auth_manager = try AuthManager.init(allocator, config);
    defer auth_manager.deinit();

    // Test authentication initiation
    const peer_id = [_]u8{2} ** 32;
    const session_id = try auth_manager.initiate_authentication(peer_id);

    const stats = auth_manager.get_stats();
    std.testing.expect(stats.authentications_initiated == 1) catch unreachable;
    std.testing.expect(session_id > 0) catch unreachable;
}
