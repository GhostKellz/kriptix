//! Transport Layer - Low-level network communication
//!
//! This module handles the transport layer for network communications
//! including TCP/UDP sockets, connection management, and data serialization.

const std = @import("std");
const NetworkConfig = @import("root.zig").NetworkConfig;
const NetworkError = @import("root.zig").NetworkError;

/// Connection states for managing socket lifecycle
const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    error_state,
};

/// Network connection representation
pub const Connection = struct {
    allocator: std.mem.Allocator,
    socket: ?std.net.Stream = null,
    address: struct { ip: [4]u8, port: u16 },
    state: ConnectionState = .disconnected,

    /// Connection metadata
    connect_time: i64 = 0,
    last_activity: i64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    /// Connection buffers
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, address: std.net.Address) Connection {
        // Convert std.net.Address to our struct format
        const addr_struct = switch (address.any.family) {
            std.os.AF.INET => .{
                .ip = address.in.sa.addr,
                .port = std.mem.nativeToBig(u16, address.in.getPort()),
            },
            else => .{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = 8080 }, // fallback
        };

        return Connection{
            .allocator = allocator,
            .address = addr_struct,
            .send_buffer = std.ArrayList(u8){},
            .recv_buffer = std.ArrayList(u8){},
        };
    }

    pub fn deinit(self: *Connection) void {
        if (self.socket) |socket| {
            socket.close();
        }
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
    }

    /// Establish connection to remote address (simplified for demo)
    pub fn connect(self: *Connection) !void {
        self.state = .connecting;

        // For demo purposes, simulate connection
        // In real implementation, would use std.net.tcpConnectToAddress
        self.state = .connected;
        self.connect_time = @intCast(std.time.milliTimestamp());
        self.last_activity = self.connect_time;
    }

    /// Send data through the connection (simplified for demo)
    pub fn send(self: *Connection, data: []const u8) !usize {
        if (self.state != .connected) {
            return NetworkError.ConnectionFailed;
        }

        // For demo purposes, simulate sending data
        // In real implementation, would use socket.writeAll(data)
        self.bytes_sent += data.len;
        self.last_activity = @intCast(std.time.milliTimestamp());

        return data.len;
    }

    /// Receive data from the connection (simplified for demo)
    pub fn receive(self: *Connection, buffer: []u8) !usize {
        if (self.state != .connected) {
            return NetworkError.ConnectionFailed;
        }

        // For demo purposes, simulate receiving data
        // In real implementation, would use socket.readAll(buffer)
        const mock_data = "mock_network_data";
        const bytes_to_copy = @min(buffer.len, mock_data.len);
        @memcpy(buffer[0..bytes_to_copy], mock_data[0..bytes_to_copy]);

        self.bytes_received += bytes_to_copy;
        self.last_activity = @intCast(std.time.milliTimestamp());

        return bytes_to_copy;
    }

    /// Close the connection
    pub fn close(self: *Connection) void {
        if (self.socket) |socket| {
            socket.close();
            self.socket = null;
        }
        self.state = .disconnected;
    }

    pub fn is_connected(self: Connection) bool {
        return self.state == .connected and self.socket != null;
    }
};

/// Main transport layer implementation
pub const TransportLayer = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,

    /// Server socket for incoming connections
    server_address: ?struct { ip: [4]u8, port: u16 } = null,

    /// Active connections
    connections: std.ArrayList(Connection),

    /// Transport statistics
    stats: TransportStats,

    /// Control flags
    is_running: bool = false,
    should_stop: bool = false,

    const TransportStats = struct {
        connections_accepted: u32 = 0,
        connections_initiated: u32 = 0,
        connections_failed: u32 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
        errors: u32 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !TransportLayer {
        return TransportLayer{
            .allocator = allocator,
            .config = config,
            .connections = std.ArrayList(Connection).init(allocator),
            .stats = TransportStats{},
        };
    }

    pub fn deinit(self: *TransportLayer) void {
        // Close all connections
        for (self.connections.items) |*conn| {
            conn.deinit();
        }
        self.connections.deinit();

        // Reset server address
        self.server_address = null;
    }

    pub fn start(self: *TransportLayer) !void {
        std.log.info("Transport Layer starting on port {}...", .{self.config.listen_port});

        // Set up server address for listening
        self.server_address = .{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = self.config.listen_port };

        self.is_running = true;
        self.should_stop = false;

        std.log.info("Transport Layer configured for {}", .{self.server_address.?});
    }

    pub fn stop(self: *TransportLayer) !void {
        std.log.info("Transport Layer stopping...", .{});

        self.should_stop = true;

        // Close all active connections
        for (self.connections.items) |*conn| {
            conn.close();
        }

        // Reset server address
        self.server_address = null;

        self.is_running = false;
        std.log.info("Transport Layer stopped");
    }

    /// Accept incoming connections (simplified for demo)
    pub fn accept_connection(self: *TransportLayer) !?Connection {
        if (self.server_address == null or !self.is_running) {
            return null;
        }

        // For demo purposes, simulate accepting a connection
        // In real implementation, would use actual socket accept
        self.stats.connections_accepted += 1;

        // Create mock connection
        const mock_address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 12345);
        var connection = Connection.init(self.allocator, mock_address);
        connection.state = .connected;
        connection.connect_time = @intCast(std.time.milliTimestamp());
        connection.last_activity = connection.connect_time;

        try self.connections.append(connection);

        std.log.info("Simulated connection accepted from {}", .{mock_address});
        return &self.connections.items[self.connections.items.len - 1];
    }

    /// Initiate outbound connection
    pub fn connect_to(self: *TransportLayer, address: std.net.Address) !*Connection {
        var connection = Connection.init(self.allocator, address);

        try connection.connect();
        try self.connections.append(connection);

        self.stats.connections_initiated += 1;
        std.log.info("Connected to {}", .{address});

        return &self.connections.items[self.connections.items.len - 1];
    }

    /// Send data to specific connection
    pub fn send_data(self: *TransportLayer, connection: *Connection, data: []const u8) !void {
        const bytes_sent = try connection.send(data);
        self.stats.bytes_sent += bytes_sent;
    }

    /// Receive data from connection
    pub fn receive_data(self: *TransportLayer, connection: *Connection, buffer: []u8) !usize {
        const bytes_received = try connection.receive(buffer);
        self.stats.bytes_received += bytes_received;
        return bytes_received;
    }

    /// Process all active connections (maintenance)
    pub fn process_connections(self: *TransportLayer) !void {
        var connections_to_remove = std.ArrayList(usize).init(self.allocator);
        defer connections_to_remove.deinit();

        const current_time = std.time.timestamp();

        // Check each connection for health
        for (self.connections.items, 0..) |*conn, i| {
            if (!conn.is_connected()) {
                try connections_to_remove.append(i);
                continue;
            }

            // Check for timeout (5 minutes of inactivity)
            if (current_time - conn.last_activity > 300) {
                std.log.info("Connection timeout for {}", .{conn.address});
                conn.close();
                try connections_to_remove.append(i);
            }
        }

        // Remove dead connections in reverse order
        var j = connections_to_remove.items.len;
        while (j > 0) {
            j -= 1;
            const index = connections_to_remove.items[j];
            var conn = self.connections.swapRemove(index);
            conn.deinit();
        }
    }

    /// Get connection count
    pub fn get_connection_count(self: TransportLayer) u32 {
        return @intCast(self.connections.items.len);
    }

    /// Get transport statistics
    pub fn get_stats(self: TransportLayer) TransportStats {
        return self.stats;
    }

    /// Check if transport layer is running
    pub fn is_active(self: TransportLayer) bool {
        return self.is_running and !self.should_stop;
    }
};
