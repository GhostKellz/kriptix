//! Specialized Blockchain Data Structures
//!
//! Advanced data structures for blockchain operations with PQC signatures,
//! including Merkle trees, Patricia tries, and other specialized structures.

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const kriptix = @import("../root.zig");

/// PQC-Aware Merkle Tree Node
pub const MerkleNode = struct {
    /// Hash of this node
    hash: [32]u8,

    /// Left child (null for leaf nodes)
    left: ?*MerkleNode = null,

    /// Right child (null for leaf nodes)
    right: ?*MerkleNode = null,

    /// Data for leaf nodes (transaction hash)
    data: ?[32]u8 = null,

    /// Level in the tree (0 for leaves)
    level: u32 = 0,

    /// PQC signature of this node (for authenticated data structures)
    signature: ?[]const u8 = null,

    pub fn init_leaf(data: [32]u8) MerkleNode {
        return MerkleNode{
            .hash = data,
            .data = data,
            .level = 0,
        };
    }

    pub fn init_internal(left: *MerkleNode, right: *MerkleNode) MerkleNode {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&left.hash);
        hasher.update(&right.hash);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        return MerkleNode{
            .hash = hash,
            .left = left,
            .right = right,
            .level = @max(left.level, right.level) + 1,
        };
    }

    pub fn is_leaf(self: MerkleNode) bool {
        return self.left == null and self.right == null;
    }
};

/// PQC-Secured Merkle Tree
pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    root: ?*MerkleNode = null,
    leaves: std.ArrayList(*MerkleNode),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .leaves = std.ArrayList(*MerkleNode).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up all nodes
        if (self.root) |root| {
            self.deinit_node(root);
        }
        self.leaves.deinit();
    }

    fn deinit_node(self: *Self, node: *MerkleNode) void {
        if (node.left) |left| {
            self.deinit_node(left);
        }
        if (node.right) |right| {
            self.deinit_node(right);
        }
        if (node.signature) |sig| {
            self.allocator.free(sig);
        }
        self.allocator.destroy(node);
    }

    /// Build tree from transaction hashes
    pub fn build_from_transactions(self: *Self, transactions: []const types.Transaction) !void {
        // Clear existing tree
        if (self.root) |root| {
            self.deinit_node(root);
        }
        self.leaves.clearRetainingCapacity();

        if (transactions.len == 0) {
            self.root = null;
            return;
        }

        // Create leaf nodes
        for (transactions) |tx| {
            const leaf = try self.allocator.create(MerkleNode);
            leaf.* = MerkleNode.init_leaf(tx.hash);
            try self.leaves.append(leaf);
        }

        // Build tree bottom-up
        var current_level = try self.allocator.dupe(*MerkleNode, self.leaves.items);
        defer self.allocator.free(current_level);

        while (current_level.len > 1) {
            const next_level_size = (current_level.len + 1) / 2;
            var next_level = try self.allocator.alloc(*MerkleNode, next_level_size);

            var i: usize = 0;
            while (i < current_level.len) : (i += 2) {
                const left = current_level[i];
                const right = if (i + 1 < current_level.len) current_level[i + 1] else left; // Duplicate last node if odd

                const internal = try self.allocator.create(MerkleNode);
                internal.* = MerkleNode.init_internal(left, right);
                next_level[i / 2] = internal;
            }

            self.allocator.free(current_level);
            current_level = next_level;
        }

        self.root = current_level[0];
        self.allocator.free(current_level);
    }

    /// Generate Merkle proof for a transaction
    pub fn generate_proof(self: *Self, tx_hash: [32]u8) !?MerkleProof {
        if (self.root == null) return null;

        // Find the leaf with matching hash
        var leaf_index: ?usize = null;
        for (self.leaves.items, 0..) |leaf, i| {
            if (std.mem.eql(u8, &leaf.hash, &tx_hash)) {
                leaf_index = i;
                break;
            }
        }

        if (leaf_index == null) return null;

        var proof = MerkleProof.init(self.allocator, tx_hash);
        try self.generate_proof_recursive(self.root.?, leaf_index.?, 0, self.leaves.items.len, &proof);

        return proof;
    }

    fn generate_proof_recursive(self: *Self, node: *MerkleNode, target_index: usize, current_index: usize, range_size: usize, proof: *MerkleProof) !void {
        if (node.is_leaf()) return;

        const mid = range_size / 2;

        if (target_index < current_index + mid) {
            // Target is in left subtree, add right hash to proof
            if (node.right) |right| {
                try proof.add_hash(right.hash, .right);
                if (node.left) |left| {
                    try self.generate_proof_recursive(left, target_index, current_index, mid, proof);
                }
            }
        } else {
            // Target is in right subtree, add left hash to proof
            if (node.left) |left| {
                try proof.add_hash(left.hash, .left);
                if (node.right) |right| {
                    try self.generate_proof_recursive(right, target_index, current_index + mid, range_size - mid, proof);
                }
            }
        }
    }

    /// Get root hash
    pub fn get_root_hash(self: Self) [32]u8 {
        if (self.root) |root| {
            return root.hash;
        }
        return [_]u8{0} ** 32;
    }
};

/// Merkle Proof for transaction inclusion
pub const MerkleProof = struct {
    allocator: std.mem.Allocator,
    target_hash: [32]u8,
    proof_hashes: std.ArrayList([32]u8),
    directions: std.ArrayList(Direction),

    const Direction = enum { left, right };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, target_hash: [32]u8) Self {
        return Self{
            .allocator = allocator,
            .target_hash = target_hash,
            .proof_hashes = std.ArrayList([32]u8).init(allocator),
            .directions = std.ArrayList(Direction).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.proof_hashes.deinit();
        self.directions.deinit();
    }

    pub fn add_hash(self: *Self, hash: [32]u8, direction: Direction) !void {
        try self.proof_hashes.append(hash);
        try self.directions.append(direction);
    }

    /// Verify the proof against a root hash
    pub fn verify(self: Self, root_hash: [32]u8) bool {
        if (self.proof_hashes.items.len != self.directions.items.len) {
            return false;
        }

        var current_hash = self.target_hash;

        for (self.proof_hashes.items, 0..) |proof_hash, i| {
            var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

            switch (self.directions.items[i]) {
                .left => {
                    hasher.update(&proof_hash);
                    hasher.update(&current_hash);
                },
                .right => {
                    hasher.update(&current_hash);
                    hasher.update(&proof_hash);
                },
            }

            hasher.final(&current_hash);
        }

        return std.mem.eql(u8, &current_hash, &root_hash);
    }
};

/// Patricia Trie Node for efficient state representation
pub const PatriciaNode = struct {
    /// Key prefix for this node
    key_prefix: []u8,

    /// Value (null for internal nodes)
    value: ?[]u8 = null,

    /// Children nodes (256 possible branches for each byte)
    children: [256]?*PatriciaNode,

    /// Whether this is a terminal node
    is_terminal: bool = false,

    /// PQC signature for authenticated operations
    signature: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, key_prefix: []const u8) !*PatriciaNode {
        const node = try allocator.create(PatriciaNode);
        node.* = PatriciaNode{
            .key_prefix = try allocator.dupe(u8, key_prefix),
            .children = [_]?*PatriciaNode{null} ** 256,
        };
        return node;
    }

    pub fn deinit(self: *PatriciaNode, allocator: std.mem.Allocator) void {
        allocator.free(self.key_prefix);
        if (self.value) |val| {
            allocator.free(val);
        }
        if (self.signature) |sig| {
            allocator.free(sig);
        }

        for (&self.children) |*child| {
            if (child.*) |child_node| {
                child_node.deinit(allocator);
                allocator.destroy(child_node);
                child.* = null;
            }
        }
    }
};

/// Patricia Trie for efficient state storage
pub const PatriciaTrie = struct {
    allocator: std.mem.Allocator,
    root: ?*PatriciaNode = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.root) |root| {
            root.deinit(self.allocator);
            self.allocator.destroy(root);
        }
    }

    /// Insert key-value pair
    pub fn insert(self: *Self, key: []const u8, value: []const u8) !void {
        if (self.root == null) {
            self.root = try PatriciaNode.init(self.allocator, &[_]u8{});
        }

        try self.insert_recursive(self.root.?, key, value, 0);
    }

    fn insert_recursive(self: *Self, node: *PatriciaNode, key: []const u8, value: []const u8, depth: usize) !void {
        if (depth >= key.len) {
            // Terminal node
            if (node.value) |old_value| {
                self.allocator.free(old_value);
            }
            node.value = try self.allocator.dupe(u8, value);
            node.is_terminal = true;
            return;
        }

        const next_byte = key[depth];

        if (node.children[next_byte] == null) {
            node.children[next_byte] = try PatriciaNode.init(self.allocator, key[depth..]);
        }

        try self.insert_recursive(node.children[next_byte].?, key, value, depth + 1);
    }

    /// Get value by key
    pub fn get(self: Self, key: []const u8) ?[]const u8 {
        if (self.root == null) return null;
        return self.get_recursive(self.root.?, key, 0);
    }

    fn get_recursive(self: Self, node: *PatriciaNode, key: []const u8, depth: usize) ?[]const u8 {
        if (depth >= key.len) {
            return if (node.is_terminal) node.value else null;
        }

        const next_byte = key[depth];
        if (node.children[next_byte]) |child| {
            return self.get_recursive(child, key, depth + 1);
        }

        return null;
    }

    /// Calculate root hash of the trie
    pub fn get_root_hash(self: Self) [32]u8 {
        if (self.root == null) {
            return [_]u8{0} ** 32;
        }
        return self.calculate_node_hash(self.root.?);
    }

    fn calculate_node_hash(self: Self, node: *PatriciaNode) [32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

        // Hash key prefix
        hasher.update(node.key_prefix);

        // Hash value if terminal
        if (node.is_terminal and node.value != null) {
            hasher.update(node.value.?);
        }

        // Hash children
        for (node.children, 0..) |child, i| {
            if (child) |child_node| {
                const index_byte = [_]u8{@as(u8, @intCast(i))};
                hasher.update(&index_byte);
                const child_hash = self.calculate_node_hash(child_node);
                hasher.update(&child_hash);
            }
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

/// Blockchain State Snapshot with PQC verification
pub const StateSnapshot = struct {
    /// Snapshot height
    height: u64,

    /// State root hash
    state_root: [32]u8,

    /// Merkle tree of account states
    account_tree: MerkleTree,

    /// Patricia trie of storage
    storage_trie: PatriciaTrie,

    /// Timestamp of snapshot
    timestamp: u64,

    /// PQC signature of the snapshot
    signature: []const u8,

    /// Algorithm used for signature
    signature_algorithm: kriptix.Algorithm,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, height: u64) Self {
        return Self{
            .height = height,
            .state_root = [_]u8{0} ** 32,
            .account_tree = MerkleTree.init(allocator),
            .storage_trie = PatriciaTrie.init(allocator),
            .timestamp = @intCast(std.time.timestamp()),
            .signature = &[_]u8{},
            .signature_algorithm = .Dilithium3,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.account_tree.deinit();
        self.storage_trie.deinit();
        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
    }

    /// Calculate and update state root
    pub fn update_state_root(self: *Self) void {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&@as([8]u8, @bitCast(self.height)));
        hasher.update(&@as([8]u8, @bitCast(self.timestamp)));

        const account_root = self.account_tree.get_root_hash();
        const storage_root = self.storage_trie.get_root_hash();

        hasher.update(&account_root);
        hasher.update(&storage_root);

        hasher.final(&self.state_root);
    }

    /// Sign the snapshot with validator key
    pub fn sign(self: *Self, allocator: std.mem.Allocator, private_key: []const u8, algorithm: kriptix.Algorithm) !void {
        self.update_state_root();

        const signature_result = try kriptix.sign(allocator, private_key, &self.state_root, algorithm);

        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
        self.signature = signature_result.data;
        self.signature_algorithm = algorithm;
    }

    /// Verify snapshot signature
    pub fn verify(self: Self, public_key: []const u8) !bool {
        const signature = kriptix.Signature{
            .data = self.signature,
            .algorithm = self.signature_algorithm,
        };

        return try kriptix.verify(public_key, &self.state_root, signature);
    }
};

/// Multi-signature structure for aBFT consensus
pub const MultiSignature = struct {
    allocator: std.mem.Allocator,

    /// Message that was signed
    message: []u8,

    /// Individual signatures from validators
    signatures: std.ArrayList(ValidatorSignature),

    /// Threshold required for validity
    threshold: u32,

    const ValidatorSignature = struct {
        validator_id: [32]u8,
        signature: []u8,
        algorithm: kriptix.Algorithm,
        public_key: []u8,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, message: []const u8, threshold: u32) !Self {
        return Self{
            .allocator = allocator,
            .message = try allocator.dupe(u8, message),
            .signatures = std.ArrayList(ValidatorSignature).init(allocator),
            .threshold = threshold,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.message);
        for (self.signatures.items) |*sig| {
            self.allocator.free(sig.signature);
            self.allocator.free(sig.public_key);
        }
        self.signatures.deinit();
    }

    /// Add a validator signature
    pub fn add_signature(self: *Self, validator_id: [32]u8, signature: []const u8, algorithm: kriptix.Algorithm, public_key: []const u8) !void {
        // Check for duplicate signatures
        for (self.signatures.items) |existing_sig| {
            if (std.mem.eql(u8, &existing_sig.validator_id, &validator_id)) {
                return; // Already have signature from this validator
            }
        }

        const validator_sig = ValidatorSignature{
            .validator_id = validator_id,
            .signature = try self.allocator.dupe(u8, signature),
            .algorithm = algorithm,
            .public_key = try self.allocator.dupe(u8, public_key),
        };

        try self.signatures.append(validator_sig);
    }

    /// Verify all signatures
    pub fn verify_all(self: Self) !bool {
        if (self.signatures.items.len < self.threshold) {
            return false;
        }

        for (self.signatures.items) |sig| {
            const signature = kriptix.Signature{
                .data = sig.signature,
                .algorithm = sig.algorithm,
            };

            const valid = try kriptix.verify(sig.public_key, self.message, signature);
            if (!valid) {
                return false;
            }
        }

        return true;
    }

    /// Check if threshold is met
    pub fn is_valid(self: Self) !bool {
        return self.signatures.items.len >= self.threshold and try self.verify_all();
    }
};

test "specialized blockchain structures" {
    std.testing.refAllDecls(@This());
}
