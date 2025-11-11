//! aBFT (Asynchronous Byzantine Fault Tolerant) Consensus Implementation
//!
//! This module implements the aBFT consensus algorithm with post-quantum
//! cryptographic security. It's designed for responsiveness where transactions
//! are confirmed asynchronously without waiting for block production.
//!
//! Based on the TxFlow architecture from the archive references.

const std = @import("std");
const blockchain = @import("../root.zig");
const crypto = @import("../crypto.zig");
const kriptix = @import("../../root.zig");

/// aBFT Consensus Configuration
pub const ABFTConfig = struct {
    /// Number of validators in the network
    validator_count: u32 = 4,

    /// Byzantine fault tolerance threshold (typically n/3)
    byzantine_threshold: u32 = 1,

    /// Voting threshold (typically 2n/3 + 1)
    voting_threshold: u32 = 3,

    /// Transaction timeout in milliseconds
    tx_timeout_ms: u64 = 10000,

    /// Block production interval in milliseconds
    block_interval_ms: u64 = 5000,

    /// PQC signature algorithm for consensus messages
    consensus_signature_algorithm: kriptix.Algorithm = .Dilithium3,
};

/// Validator information
pub const Validator = struct {
    /// Validator ID
    id: [32]u8,

    /// Public key for signature verification
    public_key: []const u8,

    /// Stake weight (for weighted voting)
    stake: u64,

    /// Whether validator is active
    active: bool = true,
};

/// Transaction vote from a validator
pub const TxVote = struct {
    /// Transaction being voted on
    tx_hash: [32]u8,

    /// Validator ID who created this vote
    validator_id: [32]u8,

    /// Vote decision (approve/reject)
    decision: enum { approve, reject },

    /// Timestamp of the vote
    timestamp: u64,

    /// PQC signature of the vote
    signature: []const u8,

    /// Hash of this vote for deduplication
    vote_hash: [32]u8,
};

/// Vote pool for tracking transaction votes
pub const VotePool = struct {
    allocator: std.mem.Allocator,

    /// Map of transaction hash to list of votes
    votes: std.HashMap([32]u8, std.ArrayList(TxVote), [32]u8, std.hash_map.default_max_load_percentage),

    /// Confirmed transactions awaiting block inclusion
    confirmed_txs: std.ArrayList([32]u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .votes = std.HashMap([32]u8, std.ArrayList(TxVote), [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .confirmed_txs = std.ArrayList([32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.votes.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.votes.deinit();
        self.confirmed_txs.deinit();
    }

    /// Add a vote to the pool
    pub fn add_vote(self: *Self, vote: TxVote, config: ABFTConfig) !bool {
        // Get or create vote list for this transaction
        const result = try self.votes.getOrPut(vote.tx_hash);
        if (!result.found_existing) {
            result.value_ptr.* = std.ArrayList(TxVote).init(self.allocator);
        }

        // Check for duplicate votes from same validator
        for (result.value_ptr.items) |existing_vote| {
            if (std.mem.eql(u8, &existing_vote.validator_id, &vote.validator_id)) {
                return false; // Duplicate vote
            }
        }

        // Add the vote
        try result.value_ptr.append(vote);

        // Check if we have enough votes to confirm the transaction
        const approval_count = self.count_approval_votes(vote.tx_hash);
        if (approval_count >= config.voting_threshold) {
            try self.confirmed_txs.append(vote.tx_hash);
            return true; // Transaction confirmed
        }

        return false; // Not yet confirmed
    }

    /// Count approval votes for a transaction
    pub fn count_approval_votes(self: *Self, tx_hash: [32]u8) u32 {
        const votes = self.votes.get(tx_hash) orelse return 0;
        var count: u32 = 0;
        for (votes.items) |vote| {
            if (vote.decision == .approve) {
                count += 1;
            }
        }
        return count;
    }

    /// Get confirmed transactions ready for block inclusion
    pub fn get_confirmed_transactions(self: *Self) []const [32]u8 {
        return self.confirmed_txs.items;
    }

    /// Clear confirmed transactions after block creation
    pub fn clear_confirmed_transactions(self: *Self) void {
        self.confirmed_txs.clearRetainingCapacity();
    }
};

/// aBFT Consensus Engine
pub const ABFTConsensus = struct {
    allocator: std.mem.Allocator,
    config: ABFTConfig,
    validators: std.ArrayList(Validator),
    vote_pool: VotePool,
    my_validator_id: [32]u8,
    my_private_key: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ABFTConfig, validator_id: [32]u8, private_key: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .validators = std.ArrayList(Validator).init(allocator),
            .vote_pool = VotePool.init(allocator),
            .my_validator_id = validator_id,
            .my_private_key = try allocator.dupe(u8, private_key),
        };
    }

    pub fn deinit(self: *Self) void {
        self.validators.deinit();
        self.vote_pool.deinit();
        self.allocator.free(self.my_private_key);
    }

    /// Add a validator to the consensus network
    pub fn add_validator(self: *Self, validator: Validator) !void {
        try self.validators.append(validator);
    }

    /// Process a new transaction and create a vote
    pub fn process_transaction(self: *Self, transaction: blockchain.Transaction) !TxVote {
        // Create vote for the transaction
        const vote = TxVote{
            .tx_hash = transaction.hash,
            .validator_id = self.my_validator_id,
            .decision = if (self.should_approve_transaction(transaction)) .approve else .reject,
            .timestamp = @intCast(std.time.timestamp()),
            .signature = try self.sign_vote_message(transaction.hash),
            .vote_hash = undefined, // Will be calculated below
        };

        // Calculate vote hash
        var vote_copy = vote;
        vote_copy.vote_hash = try self.calculate_vote_hash(vote);

        return vote_copy;
    }

    /// Process an incoming vote from another validator
    pub fn process_vote(self: *Self, vote: TxVote) !bool {
        // Verify vote signature
        if (!try self.verify_vote_signature(vote)) {
            return false;
        }

        // Add to vote pool and check if transaction is confirmed
        return try self.vote_pool.add_vote(vote, self.config);
    }

    /// Create a block from confirmed transactions
    pub fn create_block(self: *Self, previous_block_hash: [32]u8, height: u64) !blockchain.Block {
        const confirmed_txs = self.vote_pool.get_confirmed_transactions();
        _ = confirmed_txs; // TODO: Use confirmed_txs to populate actual transaction data

        // For now, create empty transactions list - will be populated with actual transaction data
        var transactions = std.ArrayList(blockchain.Transaction).init(self.allocator);
        defer transactions.deinit();

        // In a real implementation, we would retrieve the actual transaction data
        // from a transaction pool using the confirmed transaction hashes

        const header = blockchain.BlockHeader{
            .height = height,
            .timestamp = @intCast(std.time.timestamp()),
            .previous_hash = previous_block_hash,
            .merkle_root = [_]u8{0} ** 32, // Calculate actual merkle root
            .state_root = [_]u8{0} ** 32, // Calculate actual state root
            .transactions_count = @intCast(transactions.items.len),
            .hash = undefined, // Will be calculated
            .signature = undefined, // Will be calculated
        };

        var block = blockchain.Block{
            .header = header,
            .transactions = try self.allocator.dupe(blockchain.Transaction, transactions.items),
        };

        // Calculate block hash and signature
        block.header.hash = try crypto.calculate_block_hash(block.header);
        block.header.signature = try self.sign_block(block);

        // Clear confirmed transactions from vote pool
        self.vote_pool.clear_confirmed_transactions();

        return block;
    }

    /// Determine if a transaction should be approved
    fn should_approve_transaction(self: *Self, transaction: blockchain.Transaction) bool {
        _ = self;
        // Basic validation logic - in practice this would be more sophisticated
        return transaction.inputs.len > 0 and transaction.outputs.len > 0;
    }

    /// Sign a vote message using PQC signatures
    fn sign_vote_message(self: *Self, tx_hash: [32]u8) ![]u8 {
        // Create vote message to sign
        var message: [64]u8 = undefined;
        @memcpy(message[0..32], &self.my_validator_id);
        @memcpy(message[32..64], &tx_hash);

        // Sign using PQC signature algorithm
        const signature_result = try kriptix.sign(self.allocator, self.my_private_key, &message, self.config.consensus_signature_algorithm);
        return signature_result.data;
    }

    /// Verify a vote signature
    fn verify_vote_signature(self: *Self, vote: TxVote) !bool {
        // Find validator public key
        var validator_pubkey: ?[]const u8 = null;
        for (self.validators.items) |validator| {
            if (std.mem.eql(u8, &validator.id, &vote.validator_id)) {
                validator_pubkey = validator.public_key;
                break;
            }
        }

        if (validator_pubkey == null) return false;

        // Reconstruct vote message
        var message: [64]u8 = undefined;
        @memcpy(message[0..32], &vote.validator_id);
        @memcpy(message[32..64], &vote.tx_hash);

        // Verify signature
        const signature = kriptix.Signature{
            .data = vote.signature,
            .algorithm = self.config.consensus_signature_algorithm,
        };

        return kriptix.verify(validator_pubkey.?, &message, signature);
    }

    /// Calculate hash of a vote
    fn calculate_vote_hash(self: *Self, vote: TxVote) ![32]u8 {
        _ = self;
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&vote.tx_hash);
        hasher.update(&vote.validator_id);
        const decision_byte = [_]u8{if (vote.decision == .approve) 1 else 0};
        hasher.update(&decision_byte);
        hasher.update(&@as([8]u8, @bitCast(vote.timestamp)));
        hasher.update(vote.signature);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    /// Sign a block
    fn sign_block(self: *Self, block: blockchain.Block) ![]u8 {
        // Create block message to sign (just use block hash for now)
        const signature_result = try kriptix.sign(self.allocator, self.my_private_key, &block.header.hash, self.config.consensus_signature_algorithm);
        return signature_result.data;
    }
};

test "abft consensus" {
    std.testing.refAllDecls(@This());
}
