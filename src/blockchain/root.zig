//! Kriptix Blockchain Module
//! Post-quantum secure blockchain implementation with aBFT consensus
//!
//! This module provides the core blockchain functionality designed for
//! post-quantum security, including block structures, transactions,
//! state management, and consensus mechanisms.

const std = @import("std");

// Re-export core blockchain modules
pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const consensus = @import("consensus/root.zig");
pub const network = @import("network/root.zig");
pub const specialized = @import("specialized.zig");

// Re-export commonly used types for convenience
pub const Block = types.Block;
pub const Transaction = types.Transaction;
pub const ChainState = types.ChainState;
pub const BlockHeader = types.BlockHeader;
pub const TransactionReceipt = types.TransactionReceipt;

// Re-export crypto bridge functionality
pub const BlockSigner = crypto.BlockSigner;
pub const TransactionSigner = crypto.TransactionSigner;
pub const StateHasher = crypto.StateHasher;

// Re-export specialized structures
pub const MerkleTree = specialized.MerkleTree;
pub const MerkleProof = specialized.MerkleProof;
pub const PatriciaTrie = specialized.PatriciaTrie;
pub const StateSnapshot = specialized.StateSnapshot;
pub const MultiSignature = specialized.MultiSignature;

// Core blockchain operations
pub const BlockchainError = error{
    InvalidBlock,
    InvalidTransaction,
    InvalidSignature,
    ConsensusFailure,
    StateError,
    CryptoError,
    SerializationError,
    ValidationError,
};

// Blockchain configuration
pub const Config = struct {
    /// Maximum block size in bytes
    max_block_size: u32 = 1024 * 1024, // 1MB

    /// Block time in milliseconds
    block_time_ms: u64 = 3000, // 3 seconds

    /// Maximum transactions per block
    max_transactions_per_block: u32 = 1000,

    /// PQC algorithm for block signatures
    block_signature_algorithm: @import("../root.zig").Algorithm = .Dilithium3,

    /// PQC algorithm for transaction signatures
    transaction_signature_algorithm: @import("../root.zig").Algorithm = .Dilithium2,

    /// PQC algorithm for key exchange
    key_exchange_algorithm: @import("../root.zig").Algorithm = .Kyber768,

    /// Enable hybrid cryptography (PQC + Classical)
    enable_hybrid_crypto: bool = false,
};

// Main blockchain instance
pub const Blockchain = struct {
    allocator: std.mem.Allocator,
    config: Config,
    state: ChainState,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .state = try ChainState.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.state.deinit();
    }

    /// Validate and add a new block to the chain
    pub fn add_block(self: *Self, block: Block) !void {
        // Validate block structure
        try self.validate_block(block);

        // Apply block to state
        try self.state.apply_block(block);
    }

    /// Validate a block against current chain state
    pub fn validate_block(self: *Self, block: Block) !void {
        // Validate block header
        try self.validate_block_header(block.header);

        // Validate all transactions in the block
        for (block.transactions) |tx| {
            try self.validate_transaction(tx);
        }

        // Validate block signature using PQC
        try crypto.verify_block_signature(block, self.config.block_signature_algorithm);
    }

    /// Validate a transaction
    pub fn validate_transaction(self: *Self, transaction: Transaction) !void {
        // Validate transaction structure
        if (transaction.inputs.len == 0) return BlockchainError.InvalidTransaction;
        if (transaction.outputs.len == 0) return BlockchainError.InvalidTransaction;

        // Validate transaction signature using PQC
        try crypto.verify_transaction_signature(transaction, self.config.transaction_signature_algorithm);

        // Validate against current state
        try self.state.validate_transaction(transaction);
    }

    /// Get current chain height
    pub fn get_height(self: *Self) u64 {
        return self.state.height;
    }

    /// Get block by height
    pub fn get_block(self: *Self, height: u64) ?Block {
        return self.state.get_block(height);
    }

    /// Get transaction by hash
    pub fn get_transaction(self: *Self, tx_hash: [32]u8) ?Transaction {
        return self.state.get_transaction(tx_hash);
    }

    fn validate_block_header(self: *Self, header: BlockHeader) !void {
        // Validate timestamp
        const current_time = std.time.timestamp();
        if (header.timestamp > current_time + 300) { // Allow 5 minutes in future
            return BlockchainError.InvalidBlock;
        }

        // Validate height
        if (header.height != self.state.height + 1) {
            return BlockchainError.InvalidBlock;
        }

        // Validate previous block hash
        if (self.state.height > 0) {
            const prev_block = self.state.get_block(self.state.height) orelse return BlockchainError.InvalidBlock;
            if (!std.mem.eql(u8, &header.previous_hash, &prev_block.header.hash)) {
                return BlockchainError.InvalidBlock;
            }
        }
    }
};

test "blockchain module imports" {
    std.testing.refAllDecls(@This());
}
