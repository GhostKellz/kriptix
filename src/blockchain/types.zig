//! Blockchain Type Definitions
//!
//! Core data structures for the Kriptix blockchain with post-quantum
//! cryptographic security built-in.

const std = @import("std");
const kriptix = @import("../root.zig");
const hybrid_types = @import("hybrid_types.zig");

/// Transaction Input
pub const TxInput = struct {
    /// Hash of the previous transaction
    prev_tx_hash: [32]u8,

    /// Index of the output in the previous transaction
    output_index: u32,

    /// PQC Signature proving ownership of the referenced output
    signature: []const u8,

    /// Public key of the spender
    public_key: []const u8,

    /// Optional hybrid public key record for classical interoperability
    hybrid_public_key: ?hybrid_types.HybridPublicKeyRecord = null,

    /// Optional hybrid signature bundle for this input
    hybrid_signature: ?hybrid_types.HybridSignatureRecord = null,

    /// Algorithm used for the signature
    signature_algorithm: kriptix.Algorithm,

    pub fn init(prev_tx_hash: [32]u8, output_index: u32, signature: []const u8, public_key: []const u8, sig_algo: kriptix.Algorithm) TxInput {
        return TxInput{
            .prev_tx_hash = prev_tx_hash,
            .output_index = output_index,
            .signature = signature,
            .public_key = public_key,
            .signature_algorithm = sig_algo,
        };
    }

    /// Calculate hash of this input for transaction signing
    pub fn hash(self: TxInput, allocator: std.mem.Allocator) ![32]u8 {
        _ = allocator;
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.prev_tx_hash);
        hasher.update(&@as([4]u8, @bitCast(self.output_index)));
        hasher.update(self.public_key);

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    pub fn deinit(self: *TxInput, allocator: std.mem.Allocator) void {
        if (self.hybrid_public_key) |*record| {
            record.deinit(allocator);
            self.hybrid_public_key = null;
        }
        if (self.hybrid_signature) |*signature| {
            signature.deinit(allocator);
            self.hybrid_signature = null;
        }
    }
};

/// Transaction Output
pub const TxOutput = struct {
    /// Amount in base units
    amount: u64,

    /// Public key of the recipient (post-quantum)
    recipient_pubkey: []const u8,

    /// PQC algorithm for the recipient's key
    pubkey_algorithm: kriptix.Algorithm,

    /// Optional script/contract data
    script: ?[]const u8 = null,

    /// Optional hybrid public key record for the recipient
    hybrid_public_key: ?hybrid_types.HybridPublicKeyRecord = null,

    pub fn init(amount: u64, recipient_pubkey: []const u8, pubkey_algo: kriptix.Algorithm) TxOutput {
        return TxOutput{
            .amount = amount,
            .recipient_pubkey = recipient_pubkey,
            .pubkey_algorithm = pubkey_algo,
        };
    }

    /// Calculate hash of this output
    pub fn hash(self: TxOutput, allocator: std.mem.Allocator) ![32]u8 {
        _ = allocator;
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&@as([8]u8, @bitCast(self.amount)));
        hasher.update(self.recipient_pubkey);
        if (self.script) |script_data| {
            hasher.update(script_data);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    pub fn deinit(self: *TxOutput, allocator: std.mem.Allocator) void {
        if (self.hybrid_public_key) |*record| {
            record.deinit(allocator);
            self.hybrid_public_key = null;
        }
    }
};

/// Transaction
pub const Transaction = struct {
    /// Transaction version
    version: u32 = 1,

    /// Transaction inputs
    inputs: []TxInput,

    /// Transaction outputs
    outputs: []TxOutput,

    /// Transaction timestamp
    timestamp: u64,

    /// Transaction fee
    fee: u64,

    /// Nonce to prevent replay attacks
    nonce: u64,

    /// Transaction hash (calculated)
    hash: [32]u8,

    /// PQC signature of the entire transaction
    signature: []const u8,

    /// Algorithm used for transaction signature
    signature_algorithm: kriptix.Algorithm,

    /// Optional hybrid signature for the transaction
    hybrid_signature: ?hybrid_types.HybridSignatureRecord = null,

    /// Optional hybrid public key that signed the transaction
    hybrid_public_key: ?hybrid_types.HybridPublicKeyRecord = null,

    pub fn init(allocator: std.mem.Allocator, inputs: []TxInput, outputs: []TxOutput, fee: u64, nonce: u64, sig_algo: kriptix.Algorithm) !Transaction {
        var tx = Transaction{
            .inputs = try allocator.dupe(TxInput, inputs),
            .outputs = try allocator.dupe(TxOutput, outputs),
            .timestamp = @intCast(std.time.timestamp()),
            .fee = fee,
            .nonce = nonce,
            .hash = undefined,
            .signature = &[_]u8{}, // Will be set after signing
            .signature_algorithm = sig_algo,
        };
        errdefer tx.deinit(allocator);

        for (tx.inputs, 0..) |*input, idx| {
            input.hybrid_public_key = null;
            input.hybrid_signature = null;
            if (inputs[idx].hybrid_public_key) |record| {
                input.hybrid_public_key = try record.clone(allocator);
            }
            if (inputs[idx].hybrid_signature) |signature_record| {
                input.hybrid_signature = try signature_record.clone(allocator);
            }
        }

        for (tx.outputs, 0..) |*output, idx| {
            output.hybrid_public_key = null;
            if (outputs[idx].hybrid_public_key) |record| {
                output.hybrid_public_key = try record.clone(allocator);
            }
        }

        // Calculate transaction hash
        tx.hash = try tx.calculate_hash(allocator);
        return tx;
    }

    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        for (self.inputs) |*input| {
            input.deinit(allocator);
        }
        allocator.free(self.inputs);

        for (self.outputs) |*output| {
            output.deinit(allocator);
        }
        allocator.free(self.outputs);
        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
        if (self.hybrid_signature) |*signature_record| {
            signature_record.deinit(allocator);
            self.hybrid_signature = null;
        }
        if (self.hybrid_public_key) |*pk_record| {
            pk_record.deinit(allocator);
            self.hybrid_public_key = null;
        }
    }

    /// Calculate the hash of this transaction
    pub fn calculate_hash(self: *Transaction, allocator: std.mem.Allocator) ![32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

        // Hash transaction data (excluding signature)
        hasher.update(&@as([4]u8, @bitCast(self.version)));
        hasher.update(&@as([8]u8, @bitCast(self.timestamp)));
        hasher.update(&@as([8]u8, @bitCast(self.fee)));
        hasher.update(&@as([8]u8, @bitCast(self.nonce)));

        // Hash inputs
        for (self.inputs) |input| {
            const input_hash = try input.hash(allocator);
            hasher.update(&input_hash);
        }

        // Hash outputs
        for (self.outputs) |output| {
            const output_hash = try output.hash(allocator);
            hasher.update(&output_hash);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Get the message that should be signed for this transaction
    pub fn get_signing_message(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        // For now, just return the hash as the signing message
        const hash_data = try allocator.alloc(u8, 32);
        @memcpy(hash_data, &self.hash);
        return hash_data;
    }

    /// Verify the transaction signature
    pub fn verify_signature(self: Transaction) !bool {
        // This will be implemented in the crypto bridge module
        // For now, return true as placeholder
        _ = self;
        return true;
    }
};

/// Block Header
pub const BlockHeader = struct {
    /// Block height in the chain
    height: u64,

    /// Block timestamp
    timestamp: u64,

    /// Hash of the previous block
    previous_hash: [32]u8,

    /// Merkle root of all transactions in this block
    merkle_root: [32]u8,

    /// State root after applying this block
    state_root: [32]u8,

    /// Number of transactions in this block
    transactions_count: u32,

    /// Block hash (calculated from header data)
    hash: [32]u8,

    /// PQC signature of the block (by validator)
    signature: []const u8,

    /// Algorithm used for block signature
    signature_algorithm: kriptix.Algorithm = .Dilithium3,

    /// Optional hybrid signature information for the block
    hybrid_signature: ?hybrid_types.HybridSignatureRecord = null,

    /// Optional hybrid public key for the validator
    hybrid_public_key: ?hybrid_types.HybridPublicKeyRecord = null,

    /// Additional metadata
    difficulty: u64 = 0, // For future use
    validator_id: ?[32]u8 = null, // ID of the validator who created this block

    pub fn calculate_hash(self: *BlockHeader) [32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

        hasher.update(&@as([8]u8, @bitCast(self.height)));
        hasher.update(&@as([8]u8, @bitCast(self.timestamp)));
        hasher.update(&self.previous_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.state_root);
        hasher.update(&@as([4]u8, @bitCast(self.transactions_count)));
        hasher.update(&@as([8]u8, @bitCast(self.difficulty)));

        if (self.validator_id) |validator| {
            hasher.update(&validator);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

/// Block
pub const Block = struct {
    /// Block header
    header: BlockHeader,

    /// Transactions in this block
    transactions: []Transaction,

    pub fn init(allocator: std.mem.Allocator, height: u64, previous_hash: [32]u8, transactions: []Transaction) !Block {
        var block = Block{
            .header = BlockHeader{
                .height = height,
                .timestamp = @intCast(std.time.timestamp()),
                .previous_hash = previous_hash,
                .merkle_root = undefined,
                .state_root = undefined,
                .transactions_count = @intCast(transactions.len),
                .hash = undefined,
                .signature = &[_]u8{},
            },
            .transactions = try allocator.dupe(Transaction, transactions),
        };

        // Calculate merkle root of transactions
        block.header.merkle_root = try block.calculate_merkle_root(allocator);

        // Calculate block hash
        block.header.hash = block.header.calculate_hash();

        return block;
    }

    pub fn deinit(self: *Block, allocator: std.mem.Allocator) void {
        for (self.transactions) |*tx| {
            tx.deinit(allocator);
        }
        allocator.free(self.transactions);
        if (self.header.signature.len > 0) {
            allocator.free(self.header.signature);
        }
        if (self.header.hybrid_signature) |*signature_record| {
            signature_record.deinit(allocator);
            self.header.hybrid_signature = null;
        }
        if (self.header.hybrid_public_key) |*pk_record| {
            pk_record.deinit(allocator);
            self.header.hybrid_public_key = null;
        }
    }

    /// Calculate the Merkle root of all transactions
    pub fn calculate_merkle_root(self: Block, allocator: std.mem.Allocator) ![32]u8 {
        if (self.transactions.len == 0) {
            return [_]u8{0} ** 32;
        }

        // Collect transaction hashes
        var tx_hashes = try allocator.alloc([32]u8, self.transactions.len);
        defer allocator.free(tx_hashes);

        for (self.transactions, 0..) |tx, i| {
            tx_hashes[i] = tx.hash;
        }

        // Build Merkle tree
        return calculate_merkle_root_from_hashes(tx_hashes);
    }

    /// Verify block integrity
    pub fn verify(self: Block, allocator: std.mem.Allocator) !bool {
        // Verify header hash
        const calculated_hash = self.header.calculate_hash();
        if (!std.mem.eql(u8, &calculated_hash, &self.header.hash)) {
            return false;
        }

        // Verify merkle root
        const calculated_merkle = try self.calculate_merkle_root(allocator);
        if (!std.mem.eql(u8, &calculated_merkle, &self.header.merkle_root)) {
            return false;
        }

        // Verify transaction count
        if (self.header.transactions_count != self.transactions.len) {
            return false;
        }

        // Verify all transactions
        for (self.transactions) |tx| {
            if (!try tx.verify_signature()) {
                return false;
            }
        }

        return true;
    }
};

/// Transaction Receipt (for confirmed transactions)
pub const TransactionReceipt = struct {
    /// Transaction hash
    tx_hash: [32]u8,

    /// Block height where transaction was included
    block_height: u64,

    /// Block hash where transaction was included
    block_hash: [32]u8,

    /// Index of transaction within the block
    tx_index: u32,

    /// Gas used (if applicable)
    gas_used: u64 = 0,

    /// Transaction status
    status: enum { success, failed, pending } = .success,

    /// Timestamp when transaction was confirmed
    confirmation_timestamp: u64,

    pub fn init(tx_hash: [32]u8, block_height: u64, block_hash: [32]u8, tx_index: u32) TransactionReceipt {
        return TransactionReceipt{
            .tx_hash = tx_hash,
            .block_height = block_height,
            .block_hash = block_hash,
            .tx_index = tx_index,
            .confirmation_timestamp = @intCast(std.time.timestamp()),
        };
    }
};

/// Chain State Management
pub const ChainState = struct {
    allocator: std.mem.Allocator,

    /// Current chain height
    height: u64 = 0,

    /// Chain of blocks (stored as hash -> block mapping)
    blocks: std.HashMap([32]u8, Block, [32]u8, std.hash_map.default_max_load_percentage),

    /// Transaction pool (unconfirmed transactions)
    tx_pool: std.HashMap([32]u8, Transaction, [32]u8, std.hash_map.default_max_load_percentage),

    /// Confirmed transactions (hash -> receipt mapping)
    confirmed_txs: std.HashMap([32]u8, TransactionReceipt, [32]u8, std.hash_map.default_max_load_percentage),

    /// UTXO set (unspent transaction outputs)
    utxo_set: std.HashMap([32]u8, TxOutput, [32]u8, std.hash_map.default_max_load_percentage),

    /// Account balances (public key hash -> balance)
    balances: std.HashMap([32]u8, u64, [32]u8, std.hash_map.default_max_load_percentage),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .blocks = std.HashMap([32]u8, Block, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .tx_pool = std.HashMap([32]u8, Transaction, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .confirmed_txs = std.HashMap([32]u8, TransactionReceipt, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .utxo_set = std.HashMap([32]u8, TxOutput, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .balances = std.HashMap([32]u8, u64, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up blocks
        var block_iter = self.blocks.iterator();
        while (block_iter.next()) |entry| {
            var block_copy = entry.value_ptr.*;
            block_copy.deinit(self.allocator);
        }
        self.blocks.deinit();

        // Clean up transaction pool
        var tx_iter = self.tx_pool.iterator();
        while (tx_iter.next()) |entry| {
            var tx_copy = entry.value_ptr.*;
            tx_copy.deinit(self.allocator);
        }
        self.tx_pool.deinit();

        self.confirmed_txs.deinit();
        self.utxo_set.deinit();
        self.balances.deinit();
    }

    /// Apply a block to the chain state
    pub fn apply_block(self: *Self, block: Block) !void {
        // Store block
        try self.blocks.put(block.header.hash, block);

        // Update height
        self.height = block.header.height;

        // Process transactions
        for (block.transactions, 0..) |tx, i| {
            try self.apply_transaction(tx, block.header.height, block.header.hash, @intCast(i));
        }
    }

    /// Apply a transaction to the state
    pub fn apply_transaction(self: *Self, tx: Transaction, block_height: u64, block_hash: [32]u8, tx_index: u32) !void {
        // Remove from transaction pool if present
        _ = self.tx_pool.remove(tx.hash);

        // Create receipt
        const receipt = TransactionReceipt.init(tx.hash, block_height, block_hash, tx_index);
        try self.confirmed_txs.put(tx.hash, receipt);

        // Update UTXO set and balances
        try self.update_utxo_and_balances(tx);
    }

    /// Validate a transaction against current state
    pub fn validate_transaction(self: *Self, tx: Transaction) !void {
        // Check if transaction is already confirmed
        if (self.confirmed_txs.contains(tx.hash)) {
            return error.TransactionAlreadyConfirmed;
        }

        // Verify inputs exist and are unspent
        for (tx.inputs) |input| {
            const utxo_key = self.create_utxo_key(input.prev_tx_hash, input.output_index);
            if (!self.utxo_set.contains(utxo_key)) {
                return error.InvalidInput;
            }
        }

        // Verify balance (simplified)
        var total_input: u64 = 0;
        var total_output: u64 = 0;

        for (tx.inputs) |input| {
            const utxo_key = self.create_utxo_key(input.prev_tx_hash, input.output_index);
            if (self.utxo_set.get(utxo_key)) |utxo| {
                total_input += utxo.amount;
            }
        }

        for (tx.outputs) |output| {
            total_output += output.amount;
        }

        if (total_input < total_output + tx.fee) {
            return error.InsufficientFunds;
        }
    }

    /// Get block by hash
    pub fn get_block_by_hash(self: *Self, hash: [32]u8) ?Block {
        return self.blocks.get(hash);
    }

    /// Get block by height
    pub fn get_block(self: *Self, height: u64) ?Block {
        // Linear search for now - in practice this would be optimized
        var iter = self.blocks.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.header.height == height) {
                return entry.value_ptr.*;
            }
        }
        return null;
    }

    /// Get transaction by hash
    pub fn get_transaction(self: *Self, tx_hash: [32]u8) ?Transaction {
        // Check transaction pool first
        if (self.tx_pool.get(tx_hash)) |tx| {
            return tx;
        }

        // Search in confirmed transactions
        if (self.confirmed_txs.get(tx_hash)) |receipt| {
            if (self.get_block_by_hash(receipt.block_hash)) |block| {
                if (receipt.tx_index < block.transactions.len) {
                    return block.transactions[receipt.tx_index];
                }
            }
        }

        return null;
    }

    /// Add transaction to pool
    pub fn add_transaction_to_pool(self: *Self, tx: Transaction) !void {
        try self.validate_transaction(tx);
        try self.tx_pool.put(tx.hash, tx);
    }

    /// Get balance for a public key
    pub fn get_balance(self: *Self, public_key: []const u8) u64 {
        const pubkey_hash = self.hash_public_key(public_key);
        return self.balances.get(pubkey_hash) orelse 0;
    }

    // Private helper methods

    fn update_utxo_and_balances(self: *Self, tx: Transaction) !void {
        // Remove spent UTXOs
        for (tx.inputs) |input| {
            const utxo_key = self.create_utxo_key(input.prev_tx_hash, input.output_index);
            if (self.utxo_set.fetchRemove(utxo_key)) |kv| {
                // Update balance
                const pubkey_hash = self.hash_public_key(input.public_key);
                const current_balance = self.balances.get(pubkey_hash) orelse 0;
                if (current_balance >= kv.value.amount) {
                    try self.balances.put(pubkey_hash, current_balance - kv.value.amount);
                }
            }
        }

        // Add new UTXOs
        for (tx.outputs, 0..) |output, i| {
            const utxo_key = self.create_utxo_key(tx.hash, @intCast(i));
            try self.utxo_set.put(utxo_key, output);

            // Update balance
            const pubkey_hash = self.hash_public_key(output.recipient_pubkey);
            const current_balance = self.balances.get(pubkey_hash) orelse 0;
            try self.balances.put(pubkey_hash, current_balance + output.amount);
        }
    }

    fn create_utxo_key(self: *Self, tx_hash: [32]u8, output_index: u32) [32]u8 {
        _ = self;
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&tx_hash);
        hasher.update(&@as([4]u8, @bitCast(output_index)));

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    fn hash_public_key(self: *Self, public_key: []const u8) [32]u8 {
        _ = self;
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(public_key);

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

// Utility Functions

/// Calculate Merkle root from a list of hashes
pub fn calculate_merkle_root_from_hashes(hashes: [][32]u8) [32]u8 {
    if (hashes.len == 0) {
        return [_]u8{0} ** 32;
    }

    if (hashes.len == 1) {
        return hashes[0];
    }

    // For simplicity, just hash all the hashes together
    // In a real implementation, this would build a proper Merkle tree
    var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
    for (hashes) |hash| {
        hasher.update(&hash);
    }

    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

test "blockchain types" {
    std.testing.refAllDecls(@This());
}
