//! Blockchain Cryptography Bridge
//!
//! This module bridges the post-quantum cryptography primitives with
//! blockchain-specific operations like transaction signing, block validation,
//! and key derivation.

const std = @import("std");
const kriptix = @import("../root.zig");
const types = @import("types.zig");

/// Cryptographic operations error types
pub const CryptoError = error{
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    KeyDerivationFailed,
    HashingFailed,
    InvalidAlgorithm,
};

/// PQC Key Derivation Context
pub const KeyDerivationContext = struct {
    /// Base key material
    base_key: []const u8,

    /// Derivation path (e.g., "m/44'/0'/0'/0/0")
    path: []const u8,

    /// Additional context information
    context: []const u8,

    /// Salt for key derivation
    salt: []const u8,

    pub fn init(base_key: []const u8, path: []const u8, context: []const u8, salt: []const u8) KeyDerivationContext {
        return KeyDerivationContext{
            .base_key = base_key,
            .path = path,
            .context = context,
            .salt = salt,
        };
    }
};

/// Derived key pair for blockchain operations
pub const DerivedKeyPair = struct {
    public_key: []u8,
    private_key: []u8,
    algorithm: kriptix.Algorithm,
    derivation_path: []u8,

    pub fn deinit(self: *DerivedKeyPair, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key);
        allocator.free(self.private_key);
        allocator.free(self.derivation_path);
    }
};

/// Transaction Signer - handles PQC signing of transactions
pub const TransactionSigner = struct {
    allocator: std.mem.Allocator,
    algorithm: kriptix.Algorithm,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, algorithm: kriptix.Algorithm) Self {
        return Self{
            .allocator = allocator,
            .algorithm = algorithm,
        };
    }

    /// Sign a transaction with a private key
    pub fn sign_transaction(self: *Self, transaction: *types.Transaction, private_key: []const u8) !void {
        // Get the message to be signed (transaction hash)
        const signing_message = try transaction.get_signing_message(self.allocator);
        defer self.allocator.free(signing_message);

        // Sign the message using PQC
        const signature_result = try kriptix.sign(self.allocator, private_key, signing_message, self.algorithm);

        // Update transaction with signature
        if (transaction.signature.len > 0) {
            self.allocator.free(transaction.signature);
        }
        transaction.signature = signature_result.data;
        transaction.signature_algorithm = self.algorithm;
    }

    /// Verify a transaction signature
    pub fn verify_transaction(self: *Self, transaction: types.Transaction, public_key: []const u8) !bool {
        // Get the signing message
        const signing_message = try transaction.get_signing_message(self.allocator);
        defer self.allocator.free(signing_message);

        // Create signature structure
        const signature = kriptix.Signature{
            .data = transaction.signature,
            .algorithm = transaction.signature_algorithm,
        };

        // Verify using PQC
        return try kriptix.verify(public_key, signing_message, signature);
    }

    /// Sign transaction inputs individually (for multi-sig scenarios)
    pub fn sign_transaction_input(self: *Self, input: *types.TxInput, transaction_hash: [32]u8, private_key: []const u8) !void {
        // Create signing message for this input
        var signing_message = try self.allocator.alloc(u8, 64);
        defer self.allocator.free(signing_message);

        @memcpy(signing_message[0..32], &transaction_hash);
        @memcpy(signing_message[32..64], &input.prev_tx_hash);

        // Sign the input
        const signature_result = try kriptix.sign(self.allocator, private_key, signing_message, self.algorithm);

        // Update input with signature
        if (input.signature.len > 0) {
            self.allocator.free(input.signature);
        }
        input.signature = signature_result.data;
        input.signature_algorithm = self.algorithm;
    }
};

/// Block Signer - handles PQC signing of blocks
pub const BlockSigner = struct {
    allocator: std.mem.Allocator,
    algorithm: kriptix.Algorithm,
    validator_id: [32]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, algorithm: kriptix.Algorithm, validator_id: [32]u8) Self {
        return Self{
            .allocator = allocator,
            .algorithm = algorithm,
            .validator_id = validator_id,
        };
    }

    /// Sign a block with validator's private key
    pub fn sign_block(self: *Self, block: *types.Block, private_key: []const u8) !void {
        // Update validator ID in block header
        block.header.validator_id = self.validator_id;

        // Recalculate block hash with validator ID
        block.header.hash = block.header.calculate_hash();

        // Sign the block hash
        const signature_result = try kriptix.sign(self.allocator, private_key, &block.header.hash, self.algorithm);

        // Update block with signature
        if (block.header.signature.len > 0) {
            self.allocator.free(block.header.signature);
        }
        block.header.signature = signature_result.data;
        block.header.signature_algorithm = self.algorithm;
    }

    /// Verify a block signature
    pub fn verify_block(self: *Self, block: types.Block, validator_public_key: []const u8) !bool {
        _ = self;
        // Create signature structure
        const signature = kriptix.Signature{
            .data = block.header.signature,
            .algorithm = block.header.signature_algorithm,
        };

        // Verify block signature
        return try kriptix.verify(validator_public_key, &block.header.hash, signature);
    }
};

/// State Hasher - handles cryptographic state operations
pub const StateHasher = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    /// Calculate state root from account balances and UTXO set
    pub fn calculate_state_root(self: *Self, chain_state: *const types.ChainState) ![32]u8 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

        // Hash current height
        hasher.update(&@as([8]u8, @bitCast(chain_state.height)));

        // Hash balances (in deterministic order)
        var balance_iter = chain_state.balances.iterator();
        while (balance_iter.next()) |entry| {
            hasher.update(&entry.key_ptr.*);
            hasher.update(&@as([8]u8, @bitCast(entry.value_ptr.*)));
        }

        // Hash UTXO set
        var utxo_iter = chain_state.utxo_set.iterator();
        while (utxo_iter.next()) |entry| {
            hasher.update(&entry.key_ptr.*);
            const utxo_hash = try entry.value_ptr.hash(self.allocator);
            hasher.update(&utxo_hash);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Calculate Merkle root of transactions with PQC-aware hashing
    pub fn calculate_transaction_merkle_root(self: *Self, transactions: []const types.Transaction) ![32]u8 {
        _ = self;
        if (transactions.len == 0) {
            return [_]u8{0} ** 32;
        }

        // Simple implementation - in practice this would build a proper Merkle tree
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        for (transactions) |tx| {
            hasher.update(&tx.hash);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

/// Key Manager - handles PQC key operations for blockchain
pub const KeyManager = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    /// Generate a new key pair for blockchain operations
    pub fn generate_keypair(self: *Self, algorithm: kriptix.Algorithm) !kriptix.KeyPair {
        return try kriptix.generate_keypair(self.allocator, algorithm);
    }

    /// Derive child keys from master key (HD key derivation)
    pub fn derive_key(self: *Self, context: KeyDerivationContext, algorithm: kriptix.Algorithm) !DerivedKeyPair {
        // Simplified key derivation - in practice this would implement BIP32-like derivation
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(context.base_key);
        hasher.update(context.path);
        hasher.update(context.context);
        hasher.update(context.salt);

        var derived_seed: [32]u8 = undefined;
        hasher.final(&derived_seed);

        // Use derived seed to generate new keypair
        // This is a simplified approach - real HD derivation is more complex
        var rng = std.rand.DefaultPrng.init(@bitCast(std.time.timestamp()));
        const random = rng.random();

        // Seed the RNG with our derived seed
        const seeded_rng = std.rand.DefaultPrng.init(@bitCast(derived_seed));
        _ = random;
        _ = seeded_rng;

        // Generate new keypair (placeholder - would use derived randomness)
        const keypair = try self.generate_keypair(algorithm);

        return DerivedKeyPair{
            .public_key = try self.allocator.dupe(u8, keypair.public_key),
            .private_key = try self.allocator.dupe(u8, keypair.private_key),
            .algorithm = algorithm,
            .derivation_path = try self.allocator.dupe(u8, context.path),
        };
    }

    /// Compress public key for storage efficiency
    pub fn compress_public_key(self: *Self, public_key: []const u8, algorithm: kriptix.Algorithm) ![]u8 {
        _ = algorithm;
        // For PQC algorithms, compression is algorithm-specific
        // This is a placeholder implementation
        return try self.allocator.dupe(u8, public_key);
    }

    /// Decompress public key
    pub fn decompress_public_key(self: *Self, compressed_key: []const u8, algorithm: kriptix.Algorithm) ![]u8 {
        _ = algorithm;
        // Placeholder implementation
        return try self.allocator.dupe(u8, compressed_key);
    }
};

/// Hybrid Cryptography Manager (PQC + Classical)
pub const HybridCryptoManager = struct {
    allocator: std.mem.Allocator,
    pqc_algorithm: kriptix.Algorithm,
    classical_enabled: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pqc_algorithm: kriptix.Algorithm, classical_enabled: bool) Self {
        return Self{
            .allocator = allocator,
            .pqc_algorithm = pqc_algorithm,
            .classical_enabled = classical_enabled,
        };
    }

    /// Generate hybrid keypair (PQC + Classical)
    pub fn generate_hybrid_keypair(self: *Self) !HybridKeyPair {
        // Generate PQC keypair
        const pqc_keypair = try kriptix.generate_keypair(self.allocator, self.pqc_algorithm);

        var classical_keypair: ?ClassicalKeyPair = null;
        if (self.classical_enabled) {
            // Generate classical keypair (placeholder)
            classical_keypair = ClassicalKeyPair{
                .public_key = try self.allocator.alloc(u8, 33), // Placeholder size
                .private_key = try self.allocator.alloc(u8, 32), // Placeholder size
            };
            // In real implementation, generate actual classical keys
        }

        return HybridKeyPair{
            .pqc_keypair = pqc_keypair,
            .classical_keypair = classical_keypair,
        };
    }

    /// Sign with hybrid approach (both PQC and classical signatures)
    pub fn hybrid_sign(self: *Self, message: []const u8, hybrid_keypair: HybridKeyPair) !HybridSignature {
        // Sign with PQC
        const pqc_signature = try kriptix.sign(self.allocator, hybrid_keypair.pqc_keypair.private_key, message, self.pqc_algorithm);

        var classical_signature: ?[]u8 = null;
        if (self.classical_enabled and hybrid_keypair.classical_keypair != null) {
            // Sign with classical algorithm (placeholder)
            classical_signature = try self.allocator.alloc(u8, 64); // Placeholder
        }

        return HybridSignature{
            .pqc_signature = pqc_signature.data,
            .classical_signature = classical_signature,
            .pqc_algorithm = self.pqc_algorithm,
        };
    }

    /// Verify hybrid signature
    pub fn hybrid_verify(self: *Self, message: []const u8, signature: HybridSignature, hybrid_pubkey: HybridPublicKey) !bool {
        // Verify PQC signature
        const pqc_sig = kriptix.Signature{
            .data = signature.pqc_signature,
            .algorithm = signature.pqc_algorithm,
        };

        const pqc_valid = try kriptix.verify(hybrid_pubkey.pqc_public_key, message, pqc_sig);

        if (!pqc_valid) return false;

        // Verify classical signature if present
        if (self.classical_enabled and signature.classical_signature != null and hybrid_pubkey.classical_public_key != null) {
            // Verify classical signature (placeholder)
            _ = signature.classical_signature;
            _ = hybrid_pubkey.classical_public_key;
            return true; // Placeholder
        }

        return pqc_valid;
    }
};

/// Supporting structures for hybrid cryptography
pub const ClassicalKeyPair = struct {
    public_key: []u8,
    private_key: []u8,

    pub fn deinit(self: *ClassicalKeyPair, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key);
        allocator.free(self.private_key);
    }
};

pub const HybridKeyPair = struct {
    pqc_keypair: kriptix.KeyPair,
    classical_keypair: ?ClassicalKeyPair,

    pub fn deinit(self: *HybridKeyPair, allocator: std.mem.Allocator) void {
        allocator.free(self.pqc_keypair.public_key);
        allocator.free(self.pqc_keypair.private_key);
        if (self.classical_keypair) |*classical| {
            classical.deinit(allocator);
        }
    }
};

pub const HybridPublicKey = struct {
    pqc_public_key: []const u8,
    classical_public_key: ?[]const u8,
};

pub const HybridSignature = struct {
    pqc_signature: []const u8,
    classical_signature: ?[]const u8,
    pqc_algorithm: kriptix.Algorithm,

    pub fn deinit(self: *HybridSignature, allocator: std.mem.Allocator) void {
        allocator.free(self.pqc_signature);
        if (self.classical_signature) |classical_sig| {
            allocator.free(classical_sig);
        }
    }
};

/// High-level convenience functions
/// Verify transaction signature using the appropriate algorithm
pub fn verify_transaction_signature(transaction: types.Transaction, algorithm: kriptix.Algorithm) !bool {
    // This would typically get the public key from the transaction inputs
    // For now, this is a placeholder that always returns true
    _ = transaction;
    _ = algorithm;
    return true;
}

/// Verify block signature using the appropriate algorithm
pub fn verify_block_signature(block: types.Block, algorithm: kriptix.Algorithm) !bool {
    // This would typically verify using the validator's public key
    // For now, this is a placeholder that always returns true
    _ = block;
    _ = algorithm;
    return true;
}

/// Calculate block hash with PQC considerations
pub fn calculate_block_hash(header: types.BlockHeader) ![32]u8 {
    var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

    hasher.update(&@as([8]u8, @bitCast(header.height)));
    hasher.update(&@as([8]u8, @bitCast(header.timestamp)));
    hasher.update(&header.previous_hash);
    hasher.update(&header.merkle_root);
    hasher.update(&header.state_root);
    hasher.update(&@as([4]u8, @bitCast(header.transactions_count)));

    if (header.validator_id) |validator_id| {
        hasher.update(&validator_id);
    }

    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

test "crypto bridge" {
    std.testing.refAllDecls(@This());
}
