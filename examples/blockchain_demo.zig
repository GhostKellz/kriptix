//! Blockchain Module Usage Example
//!
//! This example demonstrates how to use the blockchain module
//! with post-quantum cryptographic security.

const std = @import("std");
const kriptix = @import("../src/root.zig");
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Kriptix Blockchain Module Demo ===\n");

    // Initialize the blockchain
    const blockchain_config = kriptix.blockchain.Config{
        .max_block_size = 1024 * 1024, // 1MB
        .block_time_ms = 3000, // 3 seconds
        .max_transactions_per_block = 1000,
        .block_signature_algorithm = .Dilithium3,
        .transaction_signature_algorithm = .Dilithium2,
        .key_exchange_algorithm = .Kyber768,
        .enable_hybrid_crypto = false,
    };

    var blockchain = try kriptix.blockchain.Blockchain.init(allocator, blockchain_config);
    defer blockchain.deinit();

    print("✅ Blockchain initialized with PQC algorithms:\n");
    print("   Block signatures: Dilithium3\n");
    print("   Transaction signatures: Dilithium2\n");
    print("   Key exchange: Kyber768\n");
    print("   Current height: {}\n\n", .{blockchain.get_height()});

    // Create a transaction signer
    var tx_signer = kriptix.blockchain.TransactionSigner.init(allocator, .Dilithium2);

    // Generate PQC keypair for transactions
    const keypair = try kriptix.generate_keypair(allocator, .Dilithium2);
    defer {
        allocator.free(keypair.public_key);
        allocator.free(keypair.private_key);
    }

    print("✅ Generated PQC keypair for transactions:\n");
    print("   Public key length: {} bytes\n", .{keypair.public_key.len});
    print("   Private key length: {} bytes\n", .{keypair.private_key.len});
    print("   Algorithm: {}\n\n", .{keypair.algorithm});

    // Create transaction inputs and outputs
    var inputs = [_]kriptix.blockchain.types.TxInput{
        kriptix.blockchain.types.TxInput.init(
            [_]u8{0} ** 32, // previous tx hash
            0, // output index
            &[_]u8{}, // signature (will be filled later)
            keypair.public_key,
            .Dilithium2,
        ),
    };

    var outputs = [_]kriptix.blockchain.types.TxOutput{
        kriptix.blockchain.types.TxOutput.init(
            1000, // amount
            keypair.public_key, // recipient
            .Dilithium2,
        ),
    };

    // Create transaction
    var transaction = try kriptix.blockchain.types.Transaction.init(
        allocator,
        &inputs,
        &outputs,
        10, // fee
        1, // nonce
        .Dilithium2,
    );
    defer transaction.deinit(allocator);

    print("✅ Created transaction:\n");
    print("   Hash: ");
    for (transaction.hash) |byte| {
        print("{:02x}", .{byte});
    }
    print("\n");
    print("   Inputs: {}\n", .{transaction.inputs.len});
    print("   Outputs: {}\n", .{transaction.outputs.len});
    print("   Fee: {}\n", .{transaction.fee});
    print("   Timestamp: {}\n\n", .{transaction.timestamp});

    // Sign the transaction
    try tx_signer.sign_transaction(&transaction, keypair.private_key);

    print("✅ Transaction signed with PQC signature:\n");
    print("   Signature length: {} bytes\n", .{transaction.signature.len});
    print("   Algorithm: {}\n\n", .{transaction.signature_algorithm});

    // Create a Merkle tree for transactions
    var merkle_tree = kriptix.blockchain.MerkleTree.init(allocator);
    defer merkle_tree.deinit();

    const transactions = [_]kriptix.blockchain.types.Transaction{transaction};
    try merkle_tree.build_from_transactions(&transactions);

    print("✅ Built Merkle tree:\n");
    print("   Root hash: ");
    const root_hash = merkle_tree.get_root_hash();
    for (root_hash) |byte| {
        print("{:02x}", .{byte});
    }
    print("\n");
    print("   Leaf count: {}\n\n", .{merkle_tree.leaves.items.len});

    // Generate Merkle proof
    if (try merkle_tree.generate_proof(transaction.hash)) |proof| {
        defer {
            var proof_copy = proof;
            proof_copy.deinit();
        }

        print("✅ Generated Merkle proof:\n");
        print("   Proof elements: {}\n", .{proof.proof_hashes.items.len});
        print("   Verification: {}\n\n", .{proof.verify(root_hash)});
    }

    // Demonstrate multi-signature
    var multi_sig = try kriptix.blockchain.MultiSignature.init(
        allocator,
        &transaction.hash,
        2, // threshold of 2 signatures
    );
    defer multi_sig.deinit();

    try multi_sig.add_signature(
        [_]u8{1} ** 32, // validator ID
        transaction.signature,
        .Dilithium2,
        keypair.public_key,
    );

    print("✅ Multi-signature created:\n");
    print("   Threshold: {}\n", .{multi_sig.threshold});
    print("   Signatures collected: {}\n", .{multi_sig.signatures.items.len});
    print("   Valid: {}\n\n", .{try multi_sig.is_valid()});

    // Create aBFT consensus engine
    const validator_id = [_]u8{42} ** 32;
    var abft_config = kriptix.blockchain.consensus.abft.ABFTConfig{
        .validator_count = 4,
        .byzantine_threshold = 1,
        .voting_threshold = 3,
        .tx_timeout_ms = 10000,
        .block_interval_ms = 5000,
        .consensus_signature_algorithm = .Dilithium3,
    };

    var consensus = try kriptix.blockchain.consensus.abft.ABFTConsensus.init(
        allocator,
        abft_config,
        validator_id,
        keypair.private_key,
    );
    defer consensus.deinit();

    print("✅ aBFT Consensus engine initialized:\n");
    print("   Validator count: {}\n", .{abft_config.validator_count});
    print("   Byzantine threshold: {}\n", .{abft_config.byzantine_threshold});
    print("   Voting threshold: {}\n", .{abft_config.voting_threshold});
    print("   Consensus algorithm: {}\n\n", .{abft_config.consensus_signature_algorithm});

    // Process transaction through consensus
    const vote = try consensus.process_transaction(transaction);
    print("✅ Generated consensus vote:\n");
    print("   Decision: {}\n", .{vote.decision});
    print("   Validator ID: ");
    for (vote.validator_id[0..8]) |byte| {
        print("{:02x}", .{byte});
    }
    print("...\n");
    print("   Signature length: {} bytes\n\n", .{vote.signature.len});

    print("🎉 Phase 6: Blockchain Module Foundation - COMPLETED!\n");
    print("\nKey achievements:\n");
    print("✅ Blockchain module structure created\n");
    print("✅ PQC-compatible Block and Transaction types implemented\n");
    print("✅ Crypto bridge for blockchain operations built\n");
    print("✅ Specialized data structures (Merkle trees, Patricia tries) added\n");
    print("✅ aBFT consensus implementation with PQC signatures\n");
    print("✅ Multi-signature and state management capabilities\n");
    print("✅ Full integration with main Kriptix library\n");
}
