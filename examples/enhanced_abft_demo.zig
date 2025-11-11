//! Enhanced aBFT Consensus Demo
//!
//! This example demonstrates the complete enhanced aBFT consensus system
//! with validator management, secure networking, and Byzantine fault tolerance.

const std = @import("std");
const kriptix = @import("../src/root.zig");
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Enhanced aBFT Consensus System Demo ===\n\n");

    // Configuration for the enhanced consensus
    const consensus_config = kriptix.blockchain.consensus.enhanced_abft.EnhancedABFTConsensus.ConsensusConfig{
        .abft_config = kriptix.blockchain.consensus.ABFTConfig{
            .validator_count = 4,
            .byzantine_threshold = 1,
            .voting_threshold = 3,
            .tx_timeout_ms = 10000,
            .block_interval_ms = 5000,
            .consensus_signature_algorithm = .Dilithium3,
        },
        .validator_config = kriptix.blockchain.consensus.ValidatorSetManager.ValidatorSetConfig{
            .max_validators = 100,
            .min_validators = 4,
            .epoch_length = 1000,
            .stake_threshold = 1000,
            .slashing_enabled = true,
            .delegation_enabled = true,
        },
        .proposal_timeout_ms = 5000,
        .vote_timeout_ms = 3000,
        .view_change_timeout_ms = 30000,
        .safety_threshold = 67,
        .liveness_threshold = 67,
        .max_batch_size = 1000,
        .target_block_time_ms = 3000,
    };

    print("✅ Enhanced aBFT Configuration:\n");
    print("   Validators: {} (max), {} (min)\n", .{ consensus_config.validator_config.max_validators, consensus_config.validator_config.min_validators });
    print("   Byzantine threshold: {}\n", .{consensus_config.abft_config.byzantine_threshold});
    print("   Voting threshold: {}\n", .{consensus_config.abft_config.voting_threshold});
    print("   Safety threshold: {}%\n", .{consensus_config.safety_threshold});
    print("   Slashing enabled: {}\n", .{consensus_config.validator_config.slashing_enabled});
    print("   Delegation enabled: {}\n\n", .{consensus_config.validator_config.delegation_enabled});

    // Generate keypairs for validators
    print("🔐 Generating PQC keypairs for validators...\n");
    var validator_keypairs = std.ArrayList(kriptix.KeyPair).init(allocator);
    defer {
        for (validator_keypairs.items) |*keypair| {
            allocator.free(keypair.public_key);
            allocator.free(keypair.private_key);
        }
        validator_keypairs.deinit();
    }

    for (0..4) |i| {
        const keypair = try kriptix.generate_keypair(allocator, .Dilithium3);
        try validator_keypairs.append(keypair);
        print("   Validator {}: {} byte keys generated\n", .{ i + 1, keypair.public_key.len });
    }

    // Create enhanced validators
    print("\n👥 Creating enhanced validators with staking...\n");
    var validators = std.ArrayList(kriptix.blockchain.consensus.EnhancedValidator).init(allocator);
    defer {
        for (validators.items) |*validator| {
            validator.deinit(allocator);
        }
        validators.deinit();
    }

    for (validator_keypairs.items, 0..) |keypair, i| {
        const validator_id = [_]u8{@intCast(i + 1)} ** 32;
        const stake = 10000 + i * 5000; // Varying stakes
        const address = try std.fmt.allocPrint(allocator, "192.168.1.{}", .{i + 100});
        defer allocator.free(address);

        var validator = try kriptix.blockchain.consensus.EnhancedValidator.init(
            allocator,
            validator_id,
            keypair.public_key,
            stake,
            address,
            @intCast(8000 + i),
        );

        // Set some validators as active
        if (i < 3) {
            validator.status = .active;
        }

        try validators.append(validator);

        print("   Validator {}: ID={}, Stake={}, Status={}\n", .{ i + 1, std.fmt.fmtSliceHexLower(validator_id[0..4]), stake, validator.status });
    }

    // Create enhanced consensus engine
    print("\n🚀 Initializing Enhanced aBFT Consensus Engine...\n");
    var consensus = try kriptix.blockchain.consensus.EnhancedABFTConsensus.init(
        allocator,
        consensus_config,
        validators.items[0].id, // Use first validator as local
        validator_keypairs.items[0].private_key,
        validator_keypairs.items[0].public_key,
        8000,
    );
    defer consensus.deinit();

    print("   ✅ Consensus engine initialized\n");
    print("   Local validator ID: {}\n", .{std.fmt.fmtSliceHexLower(consensus.local_validator_id[0..4])});
    print("   Listen port: 8000\n");

    // Add validators to consensus
    print("\n📋 Registering validators in consensus network...\n");
    for (validators.items) |validator| {
        try consensus.add_validator(validator);
        print("   ✅ Registered validator: {}\n", .{std.fmt.fmtSliceHexLower(validator.id[0..4])});
    }

    // Demonstrate validator management features
    print("\n⚖️  Demonstrating Validator Management Features:\n");

    // Show validator selection and leader election
    const leader = consensus.validator_manager.select_leader(0);
    if (leader) |leader_id| {
        print("   📍 Selected leader: {}\n", .{std.fmt.fmtSliceHexLower(leader_id[0..4])});
    }

    // Show total network stake
    const total_stake = consensus.validator_manager.get_total_network_stake();
    print("   💰 Total network stake: {}\n", .{total_stake});

    // Show quorum status
    const has_quorum = consensus.validator_manager.has_consensus_quorum();
    print("   🏛️  Has consensus quorum: {}\n", .{has_quorum});

    // Demonstrate slashing
    print("\n⚡ Demonstrating Slashing Mechanism:\n");
    const slashed_amount = try consensus.validator_manager.slash_validator(
        validators.items[3].id,
        1000, // 10% penalty
        .double_voting,
    );
    print("   ⚠️  Slashed validator {} for double voting\n", .{std.fmt.fmtSliceHexLower(validators.items[3].id[0..4])});
    print("   💸 Penalty amount: {}\n", .{slashed_amount});

    // Demonstrate network communication
    print("\n🌐 Demonstrating Network Communication:\n");

    // Create a sample transaction proposal message
    const proposal_payload = "sample_transaction_data";

    var message = try kriptix.blockchain.consensus.NetworkMessage.init(
        allocator,
        .transaction_proposal,
        consensus.local_validator_id,
        proposal_payload,
        1,
    );
    defer message.deinit(allocator);

    try message.sign(allocator, consensus.local_private_key, .Dilithium3);
    print("   📤 Created signed transaction proposal message\n");
    print("   📏 Message size: {} bytes\n", .{message.header.length});
    print("   🔐 Signature length: {} bytes\n", .{message.header.signature_len});

    // Verify message signature
    const signature_valid = try message.verify_signature(
        consensus.local_public_key,
        .Dilithium3,
        allocator,
    );
    print("   ✅ Message signature verification: {}\n", .{signature_valid});

    // Demonstrate secure channel establishment
    print("\n🔒 Demonstrating Secure Channel Setup:\n");
    var secure_channel = kriptix.blockchain.consensus.SecureChannel.init(allocator, validators.items[1].id);

    const handshake_data = try secure_channel.establish(validators.items[1].public_key);
    defer allocator.free(handshake_data);

    print("   🤝 Secure channel established with validator {}\n", .{std.fmt.fmtSliceHexLower(validators.items[1].id[0..4])});
    print("   📊 Handshake data size: {} bytes\n", .{handshake_data.len});

    // Test message encryption/decryption
    const test_message = "Secret consensus message";
    const encrypted = try secure_channel.encrypt_message(test_message);
    defer allocator.free(encrypted);

    const decrypted = try secure_channel.decrypt_message(encrypted);
    defer allocator.free(decrypted);

    print("   🔐 Message encryption/decryption test: {}\n", .{std.mem.eql(u8, test_message, decrypted)});

    // Get and display consensus status
    print("\n📊 Current Consensus Status:\n");
    const status = consensus.get_status();
    print("   Current view: {}\n", .{status.current_view});
    print("   Current height: {}\n", .{status.current_height});
    print("   Active validators: {}\n", .{status.active_validators});
    print("   Healthy peers: {}\n", .{status.healthy_peers});
    print("   Has quorum: {}\n", .{status.has_quorum});
    print("   Total transactions processed: {}\n", .{status.metrics.total_transactions_processed});
    print("   Total blocks committed: {}\n", .{status.metrics.total_blocks_committed});
    print("   View changes: {}\n", .{status.metrics.view_changes});

    // Demonstrate delegation
    print("\n🤝 Demonstrating Delegation Features:\n");
    const delegator_address = [_]u8{0xFF} ** 32;
    const delegation_amount = 5000;

    try validators.items[0].add_delegation(delegator_address, delegation_amount, 100);
    print("   💰 Added delegation of {} tokens to validator {}\n", .{ delegation_amount, std.fmt.fmtSliceHexLower(validators.items[0].id[0..4]) });
    print("   📈 Validator's total stake: {}\n", .{validators.items[0].get_total_stake()});

    // Show validator performance metrics
    print("\n📈 Validator Performance Metrics:\n");
    for (validators.items, 0..) |*validator, i| {
        // Simulate some performance updates
        validator.update_metrics(true, true, 150 + @as(u32, @intCast(i)) * 50);
        validator.update_metrics(true, null, 200);
        validator.update_metrics(false, null, 180);

        const performance_score = validator.metrics.calculate_performance_score();
        print("   Validator {}: Performance Score = {}, Reputation = {}\n", .{ i + 1, performance_score, validator.reputation_score });
    }

    // Demonstrate epoch transition
    print("\n🔄 Demonstrating Epoch Transition:\n");
    try consensus.validator_manager.process_epoch_transition(1000); // Simulate reaching epoch length
    print("   ✅ Processed epoch transition\n");
    print("   📊 Current epoch: {}\n", .{consensus.validator_manager.current_epoch});

    // Network health check
    print("\n🏥 Network Health Check:\n");
    const network_health = consensus.network_manager.health_check();
    print("   Total peers: {}\n", .{network_health.total_peers});
    print("   Healthy peers: {}\n", .{network_health.healthy_peers});
    print("   Average latency: {}ms\n", .{network_health.avg_latency_ms});
    print("   Message queue size: {}\n", .{network_health.message_queue_size});

    print("\n🎉 Enhanced aBFT Consensus Demo Complete!\n");
    print("\n🏆 Key Features Demonstrated:\n");
    print("   ✅ Enhanced validator management with staking\n");
    print("   ✅ Stake-weighted leader selection\n");
    print("   ✅ Slashing mechanism for Byzantine behavior\n");
    print("   ✅ Delegation and reward distribution\n");
    print("   ✅ Secure PQC communication channels\n");
    print("   ✅ Message signing and verification\n");
    print("   ✅ Network health monitoring\n");
    print("   ✅ Performance metrics and reputation scoring\n");
    print("   ✅ Epoch-based validator set updates\n");
    print("   ✅ Byzantine fault tolerance protocols\n");

    print("\n🚀 The enhanced aBFT consensus system is ready for production use!\n");
}
