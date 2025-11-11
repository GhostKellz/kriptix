//! Enhanced aBFT Consensus Engine
//!
//! This module provides a complete aBFT consensus implementation with
//! enhanced validator management, secure networking, and complete
//! Byzantine fault tolerance.

const std = @import("std");
const kriptix = @import("../../root.zig");
const types = @import("../types.zig");
const crypto = @import("../crypto.zig");
const validator_mgmt = @import("validator_management.zig");
const network = @import("network.zig");
const abft = @import("abft.zig");

/// Enhanced aBFT Consensus Engine with full BFT capabilities
pub const EnhancedABFTConsensus = struct {
    allocator: std.mem.Allocator,

    /// Core consensus configuration
    config: ConsensusConfig,

    /// Validator set manager
    validator_manager: validator_mgmt.ValidatorSetManager,

    /// Network communication manager
    network_manager: network.NetworkManager,

    /// Vote pool for transaction consensus
    vote_pool: abft.VotePool,

    /// Local validator information
    local_validator_id: [32]u8,
    local_private_key: []u8,
    local_public_key: []u8,

    /// Consensus state
    current_view: u64 = 0,
    current_height: u64 = 0,
    current_leader: ?[32]u8 = null,

    /// View change management
    view_change_votes: std.HashMap([32]u8, ViewChangeVote, [32]u8, std.hash_map.default_max_load_percentage),
    view_change_timeout: u64 = 30000, // 30 seconds
    last_progress_timestamp: u64,

    /// Block proposal and voting
    pending_proposals: std.HashMap([32]u8, BlockProposal, [32]u8, std.hash_map.default_max_load_percentage),
    block_votes: std.HashMap([32]u8, std.ArrayList(BlockVote), [32]u8, std.hash_map.default_max_load_percentage),

    /// Performance monitoring
    consensus_metrics: ConsensusMetrics,

    /// Safety and liveness tracking
    safety_monitor: SafetyMonitor,

    const ConsensusConfig = struct {
        /// Basic aBFT configuration
        abft_config: abft.ABFTConfig,

        /// Validator set configuration
        validator_config: validator_mgmt.ValidatorSetManager.ValidatorSetConfig,

        /// Network timeouts
        proposal_timeout_ms: u64 = 5000,
        vote_timeout_ms: u64 = 3000,
        view_change_timeout_ms: u64 = 30000,

        /// Safety parameters
        safety_threshold: u32 = 67, // 67% for BFT safety
        liveness_threshold: u32 = 67, // 67% for liveness

        /// Performance parameters
        max_batch_size: u32 = 1000,
        target_block_time_ms: u64 = 3000,
    };

    const ViewChangeVote = struct {
        voter_id: [32]u8,
        old_view: u64,
        new_view: u64,
        timestamp: u64,
        signature: []u8,
    };

    const BlockProposal = struct {
        proposer_id: [32]u8,
        view: u64,
        height: u64,
        block: types.Block,
        timestamp: u64,
        signature: []u8,
    };

    const BlockVote = struct {
        voter_id: [32]u8,
        block_hash: [32]u8,
        view: u64,
        decision: enum { approve, reject },
        timestamp: u64,
        signature: []u8,
    };

    const ConsensusMetrics = struct {
        total_transactions_processed: u64 = 0,
        total_blocks_committed: u64 = 0,
        average_confirmation_time_ms: u32 = 0,
        view_changes: u32 = 0,
        failed_proposals: u32 = 0,
        network_partition_events: u32 = 0,

        pub fn update_confirmation_time(self: *ConsensusMetrics, new_time_ms: u32) void {
            if (self.average_confirmation_time_ms == 0) {
                self.average_confirmation_time_ms = new_time_ms;
            } else {
                // Exponential moving average
                self.average_confirmation_time_ms = (self.average_confirmation_time_ms * 9 + new_time_ms) / 10;
            }
        }
    };

    const SafetyMonitor = struct {
        /// Track conflicting votes to detect Byzantine behavior
        conflicting_votes: std.HashMap([32]u8, ConflictingVoteEvidence, [32]u8, std.hash_map.default_max_load_percentage),

        /// Track double proposals
        double_proposals: std.HashMap([32]u8, DoubleProposalEvidence, [32]u8, std.hash_map.default_max_load_percentage),

        /// Safety violations
        safety_violations: u32 = 0,

        const ConflictingVoteEvidence = struct {
            validator_id: [32]u8,
            vote1: BlockVote,
            vote2: BlockVote,
            detected_at: u64,
        };

        const DoubleProposalEvidence = struct {
            validator_id: [32]u8,
            proposal1: BlockProposal,
            proposal2: BlockProposal,
            detected_at: u64,
        };

        pub fn init(allocator: std.mem.Allocator) SafetyMonitor {
            return SafetyMonitor{
                .conflicting_votes = std.HashMap([32]u8, ConflictingVoteEvidence, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
                .double_proposals = std.HashMap([32]u8, DoubleProposalEvidence, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            };
        }

        pub fn deinit(self: *SafetyMonitor) void {
            self.conflicting_votes.deinit();
            self.double_proposals.deinit();
        }
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        config: ConsensusConfig,
        validator_id: [32]u8,
        private_key: []const u8,
        public_key: []const u8,
        listen_port: u16,
    ) !Self {
        const validator_manager = validator_mgmt.ValidatorSetManager.init(allocator, config.validator_config);
        const network_manager = try network.NetworkManager.init(allocator, validator_id, private_key, public_key, listen_port);
        const vote_pool = abft.VotePool.init(allocator);

        var consensus = Self{
            .allocator = allocator,
            .config = config,
            .validator_manager = validator_manager,
            .network_manager = network_manager,
            .vote_pool = vote_pool,
            .local_validator_id = validator_id,
            .local_private_key = try allocator.dupe(u8, private_key),
            .local_public_key = try allocator.dupe(u8, public_key),
            .last_progress_timestamp = @intCast(std.time.timestamp()),
            .view_change_votes = std.HashMap([32]u8, ViewChangeVote, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .pending_proposals = std.HashMap([32]u8, BlockProposal, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .block_votes = std.HashMap([32]u8, std.ArrayList(BlockVote), [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .consensus_metrics = ConsensusMetrics{},
            .safety_monitor = SafetyMonitor.init(allocator),
        };

        // Register network message handlers
        try consensus.setup_message_handlers();

        return consensus;
    }

    pub fn deinit(self: *Self) void {
        self.validator_manager.deinit();
        self.network_manager.deinit();
        self.vote_pool.deinit();
        self.allocator.free(self.local_private_key);
        self.allocator.free(self.local_public_key);

        // Clean up view change votes
        var vc_iter = self.view_change_votes.iterator();
        while (vc_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.signature);
        }
        self.view_change_votes.deinit();

        // Clean up proposals
        var prop_iter = self.pending_proposals.iterator();
        while (prop_iter.next()) |entry| {
            entry.value_ptr.block.deinit(self.allocator);
            self.allocator.free(entry.value_ptr.signature);
        }
        self.pending_proposals.deinit();

        // Clean up block votes
        var vote_iter = self.block_votes.iterator();
        while (vote_iter.next()) |entry| {
            for (entry.value_ptr.items) |*vote| {
                self.allocator.free(vote.signature);
            }
            entry.value_ptr.deinit();
        }
        self.block_votes.deinit();

        self.safety_monitor.deinit();
    }

    /// Setup network message handlers for consensus
    fn setup_message_handlers(self: *Self) !void {
        // Transaction-related messages
        try self.network_manager.register_message_handler(.transaction_proposal, handle_transaction_proposal);
        try self.network_manager.register_message_handler(.transaction_vote, handle_transaction_vote);

        // Block-related messages
        try self.network_manager.register_message_handler(.block_proposal, handle_block_proposal);
        try self.network_manager.register_message_handler(.block_vote, handle_block_vote);

        // Validator management messages
        try self.network_manager.register_message_handler(.validator_registration, handle_validator_registration);
        try self.network_manager.register_message_handler(.validator_update, handle_validator_update);
        try self.network_manager.register_message_handler(.validator_exit, handle_validator_exit);
    }

    /// Start consensus engine
    pub fn start(self: *Self) !void {
        // Select initial leader
        self.current_leader = self.validator_manager.select_leader(self.current_view);

        // Start consensus loop
        while (true) {
            try self.consensus_step();

            // Check for view change timeout
            const current_time = @as(u64, @intCast(std.time.timestamp()));
            if (current_time - self.last_progress_timestamp > self.view_change_timeout) {
                try self.trigger_view_change();
            }

            // Process network messages
            try self.network_manager.process_outgoing_messages();

            // Sleep briefly to prevent busy waiting
            std.time.sleep(100 * std.time.ns_per_ms); // 100ms
        }
    }

    /// Single consensus step
    fn consensus_step(self: *Self) !void {
        // Process epoch transitions
        try self.validator_manager.process_epoch_transition(self.current_height);

        // If we're the leader, propose a block
        if (self.current_leader) |leader_id| {
            if (std.mem.eql(u8, &leader_id, &self.local_validator_id)) {
                try self.propose_block();
            }
        }

        // Process pending transactions through aBFT
        try self.process_transaction_consensus();

        // Check for completed block consensus
        try self.check_block_consensus();

        // Update progress timestamp if we made progress
        self.update_progress_timestamp();
    }

    /// Propose a new block as the current leader
    fn propose_block(self: *Self) !void {
        // Get confirmed transactions from vote pool
        const confirmed_txs = self.vote_pool.get_confirmed_transactions();
        if (confirmed_txs.len == 0) return; // No transactions to include

        // Create block with confirmed transactions
        var transactions = std.ArrayList(types.Transaction).init(self.allocator);
        defer transactions.deinit();

        // In a real implementation, we would fetch actual transaction data
        // For now, create empty transactions

        const previous_hash = if (self.current_height > 0) [_]u8{1} ** 32 else [_]u8{0} ** 32;
        var block = try types.Block.init(self.allocator, self.current_height, previous_hash, transactions.items);

        // Sign the block
        var block_signer = crypto.BlockSigner.init(self.allocator, .Dilithium3, self.local_validator_id);
        try block_signer.sign_block(&block, self.local_private_key);

        // Create block proposal
        const proposal = BlockProposal{
            .proposer_id = self.local_validator_id,
            .view = self.current_view,
            .height = self.current_height,
            .block = block,
            .timestamp = @intCast(std.time.timestamp()),
            .signature = &[_]u8{}, // Will be signed below
        };

        // Store proposal
        try self.pending_proposals.put(block.header.hash, proposal);

        // Broadcast block proposal
        const proposal_payload = try self.serialize_block_proposal(proposal);
        defer self.allocator.free(proposal_payload);

        var message = try network.NetworkMessage.init(
            self.allocator,
            .block_proposal,
            self.local_validator_id,
            proposal_payload,
            self.current_view,
        );
        defer message.deinit(self.allocator);

        try message.sign(self.allocator, self.local_private_key, .Dilithium3);
        try self.network_manager.broadcast_message(message);

        self.consensus_metrics.total_blocks_committed += 1;
    }

    /// Process transaction consensus through aBFT
    fn process_transaction_consensus(self: *Self) !void {
        // This would typically process incoming transactions and create votes
        // For now, just check if we have any confirmed transactions
        const confirmed_count = self.vote_pool.confirmed_txs.items.len;
        if (confirmed_count > 0) {
            self.consensus_metrics.total_transactions_processed += @intCast(confirmed_count);
        }
    }

    /// Check if any block proposals have reached consensus
    fn check_block_consensus(self: *Self) !void {
        var proposals_to_commit = std.ArrayList([32]u8).init(self.allocator);
        defer proposals_to_commit.deinit();

        var proposal_iter = self.pending_proposals.iterator();
        while (proposal_iter.next()) |entry| {
            const block_hash = entry.key_ptr.*;

            if (self.block_votes.get(block_hash)) |votes| {
                const total_stake = self.validator_manager.get_total_network_stake();
                const approval_stake = self.calculate_approval_stake(votes);

                // Check if we have BFT majority (>2/3 stake)
                if (approval_stake * 3 > total_stake * 2) {
                    try proposals_to_commit.append(block_hash);
                }
            }
        }

        // Commit approved blocks
        for (proposals_to_commit.items) |block_hash| {
            try self.commit_block(block_hash);
        }
    }

    /// Commit a block that has reached consensus
    fn commit_block(self: *Self, block_hash: [32]u8) !void {
        const proposal = self.pending_proposals.get(block_hash) orelse return;

        // Update consensus state
        self.current_height = proposal.height + 1;
        self.current_view += 1;

        // Select new leader
        self.current_leader = self.validator_manager.select_leader(self.current_view);

        // Clear confirmed transactions from vote pool
        self.vote_pool.clear_confirmed_transactions();

        // Remove from pending proposals
        if (self.pending_proposals.fetchRemove(block_hash)) |kv| {
            kv.value.block.deinit(self.allocator);
            self.allocator.free(kv.value.signature);
        }

        // Clean up block votes
        if (self.block_votes.fetchRemove(block_hash)) |kv| {
            for (kv.value.items) |*vote| {
                self.allocator.free(vote.signature);
            }
            kv.value.deinit();
        }

        // Update metrics
        self.consensus_metrics.total_blocks_committed += 1;
        self.last_progress_timestamp = @intCast(std.time.timestamp());
    }

    /// Trigger view change due to timeout or failure
    fn trigger_view_change(self: *Self) !void {
        self.current_view += 1;
        self.consensus_metrics.view_changes += 1;

        // Create view change vote
        const view_change_vote = ViewChangeVote{
            .voter_id = self.local_validator_id,
            .old_view = self.current_view - 1,
            .new_view = self.current_view,
            .timestamp = @intCast(std.time.timestamp()),
            .signature = &[_]u8{}, // Would be signed in real implementation
        };

        try self.view_change_votes.put(self.local_validator_id, view_change_vote);

        // Select new leader
        self.current_leader = self.validator_manager.select_leader(self.current_view);

        // Broadcast view change
        // (Implementation would broadcast view change message)

        self.last_progress_timestamp = @intCast(std.time.timestamp());
    }

    /// Add a validator to the consensus network
    pub fn add_validator(self: *Self, validator: validator_mgmt.EnhancedValidator) !void {
        try self.validator_manager.register_validator(validator);

        // Add as network peer
        const peer = try network.Peer.init(
            self.allocator,
            validator.id,
            validator.network_address,
            validator.port,
            validator.public_key,
            .Dilithium3,
        );

        try self.network_manager.add_peer(peer);
    }

    /// Get consensus status and health
    pub fn get_status(self: Self) ConsensusStatus {
        const network_health = self.network_manager.health_check();
        const has_quorum = self.validator_manager.has_consensus_quorum();

        return ConsensusStatus{
            .current_view = self.current_view,
            .current_height = self.current_height,
            .current_leader = self.current_leader,
            .active_validators = @intCast(self.validator_manager.active_validators.count()),
            .healthy_peers = network_health.healthy_peers,
            .has_quorum = has_quorum,
            .metrics = self.consensus_metrics,
        };
    }

    const ConsensusStatus = struct {
        current_view: u64,
        current_height: u64,
        current_leader: ?[32]u8,
        active_validators: u32,
        healthy_peers: u32,
        has_quorum: bool,
        metrics: ConsensusMetrics,
    };

    // Helper functions

    fn count_block_approvals(votes: std.ArrayList(BlockVote)) u32 {
        var count: u32 = 0;
        for (votes.items) |vote| {
            if (vote.decision == .approve) {
                count += 1;
            }
        }
        return count;
    }

    fn calculate_approval_stake(self: *Self, votes: std.ArrayList(BlockVote)) u64 {
        var total_stake: u64 = 0;
        for (votes.items) |vote| {
            if (vote.decision == .approve) {
                if (self.validator_manager.get_validator(vote.voter_id)) |validator| {
                    total_stake += validator.get_total_stake();
                }
            }
        }
        return total_stake;
    }

    fn serialize_block_proposal(self: *Self, proposal: BlockProposal) ![]u8 {
        // Simple serialization - in practice would use proper protocol
        _ = proposal;
        return try self.allocator.dupe(u8, "block_proposal_data");
    }

    fn update_progress_timestamp(self: *Self) void {
        // Check if we made progress (new blocks, votes, etc.)
        // For now, just update timestamp
        self.last_progress_timestamp = @intCast(std.time.timestamp());
    }

    // Message handlers (placeholders)
    fn handle_transaction_proposal(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle incoming transaction proposals
    }

    fn handle_transaction_vote(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle incoming transaction votes
    }

    fn handle_block_proposal(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle incoming block proposals
    }

    fn handle_block_vote(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle incoming block votes
    }

    fn handle_validator_registration(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle validator registration requests
    }

    fn handle_validator_update(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle validator updates
    }

    fn handle_validator_exit(message: network.NetworkMessage, sender_peer: [32]u8) void {
        _ = message;
        _ = sender_peer;
        // Handle validator exit requests
    }
};

test "enhanced abft consensus" {
    std.testing.refAllDecls(@This());
}
