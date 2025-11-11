//! Enhanced Validator Management System
//!
//! This module provides comprehensive validator management for aBFT consensus
//! including stake-weighted voting, registration/deregistration, slashing,
//! and advanced validator lifecycle management.

const std = @import("std");
const kriptix = @import("../../root.zig");
const crypto = @import("../crypto.zig");
const types = @import("../types.zig");

/// Validator status enumeration
pub const ValidatorStatus = enum {
    /// Validator is active and participating in consensus
    active,
    /// Validator is temporarily inactive (maintenance, etc.)
    inactive,
    /// Validator is being removed from the set
    exiting,
    /// Validator has been slashed and is banned
    slashed,
    /// Validator registration is pending
    pending,
};

/// Validator performance metrics
pub const ValidatorMetrics = struct {
    /// Total number of votes cast
    votes_cast: u64 = 0,
    /// Number of votes that were correct
    correct_votes: u64 = 0,
    /// Number of blocks proposed
    blocks_proposed: u64 = 0,
    /// Number of valid blocks proposed
    valid_blocks: u64 = 0,
    /// Last activity timestamp
    last_activity: u64 = 0,
    /// Uptime percentage (0-10000 for 0.00% to 100.00%)
    uptime_bps: u16 = 0,
    /// Response time average in milliseconds
    avg_response_time_ms: u32 = 0,

    pub fn calculate_performance_score(self: ValidatorMetrics) u32 {
        if (self.votes_cast == 0) return 0;

        const vote_accuracy = (self.correct_votes * 100) / self.votes_cast;
        const block_success_rate = if (self.blocks_proposed > 0)
            (self.valid_blocks * 100) / self.blocks_proposed
        else
            100;

        // Weighted performance score (0-100)
        return @intCast((vote_accuracy * 4 + block_success_rate * 3 + self.uptime_bps / 100 * 3) / 10);
    }
};

/// Enhanced validator structure with comprehensive management
pub const EnhancedValidator = struct {
    /// Basic validator information
    id: [32]u8,
    public_key: []u8,

    /// Staking information
    stake: u64,
    delegated_stake: u64 = 0,
    minimum_stake: u64 = 1000,

    /// Status and lifecycle
    status: ValidatorStatus = .pending,
    registration_height: u64 = 0,
    activation_height: u64 = 0,
    exit_height: ?u64 = null,

    /// Performance and reputation
    metrics: ValidatorMetrics,
    slashing_count: u32 = 0,
    reputation_score: u32 = 100, // 0-100

    /// Network information
    network_address: []u8,
    port: u16,
    supported_algorithms: []kriptix.Algorithm,

    /// Delegation information
    delegators: std.ArrayList(Delegator),

    /// Commission rate (0-10000 for 0.00% to 100.00%)
    commission_rate_bps: u16 = 500, // 5.00% default

    const Delegator = struct {
        address: [32]u8,
        amount: u64,
        delegation_height: u64,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id: [32]u8, public_key: []const u8, stake: u64, network_address: []const u8, port: u16) !Self {
        return Self{
            .id = id,
            .public_key = try allocator.dupe(u8, public_key),
            .stake = stake,
            .metrics = ValidatorMetrics{},
            .network_address = try allocator.dupe(u8, network_address),
            .port = port,
            .supported_algorithms = try allocator.dupe(kriptix.Algorithm, &[_]kriptix.Algorithm{ .Dilithium3, .Kyber768 }),
            .delegators = std.ArrayList(Delegator).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key);
        allocator.free(self.network_address);
        allocator.free(self.supported_algorithms);
        self.delegators.deinit();
    }

    /// Get total stake (own + delegated)
    pub fn get_total_stake(self: Self) u64 {
        return self.stake + self.delegated_stake;
    }

    /// Check if validator is eligible to participate
    pub fn is_eligible(self: Self) bool {
        return self.status == .active and
            self.get_total_stake() >= self.minimum_stake and
            self.reputation_score >= 50; // Minimum reputation threshold
    }

    /// Get voting weight based on stake
    pub fn get_voting_weight(self: Self, total_network_stake: u64) u32 {
        if (total_network_stake == 0) return 0;
        const weight = (self.get_total_stake() * 10000) / total_network_stake;
        return @intCast(@min(weight, 3333)); // Cap at 33.33% to prevent dominance
    }

    /// Add delegation
    pub fn add_delegation(self: *Self, delegator_address: [32]u8, amount: u64, height: u64) !void {
        try self.delegators.append(Delegator{
            .address = delegator_address,
            .amount = amount,
            .delegation_height = height,
        });
        self.delegated_stake += amount;
    }

    /// Remove delegation
    pub fn remove_delegation(self: *Self, delegator_address: [32]u8, amount: u64) bool {
        for (self.delegators.items, 0..) |delegator, i| {
            if (std.mem.eql(u8, &delegator.address, &delegator_address)) {
                if (delegator.amount >= amount) {
                    self.delegated_stake -= amount;
                    if (delegator.amount == amount) {
                        _ = self.delegators.swapRemove(i);
                    } else {
                        self.delegators.items[i].amount -= amount;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    /// Update performance metrics
    pub fn update_metrics(self: *Self, vote_correct: bool, block_valid: ?bool, response_time_ms: u32) void {
        self.metrics.votes_cast += 1;
        if (vote_correct) {
            self.metrics.correct_votes += 1;
        }

        if (block_valid) |valid| {
            self.metrics.blocks_proposed += 1;
            if (valid) {
                self.metrics.valid_blocks += 1;
            }
        }

        // Update moving average of response time
        if (self.metrics.avg_response_time_ms == 0) {
            self.metrics.avg_response_time_ms = response_time_ms;
        } else {
            self.metrics.avg_response_time_ms = (@as(u64, self.metrics.avg_response_time_ms) * 9 + response_time_ms) / 10;
        }

        self.metrics.last_activity = @intCast(std.time.timestamp());

        // Update reputation based on performance
        self.update_reputation();
    }

    /// Update reputation score based on metrics
    fn update_reputation(self: *Self) void {
        const performance_score = self.metrics.calculate_performance_score();

        // Gradually adjust reputation towards performance score
        if (performance_score > self.reputation_score) {
            self.reputation_score = @min(100, self.reputation_score + 1);
        } else if (performance_score < self.reputation_score) {
            self.reputation_score = @max(0, self.reputation_score - 1);
        }

        // Penalty for slashing
        if (self.slashing_count > 0) {
            self.reputation_score = @max(0, self.reputation_score - @min(50, self.slashing_count * 10));
        }
    }

    /// Apply slashing penalty
    pub fn slash(self: *Self, penalty_percentage: u16, reason: SlashingReason) u64 {
        const penalty_amount = (self.stake * penalty_percentage) / 10000;
        self.stake = @max(0, self.stake - penalty_amount);
        self.slashing_count += 1;
        self.reputation_score = @max(0, self.reputation_score - 20);

        // If slashed too much, mark as slashed status
        if (self.slashing_count >= 3 or penalty_percentage >= 5000) { // 50%+
            self.status = .slashed;
        }

        _ = reason; // Log slashing reason in real implementation
        return penalty_amount;
    }
};

/// Slashing reasons
pub const SlashingReason = enum {
    double_voting,
    invalid_block_proposal,
    offline_for_extended_period,
    malicious_behavior,
    protocol_violation,
};

/// Validator Set Manager
pub const ValidatorSetManager = struct {
    allocator: std.mem.Allocator,

    /// Active validator set
    active_validators: std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage),

    /// Pending validators waiting for activation
    pending_validators: std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage),

    /// Exiting validators
    exiting_validators: std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage),

    /// Validator set configuration
    config: ValidatorSetConfig,

    /// Current epoch information
    current_epoch: u64 = 0,
    epoch_start_height: u64 = 0,

    /// Validator selection randomness
    randomness_seed: [32]u8,

    pub const ValidatorSetConfig = struct {
        max_validators: u32 = 100,
        min_validators: u32 = 4,
        epoch_length: u64 = 1000, // blocks
        stake_threshold: u64 = 1000,
        slashing_enabled: bool = true,
        delegation_enabled: bool = true,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ValidatorSetConfig) Self {
        var randomness_seed: [32]u8 = undefined;
        std.crypto.random.bytes(&randomness_seed);

        return Self{
            .allocator = allocator,
            .active_validators = std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .pending_validators = std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .exiting_validators = std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage).init(allocator),
            .config = config,
            .randomness_seed = randomness_seed,
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up active validators
        var active_iter = self.active_validators.iterator();
        while (active_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.active_validators.deinit();

        // Clean up pending validators
        var pending_iter = self.pending_validators.iterator();
        while (pending_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_validators.deinit();

        // Clean up exiting validators
        var exiting_iter = self.exiting_validators.iterator();
        while (exiting_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.exiting_validators.deinit();
    }

    /// Register a new validator
    pub fn register_validator(self: *Self, validator: EnhancedValidator) !void {
        if (self.active_validators.count() + self.pending_validators.count() >= self.config.max_validators) {
            return error.ValidatorSetFull;
        }

        if (validator.get_total_stake() < self.config.stake_threshold) {
            return error.InsufficientStake;
        }

        // Check if validator already exists
        if (self.active_validators.contains(validator.id) or self.pending_validators.contains(validator.id)) {
            return error.ValidatorAlreadyExists;
        }

        try self.pending_validators.put(validator.id, validator);
    }

    /// Activate pending validators at the start of a new epoch
    pub fn process_epoch_transition(self: *Self, new_height: u64) !void {
        if (new_height < self.epoch_start_height + self.config.epoch_length) {
            return; // Not time for epoch transition yet
        }

        self.current_epoch += 1;
        self.epoch_start_height = new_height;

        // Activate eligible pending validators
        var pending_iter = self.pending_validators.iterator();
        var validators_to_activate = std.ArrayList([32]u8).init(self.allocator);
        defer validators_to_activate.deinit();

        while (pending_iter.next()) |entry| {
            if (entry.value_ptr.is_eligible() and self.active_validators.count() < self.config.max_validators) {
                try validators_to_activate.append(entry.key_ptr.*);
            }
        }

        // Move validators from pending to active
        for (validators_to_activate.items) |validator_id| {
            if (self.pending_validators.fetchRemove(validator_id)) |kv| {
                var validator = kv.value;
                validator.status = .active;
                validator.activation_height = new_height;
                try self.active_validators.put(validator_id, validator);
            }
        }

        // Process exiting validators
        try self.process_exiting_validators(new_height);

        // Update randomness for leader selection
        self.update_randomness_seed(new_height);
    }

    /// Process validators that are exiting
    fn process_exiting_validators(self: *Self, current_height: u64) !void {
        var exiting_iter = self.exiting_validators.iterator();
        var validators_to_remove = std.ArrayList([32]u8).init(self.allocator);
        defer validators_to_remove.deinit();

        while (exiting_iter.next()) |entry| {
            if (entry.value_ptr.exit_height) |exit_height| {
                // Allow exit after one epoch
                if (current_height >= exit_height + self.config.epoch_length) {
                    try validators_to_remove.append(entry.key_ptr.*);
                }
            }
        }

        // Remove fully exited validators
        for (validators_to_remove.items) |validator_id| {
            if (self.exiting_validators.fetchRemove(validator_id)) |kv| {
                kv.value.deinit(self.allocator);
            }
        }
    }

    /// Initiate validator exit
    pub fn exit_validator(self: *Self, validator_id: [32]u8, exit_height: u64) !void {
        if (self.active_validators.fetchRemove(validator_id)) |kv| {
            var validator = kv.value;
            validator.status = .exiting;
            validator.exit_height = exit_height;
            try self.exiting_validators.put(validator_id, validator);
        } else {
            return error.ValidatorNotFound;
        }
    }

    /// Slash a validator
    pub fn slash_validator(self: *Self, validator_id: [32]u8, penalty_percentage: u16, reason: SlashingReason) !u64 {
        if (!self.config.slashing_enabled) {
            return 0;
        }

        if (self.active_validators.getPtr(validator_id)) |validator| {
            return validator.slash(penalty_percentage, reason);
        }

        return error.ValidatorNotFound;
    }

    /// Get validator by ID
    pub fn get_validator(self: *Self, validator_id: [32]u8) ?*EnhancedValidator {
        return self.active_validators.getPtr(validator_id);
    }

    /// Get all active validators
    pub fn get_active_validators(self: *Self) std.HashMap([32]u8, EnhancedValidator, [32]u8, std.hash_map.default_max_load_percentage).Iterator {
        return self.active_validators.iterator();
    }

    /// Select leader for current round using stake-weighted random selection
    pub fn select_leader(self: *Self, round: u64) ?[32]u8 {
        if (self.active_validators.count() == 0) return null;

        // Calculate total stake
        var total_stake: u64 = 0;
        var validator_iter = self.active_validators.iterator();
        while (validator_iter.next()) |entry| {
            if (entry.value_ptr.is_eligible()) {
                total_stake += entry.value_ptr.get_total_stake();
            }
        }

        if (total_stake == 0) return null;

        // Generate deterministic randomness for this round
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.randomness_seed);
        hasher.update(&@as([8]u8, @bitCast(round)));
        var round_hash: [32]u8 = undefined;
        hasher.final(&round_hash);

        // Convert to selection value
        const selection_value = std.mem.readInt(u64, round_hash[0..8], .little) % total_stake;

        // Select validator based on stake weight
        var cumulative_stake: u64 = 0;
        validator_iter = self.active_validators.iterator();
        while (validator_iter.next()) |entry| {
            if (entry.value_ptr.is_eligible()) {
                cumulative_stake += entry.value_ptr.get_total_stake();
                if (selection_value < cumulative_stake) {
                    return entry.key_ptr.*;
                }
            }
        }

        return null;
    }

    /// Get total network stake
    pub fn get_total_network_stake(self: *Self) u64 {
        var total: u64 = 0;
        var validator_iter = self.active_validators.iterator();
        while (validator_iter.next()) |entry| {
            total += entry.value_ptr.get_total_stake();
        }
        return total;
    }

    /// Update randomness seed for unpredictable leader selection
    fn update_randomness_seed(self: *Self, height: u64) void {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&self.randomness_seed);
        hasher.update(&@as([8]u8, @bitCast(height)));
        hasher.update(&@as([8]u8, @bitCast(self.current_epoch)));
        hasher.final(&self.randomness_seed);
    }

    /// Check if enough validators are online for consensus
    pub fn has_consensus_quorum(self: *Self) bool {
        const active_count = self.active_validators.count();
        const required_count = (active_count * 2) / 3 + 1; // 2/3 + 1 for BFT

        var online_count: u32 = 0;
        var validator_iter = self.active_validators.iterator();
        while (validator_iter.next()) |entry| {
            if (entry.value_ptr.is_eligible()) {
                // Check if validator was active recently (within last 5 minutes)
                const current_time = @as(u64, @intCast(std.time.timestamp()));
                if (current_time - entry.value_ptr.metrics.last_activity < 300) {
                    online_count += 1;
                }
            }
        }

        return online_count >= required_count;
    }
};

test "enhanced validator management" {
    std.testing.refAllDecls(@This());
}
