//! Blockchain Consensus Module
//!
//! This module contains the aBFT (asynchronous Byzantine Fault Tolerant)
//! consensus implementation for the Kriptix blockchain.

const std = @import("std");

// Re-export consensus implementations
pub const abft = @import("abft.zig");
pub const validator_management = @import("validator_management.zig");
pub const network = @import("network.zig");
pub const enhanced_abft = @import("enhanced_abft.zig");

// Re-export commonly used types
pub const ABFTConsensus = abft.ABFTConsensus;
pub const ABFTConfig = abft.ABFTConfig;
pub const TxVote = abft.TxVote;
pub const VotePool = abft.VotePool;

pub const ValidatorSetManager = validator_management.ValidatorSetManager;
pub const EnhancedValidator = validator_management.EnhancedValidator;
pub const ValidatorStatus = validator_management.ValidatorStatus;
pub const SlashingReason = validator_management.SlashingReason;

pub const NetworkManager = network.NetworkManager;
pub const NetworkMessage = network.NetworkMessage;
pub const MessageType = network.MessageType;
pub const Peer = network.Peer;
pub const SecureChannel = network.SecureChannel;

pub const EnhancedABFTConsensus = enhanced_abft.EnhancedABFTConsensus;

// Future consensus algorithms can be added here
// pub const pbft = @import("pbft.zig");
// pub const hotstuff = @import("hotstuff.zig");

test "consensus module imports" {
    std.testing.refAllDecls(@This());
}
