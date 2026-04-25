// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IOkkultShield
/// @notice Standard interface for OkkultShield shielded pool
interface IOkkultShield {

    /// @notice Emitted when tokens are shielded into the pool
    event Shielded(
        bytes32 indexed commitment,
        uint256 indexed leafIndex,
        address         token,
        uint256         fee
    );

    /// @notice Emitted when tokens are unshielded from the pool
    event Unshielded(
        bytes32 indexed nullifier,
        address indexed recipient,
        address         token,
        uint256         amount
    );

    /// @notice Emitted on private transfer between 0zk addresses
    event PrivateTransfer(
        bytes32 indexed inNullifier,
        bytes32 indexed outCommitment1,
        bytes32 indexed outCommitment2
    );

    /// @notice Shield ERC-20 tokens into the private pool
    /// @dev Requires valid Okkult compliance proof
    /// @param token      ERC-20 token address
    /// @param amount     Amount to shield
    /// @param commitment UTXO commitment hash
    /// @param proof_a    ZK proof component a
    /// @param proof_b    ZK proof component b
    /// @param proof_c    ZK proof component c
    function shield(
        address    token,
        uint256    amount,
        bytes32    commitment,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    ) external;

    /// @notice Withdraw tokens from the private pool
    /// @param token     ERC-20 token address
    /// @param amount    Amount to withdraw
    /// @param nullifier Nullifier of the UTXO being spent
    /// @param root      Merkle root used for proof
    /// @param recipient Destination address
    /// @param proof_a   ZK proof component a
    /// @param proof_b   ZK proof component b
    /// @param proof_c   ZK proof component c
    function unshield(
        address    token,
        uint256    amount,
        bytes32    nullifier,
        bytes32    root,
        address    recipient,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    ) external;

    /// @notice Private transfer between two 0zk addresses
    /// @param inNullifier    Nullifier of the input UTXO
    /// @param outCommitment1 Commitment of output UTXO 1
    /// @param outCommitment2 Commitment of output UTXO 2
    /// @param root           Merkle root used for proof
    /// @param proof_a        ZK proof component a
    /// @param proof_b        ZK proof component b
    /// @param proof_c        ZK proof component c
    function privateTransfer(
        bytes32    inNullifier,
        bytes32    outCommitment1,
        bytes32    outCommitment2,
        bytes32    root,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    ) external;

    /// @notice Check if a UTXO nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been spent
    function isSpent(bytes32 nullifier)
        external view returns (bool);

    /// @notice Get the current UTXO Merkle tree root
    /// @return Current Merkle root
    function getRoot()
        external view returns (bytes32);
}
