// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NullifierRegistry
/// @notice Stores used nullifiers to prevent ZK proof reuse
/// @dev Append-only mapping — nullifiers can never be unspent
///      Immutable after deployment — no admin keys
contract NullifierRegistry {

    // ── State ─────────────────────────────────────────────────

    /// @notice Address of OkkultVerifier — only caller allowed
    address public immutable verifier;

    /// @notice Mapping of used nullifiers
    /// @dev bytes32 → bool, O(1) lookup
    mapping(bytes32 => bool) public usedNullifiers;

    // ── Events ────────────────────────────────────────────────

    /// @notice Emitted when a nullifier is marked as used
    /// @param nullifier The nullifier that was spent
    event NullifierUsed(bytes32 indexed nullifier);

    // ── Errors ────────────────────────────────────────────────

    error OnlyVerifier();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidNullifier();

    // ── Modifiers ─────────────────────────────────────────────

    /// @dev Restricts function to OkkultVerifier contract only
    modifier onlyVerifier() {
        if (msg.sender != verifier) revert OnlyVerifier();
        _;
    }

    // ── Constructor ───────────────────────────────────────────

    /// @param _verifier Address of OkkultVerifier contract
    constructor(address _verifier) {
        require(_verifier != address(0), 'Invalid verifier');
        verifier = _verifier;
    }

    // ── External functions ────────────────────────────────────

    /// @notice Check if a nullifier has been used
    /// @param nullifier The nullifier to check
    /// @return True if nullifier has been used
    function isUsed(bytes32 nullifier)
        external
        view
        returns (bool)
    {
        return usedNullifiers[nullifier];
    }

    /// @notice Mark a nullifier as used
    /// @dev Only callable by OkkultVerifier
    /// @param nullifier The nullifier to mark as used
    function markUsed(bytes32 nullifier)
        external
        onlyVerifier
    {
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (usedNullifiers[nullifier])
            revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;
        emit NullifierUsed(nullifier);
    }
}
