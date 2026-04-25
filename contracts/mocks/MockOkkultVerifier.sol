// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockOkkultVerifier
/// @notice Mock OkkultVerifier for testing compliance checks
/// @dev NEVER deploy to mainnet
contract MockOkkultVerifier {

    mapping(address => bool)    private _validProofs;
    mapping(address => uint256) private _expiries;

    /// @notice Set proof validity for an address
    function setValidProof(address user, bool valid) external {
        _validProofs[user] = valid;
        _expiries[user]    = valid
            ? block.timestamp + 30 days
            : 0;
    }

    /// @notice Check if address has valid proof
    function hasValidProof(address user)
        external view returns (bool) {
        return _validProofs[user] &&
               _expiries[user] > block.timestamp;
    }

    /// @notice Get proof expiry timestamp
    function proofExpiry(address user)
        external view returns (uint256) {
        return _expiries[user];
    }
}
