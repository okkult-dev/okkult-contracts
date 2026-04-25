// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockVerifier
/// @notice Mock ZK verifier for testing — always returns true
/// @dev NEVER deploy to mainnet
contract MockVerifier {

    bool private _shouldPass;

    constructor() {
        _shouldPass = true;
    }

    /// @notice Toggle whether proofs pass or fail
    function setShouldPass(bool value) external {
        _shouldPass = value;
    }

    /// @notice Mock proof verification
    function verifyProof(
        uint[2]    calldata,
        uint[2][2] calldata,
        uint[2]    calldata,
        uint[2]    calldata
    ) external view returns (bool) {
        return _shouldPass;
    }
}
