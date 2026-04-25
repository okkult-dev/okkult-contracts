// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IComplianceGate
/// @notice Interface for ZK compliance enforcement
/// @dev Any DeFi protocol inherits this to add Okkult compliance

enum ComplianceMode {
    STRICT, // Revert if user has no valid proof
    SOFT    // Emit event but allow through
}

interface IComplianceGate {

    /// @notice Emitted when compliance is checked
    event ComplianceChecked(
        address indexed user,
        bool    indexed passed,
        uint256         timestamp
    );

    /// @notice Emitted when an address is whitelisted
    event ProtocolWhitelisted(address indexed addr);

    /// @notice Emitted when an address is removed from whitelist
    event ProtocolBlacklisted(address indexed addr);

    /// @notice Check if a user is compliant
    /// @dev Returns true if whitelisted OR has valid proof
    /// @param user Address to check
    /// @return True if compliant
    function isCompliant(address user)
        external view returns (bool);

    /// @notice Require compliance — revert if not compliant
    /// @param user Address to check
    function requireCompliance(address user)
        external view;

    /// @notice Whitelist an address (for contracts, DAOs, multisigs)
    /// @param addr Address to whitelist
    function whitelist(address addr) external;

    /// @notice Remove address from whitelist
    /// @param addr Address to remove
    function removeWhitelist(address addr) external;

    /// @notice Set compliance enforcement mode
    /// @param mode STRICT or SOFT
    function setMode(ComplianceMode mode) external;
}
