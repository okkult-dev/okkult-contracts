// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IComplianceGate, ComplianceMode } from
    '../interfaces/IComplianceGate.sol';

/// @title ComplianceGate
/// @notice Base contract for ZK compliance enforcement
/// @dev Any DeFi protocol inherits this to add Okkult compliance
///      in one import and one modifier.
///
///      Usage:
///        contract MyProtocol is ComplianceGate {
///          constructor(address okkultVerifier)
///            ComplianceGate(okkultVerifier, ComplianceMode.STRICT)
///          {}
///          function deposit(uint256 amount)
///            external
///            onlyCompliant(msg.sender)
///          { ... }
///        }
contract ComplianceGate is IComplianceGate {

    // ── Interfaces ────────────────────────────────────────────

    /// @dev Minimal interface for OkkultVerifier
    interface IOkkultVerifier {
        function hasValidProof(address user)
            external view returns (bool);
    }

    // ── State ─────────────────────────────────────────────────

    /// @notice OkkultVerifier contract
    IOkkultVerifier public immutable verifier;

    /// @notice Current compliance enforcement mode
    ComplianceMode public mode;

    /// @notice Admin address — can whitelist and change mode
    address public admin;

    /// @notice Whitelisted addresses — exempt from proof check
    /// @dev Use for: contracts, multisigs, DAOs, protocol treasuries
    mapping(address => bool) public whitelisted;

    // ── Errors ────────────────────────────────────────────────

    error NotAdmin();
    error NotCompliant(address user);
    error InvalidAddress();

    // ── Modifiers ─────────────────────────────────────────────

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /// @notice Enforce compliance for a user
    /// @dev Whitelisted addresses bypass proof check
    ///      STRICT mode: reverts if not compliant
    ///      SOFT mode:   emits event but allows through
    modifier onlyCompliant(address user) {
        if (!whitelisted[user]) {
            bool compliant = verifier.hasValidProof(user);

            emit ComplianceChecked(user, compliant, block.timestamp);

            if (!compliant && mode == ComplianceMode.STRICT) {
                revert NotCompliant(user);
            }
        }
        _;
    }

    // ── Constructor ───────────────────────────────────────────

    /// @param _verifier OkkultVerifier contract address
    /// @param _mode     Initial compliance enforcement mode
    constructor(address _verifier, ComplianceMode _mode) {
        require(_verifier != address(0), 'Invalid verifier');
        verifier = IOkkultVerifier(_verifier);
        mode     = _mode;
        admin    = msg.sender;
    }

    // ── External functions ────────────────────────────────────

    /// @notice Check if a user is compliant
    /// @param user Address to check
    /// @return True if whitelisted or has valid proof
    function isCompliant(address user)
        external
        view
        override
        returns (bool)
    {
        return whitelisted[user] ||
               verifier.hasValidProof(user);
    }

    /// @notice Require compliance — revert if not compliant
    /// @param user Address to check
    function requireCompliance(address user)
        external
        view
        override
    {
        if (!whitelisted[user] && !verifier.hasValidProof(user)) {
            revert NotCompliant(user);
        }
    }

    /// @notice Whitelist an address
    /// @param addr Address to whitelist
    function whitelist(address addr)
        external
        override
        onlyAdmin
    {
        if (addr == address(0)) revert InvalidAddress();
        whitelisted[addr] = true;
        emit ProtocolWhitelisted(addr);
    }

    /// @notice Remove address from whitelist
    /// @param addr Address to remove
    function removeWhitelist(address addr)
        external
        override
        onlyAdmin
    {
        whitelisted[addr] = false;
        emit ProtocolBlacklisted(addr);
    }

    /// @notice Set compliance enforcement mode
    /// @param _mode New mode (STRICT or SOFT)
    function setMode(ComplianceMode _mode)
        external
        override
        onlyAdmin
    {
        mode = _mode;
    }

    /// @notice Transfer admin role
    /// @param newAdmin New admin address
    function transferAdmin(address newAdmin)
        external
        onlyAdmin
    {
        if (newAdmin == address(0)) revert InvalidAddress();
        admin = newAdmin;
    }
}
