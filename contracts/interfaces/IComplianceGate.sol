// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IComplianceGate
 * @author Okkult Protocol
 * @notice Standard interface for integrating Okkult compliance checks into DeFi protocols.
 *
 * Any protocol can inherit from an implementation of this interface to enforce
 * address compliance through either:
 * - Whitelisting: Direct approval of protocol-trusted addresses without ZK proof.
 * - Zero-Knowledge Proofs: Verify the address is not sanctioned via Okkult's verifier.
 *
 * Two compliance modes enable flexible integration:
 * - STRICT: Requires whitelisting OR valid ZK proof (recommended for sensitive protocols).
 * - SOFT: Allows whitelisting without proof, suitable for less sensitive protocols.
 *
 * @dev Protocols integrate via:
 *      contract MyProtocol is IComplianceGate {
 *          modifier onlyCompliant(address user) {
 *              requireCompliance(user);
 *              _;
 *          }
 *      }
 */

/// ========================================
/// Compliance Mode Enum
/// ========================================

/**
 * @dev Defines how strict compliance checking is enforced:
 *
 * STRICT (0):
 *   - User must be whitelisted OR have a valid, non-expired ZK proof.
 *   - Recommended for: DEX aggregators, bridge protocols, high-value operations.
 *   - Prevents accidental OFAC exposure via stale whitelist.
 *
 * SOFT (1):
 *   - Whitelist bypasses proof requirement (trust assumption).
 *   - Non-whitelisted users still must provide valid proof.
 *   - Suitable for: Community pools, low-sensitivity operations, partnerships.
 *   - Trade-off: Faster onboarding vs. compliance strength.
 */
enum ComplianceMode {
    STRICT,
    SOFT
}

interface IComplianceGate {
    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted whenever compliance is checked (regardless of outcome).
     * @param user The address being checked for compliance.
     * @param passed True if the user passed compliance (whitelisted or has valid proof),
     *               false otherwise.
     * @param timestamp The block timestamp at which the check was performed.
     *
     * @dev Useful for compliance audits and monitoring. Off-chain systems can listen
     *      to this event to track access patterns and suspicious activity.
     */
    event ComplianceChecked(
        address indexed user,
        bool indexed passed,
        uint256 timestamp
    );

    /**
     * @notice Emitted when an address is added to the compliance whitelist.
     * @param addr The address that was whitelisted.
     *
     * @dev Whitelisted addresses bypass ZK proof requirements within the configured
     *      compliance mode (see ComplianceMode for behavior details).
     *      Typical use cases: protocol team multisigs, fully-verified service providers.
     */
    event ProtocolWhitelisted(address indexed addr);

    /**
     * @notice Emitted when an address is removed from the compliance whitelist.
     * @param addr The address that was de-whitelisted.
     *
     * @dev Revokes the compliance bypass. The address must now submit a valid ZK proof
     *      to re-gain compliance access (in STRICT mode) or loses access (in SOFT mode).
     */
    event ProtocolBlacklisted(address indexed addr);

    /// ========================================
    /// Compliance Checks
    /// ========================================

    /**
     * @notice Determines if a user satisfies the protocol's compliance requirements.
     *
     * @param user The address to check for compliance.
     *
     * @return compliant True if the user passes compliance, false otherwise.
     *
     * @dev Returns true if ANY of the following conditions are met:
     *      1. User is on the whitelist (regardless of mode).
     *      2. User has a valid, non-expired ZK proof from the Okkult verifier.
     *
     * @dev In STRICT mode, both checks apply equally.
     *      In SOFT mode, whitelist behaves identically but represents a trust assumption.
     *
     * @dev This is a view function suitable for off-chain queries and is non-reverting.
     *      Use requireCompliance() to enforce access control at transaction time.
     */
    function isCompliant(address user)
        external
        view
        returns (bool compliant);

    /**
     * @notice Enforces compliance as an access control modifier primitive.
     *
     * @param user The address to check for compliance.
     *
     * @dev REVERTS if the user does not pass compliance checks.
     *      Use this function inside transaction modifiers to gate sensitive operations.
     *
     * @dev Example integration:
     *      contract PrivateSwap is IComplianceGate {
     *          function swap(address user, uint256 amount)
     *              external
     *          {
     *              requireCompliance(user);
     *              // ... swap logic ...
     *          }
     *      }
     *
     * @dev Emits ComplianceChecked event even on revert (depending on implementation).
     */
    function requireCompliance(address user)
        external
        view;

    /// ========================================
    /// Combined Proof + Compliance Check
    /// ========================================

    /**
     * @notice Verifies a new ZK proof and checks compliance in a single transaction.
     *
     * @param user The address submitting the proof (typically msg.sender).
     * @param proof_a The first component of the zk-SNARK proof.
     * @param proof_b The second component of the zk-SNARK proof.
     * @param proof_c The third component of the zk-SNARK proof.
     * @param publicInputs Array containing public proof inputs:
     *      - publicInputs[0]: Merkle root of the compliance tree.
     *      - publicInputs[1]: Nullifier hash (prevents proof replay).
     *
     * @return compliant True if proof verification succeeds and user now passes compliance,
     *                   false if proof is invalid.
     *
     * @dev ATOMICALLY:
     *      1. Forwards the proof to the Okkult verifier contract.
     *      2. If verification succeeds, immediately checks if user is now compliant.
     *      3. Returns compliance status without requiring a second call.
     *
     * @dev Optimization: Enables protocols to accept initial verification + operation
     *      in a single transaction, improving UX. User doesn't need to:
     *      1. Call verifyProof() on Okkult verifier.
     *      2. Wait for next block.
     *      3. Call the protocol function again.
     *
     * @dev Emits ProofVerified (from verifier) and ComplianceChecked (from gate).
     */
    function checkAndVerify(
        address user,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c,
        uint[2] calldata publicInputs
    ) external returns (bool compliant);

    /// ========================================
    /// Whitelist Management (Admin Functions)
    /// ========================================

    /**
     * @notice Adds an address to the compliance whitelist.
     *
     * @param addr The address to whitelist.
     *
     * @dev ADMIN ONLY: Typically restricted to protocol owner/governance.
     *
     * @dev Whitelisted addresses are considered compliant without requiring:
     *      - ZK proof submission.
     *      - Any verification from Okkult verifier.
     *
     * @dev Ideal for:
     *      - Protocol multisigs and core team addresses.
     *      - Service providers with pre-verified compliance.
     *      - Established institutional participants.
     *
     * @dev Emits ProtocolWhitelisted event.
     */
    function whitelist(address addr) external;

    /**
     * @notice Removes an address from the compliance whitelist.
     *
     * @param addr The address to de-whitelist.
     *
     * @dev ADMIN ONLY: Typically restricted to protocol owner/governance.
     *
     * @dev After removal, the address must submit a valid ZK proof to regain compliance
     *      (in STRICT mode) or is immediately non-compliant (in SOFT mode).
     *
     * @dev Useful for revoking access in case of:
     *      - Security incidents involving the address.
     *      - Governance decisions to restrict an entity.
     *      - Contract upgrades or compliance policy changes.
     *
     * @dev Emits ProtocolBlacklisted event.
     */
    function removeWhitelist(address addr) external;

    /// ========================================
    /// Configuration
    /// ========================================

    /**
     * @notice Sets the compliance enforcement mode for this gate.
     *
     * @param mode The new ComplianceMode:
     *      - STRICT: Both whitelist AND ZK proof are recognized as compliance.
     *      - SOFT: Whitelist provides bypass; non-whitelisted users need proof.
     *
     * @dev ADMIN ONLY: Typically restricted to protocol owner/governance.
     *
     * @dev Changing modes affects enforcement immediately:
     *      - Switching to STRICT: Whitelisted users remain compliant but non-whitelisted
     *        users must now provide ZK proof.
     *      - Switching to SOFT: All whitelisted users bypass proof requirements.
     *
     * @dev Governance should carefully coordinate mode changes with community to avoid
     *      unexpected access revocations or loosened compliance.
     *
     * @dev No event emission required but recommended: `event ComplianceModeChanged(ComplianceMode mode);`
     */
    function setMode(ComplianceMode mode) external;
}
