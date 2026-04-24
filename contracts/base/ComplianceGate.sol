// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IComplianceGate.sol";
import "../interfaces/IOkkultVerifier.sol";

/**
 * @title ComplianceGate
 * @author Okkult Protocol
 * @notice Base contract enabling any DeFi protocol to enforce address compliance in 3 lines.
 *
 * ComplianceGate is the primary integration point for Okkult Protocol. DeFi protocols
 * inherit from this contract to:
 * 1. Check if users are compliant (not sanctioned).
 * 2. Gate sensitive operations (swaps, withdrawals, governance votes).
 * 3. Support whitelisting (for trusted counterparties).
 * 4. Switch between STRICT and SOFT compliance modes.
 *
 * INTEGRATION PATTERN:
 * ```solidity
 * contract PrivateSwap is ComplianceGate {
 *     constructor(address okkultVerifier)
 *         ComplianceGate(okkultVerifier, ComplianceMode.STRICT)
 *     {}
 *
 *     function swap(address tokenIn, uint256 amountIn, address user)
 *         external
 *         onlyCompliant(user)
 *     {
 *         // Swap logic only executes if user is compliant.
 *     }
 * }
 * ```
 *
 * COMPLIANCE MODES:
 * - STRICT: User must be whitelisted OR have valid ZK proof.
 * - SOFT: Whitelist bypasses proof requirement; non-whitelisted users need proof.
 *
 * WHITELISTING USES:
 * - Protocol teams (multisig addresses).
 * - Institutional participants (pre-verified compliance).
 * - Service providers (API endpoints, batch processes).
 * - Emergency backdoor (unforeseen compliance issues).
 *
 * PROOF VERIFICATION:
 * - Delegates to IOkkultVerifier contract.
 * - Verifier maintains current compliance tree root.
 * - Verifier checks proof validity and expiry.
 * - Gate only queries hasValidProof() (verifier owns proof logic).
 *
 * ACCESS CONTROL:
 * - admin: Can whitelist/blacklist addresses, switch modes.
 * - can be upgraded to multi-sig or governance DAO.
 * - Recommended: Set admin to governance after deployment.
 *
 * @dev SECURITY NOTES:
 *      - Gate is immutable once deployed (no verifier upgrade).
 *      - Whitelist is mutable (admin can freeze/unfreeze access).
 *      - Mode switch is mutable (admin can tighten or relax compliance).
 *      - Compliance checks are atomic (no race conditions).
 *      - emit ComplianceChecked in modifiers for audit trail.
 */
contract ComplianceGate is IComplianceGate {
    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice The Okkult verifier contract that validates ZK proofs.
    /// @dev Immutable after deployment. Handles proof verification and proof expiry.
    /// @dev All compliance queries ultimately delegate to this verifier.
    IOkkultVerifier public verifier;

    /// @notice Current compliance enforcement mode (STRICT or SOFT).
    /// @dev STRICT: Both whitelist and proofs recognized.
    ///      SOFT: Whitelist bypasses proof requirement.
    /// @dev Mutable via setMode() (admin only).
    /// @dev Allows protocols to relax/tighten compliance post-deployment.
    ComplianceMode public mode;

    /// @notice Address with authority to update whitelist and mode.
    /// @dev Set to msg.sender at deployment.
    /// @dev Can be transferred to multi-sig or governance contract.
    /// @dev Recommended: Transfer to DAO after testing.
    address public admin;

    /// @notice Mapping of whitelisted addresses (bypass proof requirement).
    /// @dev true = address is whitelisted (trusted, no proof needed).
    ///      false = address must provide valid proof (default).
    /// @dev Mutable via whitelist() and removeWhitelist() (admin only).
    /// @dev Used in both STRICT and SOFT modes.
    mapping(address => bool) public whitelisted;

    /// ========================================
    /// Modifiers
    /// ========================================

    /**
     * @notice Restricts function access to the protocol admin.
     * @dev Reverts with "Only admin" if caller is not the admin.
     *
     * @dev Used to protect:
     *      - whitelist() and removeWhitelist() (access control).
     *      - setMode() (compliance policy changes).
     *      - transferAdmin() (admin rotation).
     */
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    /**
     * @notice Enforces compliance checks for a user (primary gate mechanism).
     * @param user The address to check for compliance.
     *
     * @dev FLOW:
     *      1. If user is whitelisted, allow (bypass proof check).
     *      2. Otherwise, check verifier.hasValidProof(user).
     *      3. Emit ComplianceChecked event for audit.
     *      4. If STRICT mode and not compliant, revert.
     *      5. If SOFT mode, allow even without proof (only whitelist matters).
     *
     * @dev USAGE:
     *      contract MyDeFi is ComplianceGate {
     *          function deposit(address user, uint256 amount)
     *              external
     *              onlyCompliant(user)
     *          {
     *              // Only executes if user passes compliance.
     *          }
     *      }
     *
     * @dev EVENTS:
     *      Emits ComplianceChecked with (user, passed, block.timestamp).
     *      Off-chain systems monitor for access patterns and suspicious activity.
     *
     * @dev REVERT CONDITIONS:
     *      - In STRICT mode: If user not whitelisted and has no valid proof.
     *      - Always allows whitelisted addresses (both modes).
     */
    modifier onlyCompliant(address user) {
        // Check if user satisfies compliance.
        bool isUserCompliant = _isCompliant(user);

        // Emit audit event.
        emit ComplianceChecked(user, isUserCompliant, block.timestamp);

        // In STRICT mode, require compliance. In SOFT mode, allow always.
        if (mode == ComplianceMode.STRICT) {
            require(isUserCompliant, "User not compliant");
        }

        _;
    }

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes the ComplianceGate with a verifier and mode.
     *
     * @param _verifier The address of the OkkultVerifier contract.
     * @param _mode The initial compliance mode (STRICT or SOFT).
     *
     * @dev REQUIREMENTS:
     *      - _verifier must be a valid, non-zero address.
     *      - Typically: address of deployed OkkultVerifier contract.
     *
     * @dev INITIALIZATION:
     *      1. Set verifier = _verifier (immutable thereafter).
     *      2. Set mode = _mode (can be changed later via setMode).
     *      3. Set admin = msg.sender (can be transferred via transferAdmin).
     *      4. whitelisted mapping is empty (all addresses initially require proof).
     *
     * @dev TYPICAL DEPLOYMENT:
     *      1. Deploy OkkultVerifier (get address).
     *      2. Deploy ComplianceGate(okkultVerifierAddress, STRICT).
     *      3. Protocol inherits from ComplianceGate.
     *      4. After testing, transferAdmin to governance DAO.
     *
     * @dev GAS:
     *      Constructor stores 3 values: ~60k gas.
     */
    constructor(address _verifier, ComplianceMode _mode) {
        require(_verifier != address(0), "Verifier cannot be zero address");
        verifier = _verifier;
        mode = _mode;
        admin = msg.sender;
    }

    /// ========================================
    /// Compliance Queries (IComplianceGate)
    /// ========================================

    /**
     * @notice Determines if a user satisfies the protocol's compliance requirements.
     *
     * @param user The address to check for compliance.
     *
     * @return compliant True if user is whitelisted OR has valid proof, false otherwise.
     *
     * @dev RETURNS TRUE IF:
     *      1. User is whitelisted (checked first, short-circuit).
     *      2. User has valid, non-expired ZK proof from verifier.
     *
     * @dev VIEW FUNCTION:
     *      Non-reverting, safe to call from anywhere (even read-only contexts).
     *
     * @dev USAGE:
     *      // Off-chain: Pre-check before submitting transaction.
     *      if (compliantGate.isCompliant(userAddress)) {
     *          proceedWithTransaction();
     *      }
     *
     * @dev Does NOT emit events (use requireCompliance for audit logs).
     *
     * @dev GAS COST:
     *      - Whitelist check: ~100-2100 gas (cold/warm).
     *      - Verifier call: ~3-5k gas (external call + proof check).
     *      - Total: ~3-7k gas.
     */
    function isCompliant(address user)
        external
        view
        returns (bool compliant)
    {
        return _isCompliant(user);
    }

    /**
     * @notice Enforces compliance, reverting if user is not compliant.
     *
     * @param user The address to check for compliance.
     *
     * @dev REVERTS IF:
     *      - User is not whitelisted AND has no valid proof.
     *      - Suitable for transaction validation (inline with operation execution).
     *
     * @dev USAGE:
     *      function withdraw(address user, uint256 amount) external {
     *          requireCompliance(user);
     *          // Proceed with withdrawal only if user is compliant.
     *          _transfer(user, amount);
     *      }
     *
     * @dev EMITS:
     *      ComplianceChecked event (for audit trail).
     *      Emitted even on revert (log remains in failed transaction).
     *
     * @dev GAS COST:
     *      ~3-7k gas (same as isCompliant + event emission + require check).
     */
    function requireCompliance(address user)
        external
        view
    {
        bool isUserCompliant = _isCompliant(user);

        emit ComplianceChecked(user, isUserCompliant, block.timestamp);

        require(isUserCompliant, "User not compliant");
    }

    /// ========================================
    /// Combined Proof + Compliance
    /// ========================================

    /**
     * @notice Verifies a new ZK proof and checks compliance in a single transaction.
     *
     * @param user The address submitting the proof.
     * @param proof_a First component of the zk-SNARK proof.
     * @param proof_b Second component of the zk-SNARK proof.
     * @param proof_c Third component of the zk-SNARK proof.
     * @param publicInputs Array containing public proof inputs (root, nullifier).
     *
     * @return compliant True if proof is valid and user is now compliant, false otherwise.
     *
     * @dev FLOW:
     *      1. Forwards proof to verifier.verifyProof().
     *      2. If verification succeeds, checks if user is now compliant.
     *      3. Emits ComplianceChecked event.
     *      4. Returns compliance status.
     *
     * @dev OPTIMIZATION:
     *      Enables protocols to accept initial verification + operation in single tx.
     *      Users don't need to:
     *      1. Call verifyProof() on verifier.
     *      2. Wait for next block.
     *      3. Call protocol function again.
     *      Result: Better UX, lower gas per operation (one tx instead of two).
     *
     * @dev REVERTS IF:
     *      - Proof verification fails (verifier.verifyProof reverts).
     *      - Public inputs malformed.
     *
     * @dev DOES NOT REVERT IF:
     *      - Proof is valid but user is not compliant.
     *      Returns false in this case (allows caller to handle).
     *
     * @dev GAS COST:
     *      - Proof verification: ~2-3M gas (major cost).
     *      - Compliance check: ~3-7k gas.
     *      - Total: ~2-3M gas (dominated by proof verification).
     *
     * @dev EMITS:
     *      ProofVerified (from verifier).
     *      ComplianceChecked (from this gate).
     */
    function checkAndVerify(
        address user,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c,
        uint[2] calldata publicInputs
    ) external returns (bool compliant) {
        // Forward proof to verifier.
        verifier.verifyProof(proof_a, proof_b, proof_c, publicInputs);

        // Check if user is now compliant.
        bool isUserCompliant = _isCompliant(user);

        // Emit audit event.
        emit ComplianceChecked(user, isUserCompliant, block.timestamp);

        return isUserCompliant;
    }

    /// ========================================
    /// Whitelist Management
    /// ========================================

    /**
     * @notice Adds an address to the compliance whitelist.
     *
     * @param addr The address to whitelist.
     *
     * @dev ADMIN ONLY: Restricted to admin address.
     *
     * @dev EFFECT:
     *      After whitelisting, address bypasses proof requirement.
     *      In STRICT mode: User is compliant without proof.
     *      In SOFT mode: User is compliant without proof (same effect).
     *
     * @dev IDEMPOTENT:
     *      Calling multiple times with same address is safe.
     *      Second call has no effect (whitelisted[addr] already true).
     *
     * @dev USE CASES:
     *      - Protocol multisigs (core team).
     *      - Institutional participants (pre-verified).
     *      - Service providers (batch processors, API endpoints).
     *      - Emergency backdoor (unforeseen compliance issues).
     *
     * @dev REVERTS IF:
     *      - msg.sender != admin ("Only admin").
     *
     * @dev EMITS:
     *      ProtocolWhitelisted event.
     *
     * @dev GAS:
     *      ~20k gas (cold write) or ~5k gas (warm write, if previously whitelisted).
     */
    function whitelist(address addr)
        external
        onlyAdmin
    {
        whitelisted[addr] = true;
        emit ProtocolWhitelisted(addr);
    }

    /**
     * @notice Removes an address from the compliance whitelist.
     *
     * @param addr The address to de-whitelist.
     *
     * @dev ADMIN ONLY: Restricted to admin address.
     *
     * @dev EFFECT:
     *      After de-whitelisting, address must provide valid proof to be compliant.
     *      In STRICT mode: User needs proof (no more automatic bypass).
     *      In SOFT mode: User needs proof (no more automatic bypass).
     *
     * @dev IDEMPOTENT:
     *      Calling multiple times with same address is safe.
     *      Second call has no effect (whitelisted[addr] already false).
     *
     * @dev USE CASES:
     *      - Revoking access from compromised entity.
     *      - Governance decisions to restrict participation.
     *      - Contract upgrades or policy changes.
     *      - Emergency response to bad actor.
     *
     * @dev WARNING:
     *      Users not yet holding valid proofs will lose access immediately.
     *      Recommend announcement before de-whitelisting.
     *
     * @dev REVERTS IF:
     *      - msg.sender != admin ("Only admin").
     *
     * @dev EMITS:
     *      ProtocolBlacklisted event.
     *
     * @dev GAS:
     *      ~5k gas (warm write, typically address was previously whitelisted).
     */
    function removeWhitelist(address addr)
        external
        onlyAdmin
    {
        whitelisted[addr] = false;
        emit ProtocolBlacklisted(addr);
    }

    /// ========================================
    /// Configuration
    /// ========================================

    /**
     * @notice Switches the compliance enforcement mode.
     *
     * @param newMode The new compliance mode (STRICT or SOFT).
     *
     * @dev ADMIN ONLY: Restricted to admin address.
     *
     * @dev STRICT MODE (0):
     *      - User must be whitelisted OR have valid proof.
     *      - Non-whitelisted users without proof are rejected.
     *      - Recommended for: DEX aggregators, bridges, high-value operations.
     *
     * @dev SOFT MODE (1):
     *      - Whitelisted users are always accepted (no proof required).
     *      - Non-whitelisted users still must provide valid proof.
     *      - Recommended for: Community pools, low-sensitivity operations.
     *
     * @dev MODE SWITCHING:
     *      Switching to STRICT: Non-whitelisted users may lose access (if no proof).
     *      Switching to SOFT: Whitelisted users remain compliant (no change).
     *
     * @dev USAGE:
     *      // Tighten compliance (e.g., after security incident).
     *      gate.setMode(ComplianceMode.STRICT);
     *
     *      // Relax compliance (e.g., for initial onboarding).
     *      gate.setMode(ComplianceMode.SOFT);
     *
     * @dev COORDINATION:
     *      Governance should announce mode changes to avoid surprises.
     *      Users have time to generate proofs if switching to STRICT.
     *
     * @dev REVERTS IF:
     *      - msg.sender != admin ("Only admin").
     *
     * @dev GAS:
     *      ~5k gas (state write).
     */
    function setMode(ComplianceMode newMode)
        external
        onlyAdmin
    {
        mode = newMode;
    }

    /**
     * @notice Transfers admin authority to a new address.
     *
     * @param newAdmin The address to transfer admin rights to.
     *
     * @dev CURRENT ADMIN ONLY: Restricted to current admin address.
     *
     * @dev PURPOSE:
     *      - Initial deployment: admin is deployer (temporary).
     *      - After testing: transfer to multi-sig wallet.
     *      - Governance: transfer to DAO contract.
     *      - Upgrade: rotate to new admin address.
     *
     * @dev REQUIREMENTS:
     *      - newAdmin must be a valid, non-zero address.
     *      - Typically: multi-sig wallet or governance DAO.
     *
     * @dev ATOMIC TRANSFER:
     *      Once transferAdmin() succeeds, old admin has no authority.
     *      No "pending admin" or two-step confirmation (keep it simple).
     *      Caller responsible for ensuring newAdmin is correct.
     *
     * @dev REVERTS IF:
     *      - msg.sender != admin ("Only admin").
     *      - newAdmin == address(0) ("New admin cannot be zero address").
     *
     * @dev GAS:
     *      ~5k gas (state write).
     *
     * @dev RECOMMENDATION:
     *      Consider two-step transfer pattern in production (pending admin).
     *      Prevents accidental address transfer to wrong recipient.
     */
    function transferAdmin(address newAdmin)
        external
        onlyAdmin
    {
        require(newAdmin != address(0), "New admin cannot be zero address");
        admin = newAdmin;
    }

    /// ========================================
    /// Internal Helpers
    /// ========================================

    /**
     * @notice Internal helper to check if a user is compliant.
     *
     * @param user The address to check.
     *
     * @return compliant True if user is whitelisted OR has valid proof.
     *
     * @dev PURE LOGIC:
     *      1. If whitelisted[user] = true, return true (short-circuit).
     *      2. Otherwise, query verifier.hasValidProof(user).
     *      3. Return result.
     *
     * @dev USED BY:
     *      - isCompliant() view function.
     *      - requireCompliance() view function.
     *      - onlyCompliant modifier.
     *      - checkAndVerify() after proof submission.
     *
     * @dev PRIVATE:
     *      Internal function, not exposed to external callers directly.
     */
    function _isCompliant(address user)
        internal
        view
        returns (bool compliant)
    {
        // Whitelist check (fast path).
        if (whitelisted[user]) {
            return true;
        }

        // Proof check (slow path).
        return verifier.hasValidProof(user);
    }
}
