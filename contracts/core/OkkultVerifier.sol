// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../base/NullifierRegistry.sol";
import "../base/ComplianceTree.sol";
import "../interfaces/IOkkultVerifier.sol";

/**
 * @title OkkultVerifier
 * @author Okkult Protocol
 * @notice Main on-chain contract for verifying zero-knowledge compliance proofs.
 *
 * OkkultVerifier is the heart of the Okkult Protocol. It:
 * 1. Receives ZK proofs from users claiming address non-sanctioned status.
 * 2. Delegates proof verification to a Circom verifier contract.
 * 3. Checks proof against current/historical compliance tree roots.
 * 4. Prevents proof replay via nullifier registry.
 * 5. Records valid proofs with 30-day expiry per user.
 * 6. Collects protocol fees (routed to treasury).
 *
 * PROOF FLOW:
 * 1. User generates ZK proof off-chain proving:
 *    - Address is included in ComplianceTree root (not OFAC sanctioned).
 *    - Proof is derived from user's private key (proves authorization).
 * 2. User submits proof on-chain via verifyProof() with 0.001 ETH fee.
 * 3. OkkultVerifier checks:
 *    - Fee is sufficient.
 *    - Root is valid and not stale (< 48 hours old).
 *    - Nullifier hasn't been used (prevents replay).
 *    - Circom verifier confirms proof is cryptographically valid.
 * 4. On success:
 *    - Nullifier is marked as used (prevents reuse of same proof).
 *    - User's lastValidProof is set to current time + 30 days.
 *    - Fee is sent to treasury.
 *    - ProofVerified event is emitted.
 * 5. Protocols query hasValidProof(user) to gate operations.
 *
 * PROOF VALIDITY:
 * - After verification, proof is valid for 30 days.
 * - After 30 days, user must re-verify with fresh proof.
 * - Prevents stale sanctioned-list data from being exploited.
 * - Monthly re-verification enables compliance monitoring.
 *
 * NULLIFIER SEMANTICS:
 * - Nullifier = hash(user_secret, proof_data) computed in circuit.
 * - Each proof generates unique nullifier.
 * - Nullifier is revealed on-chain (indexed for easy lookup).
 * - Same proof resubmitted generates same nullifier (replay prevented).
 * - Allows off-chain systems to track submitted proofs without learning identity.
 *
 * ROOT STALENESS:
 * - Root must be <= 48 hours old (ComplianceTree.MAX_ROOT_AGE).
 * - ComplianceTree updates root every ~6 hours from OFAC data.
 * - If no update for 48 hours, all proofs fail (fail-safe).
 * - Prevents exploitation of outdated sanctions lists.
 *
 * INTEGRATION:
 * Protocols call hasValidProof(user) to check if user has valid proof:
 * ```solidity
 * if (okkultVerifier.hasValidProof(msg.sender)) {
 *     // User is verified compliant, proceed with transaction.
 * }
 * ```
 *
 * @dev TRUST MODEL:
 *      - Circom verifier is trusted (proof circuit is audited).
 *      - ComplianceTree is trusted (root is authoritative OFAC source).
 *      - NullifierRegistry is trusted (prevents proof replay).
 *      - Treasury is trusted (destination for protocol fees).
 *      - All are set once at deployment (immutable thereafter).
 *
 * @dev SECURITY:
 *      - Proof validity window (30 days) prevents perpetual compliance.
 *      - Nullifier replay prevention stops double-verification.
 *      - Root staleness check stops using outdated sanctions data.
 *      - Circom verification ensures cryptographic soundness.
 */
interface ICircomVerifier {
    /**
     * @notice Verifies a zk-SNARK proof against public inputs.
     *
     * @param a First component of the proof (point on curve).
     * @param b Second component of the proof (pairing-friendly point).
     * @param c Third component of the proof (point on curve).
     * @param input Public inputs to the proof circuit (root, nullifier, etc.).
     *
     * @return valid True if proof verifies, false otherwise.
     *
     * @dev This is typically a Circom-generated Solidity verifier.
     *      The circuit encodes the compliance logic (address in tree, etc.).
     *      This contract just forwards the proof for verification.
     */
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[2] calldata input
    ) external view returns (bool valid);
}

contract OkkultVerifier is IOkkultVerifier {
    /// ========================================
    /// Dependencies
    /// ========================================

    /// @notice Registry of used nullifiers (prevents proof replay).
    /// @dev Immutable after deployment. Shared across all proofs.
    NullifierRegistry public nullifierRegistry;

    /// @notice Current and historical compliance tree roots (OFAC list).
    /// @dev Immutable after deployment. Updated every ~6 hours by off-chain service.
    ComplianceTree public complianceTree;

    /// @notice Circom-generated ZK proof verifier contract.
    /// @dev Immutable after deployment. Encodes compliance logic in circuit.
    ICircomVerifier public circomVerifier;

    /// @notice Treasury address receiving protocol fees.
    /// @dev Immutable after deployment. Typically DAO or governance contract.
    address public treasury;

    /// ========================================
    /// Constants
    /// ========================================

    /// @notice Duration for which a proof remains valid (30 days).
    /// @dev After this period, user must re-verify with fresh proof.
    /// @dev Enforces regular proof rotation (compliance monitoring).
    /// @dev Value: 30 * 24 * 3600 = 2,592,000 seconds.
    uint256 public constant PROOF_VALIDITY = 30 days;

    /// @notice Fee required to submit a proof (0.001 ETH).
    /// @dev Prevents spam and incentivizes honest submissions.
    /// @dev Routed to treasury for protocol maintenance.
    /// @dev Value: 0.001 ETH = 10^15 wei.
    uint256 public constant PROOF_FEE = 0.001 ether;

    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice Timestamp when user's current proof expires (0 if no proof).
    /// @dev Maps user address → expiry timestamp.
    /// @dev If block.timestamp < lastValidProof[user], proof is valid.
    /// @dev If block.timestamp >= lastValidProof[user], proof has expired.
    /// @dev Updated when verifyProof() is called successfully.
    mapping(address => uint256) public lastValidProof;

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes OkkultVerifier with all required dependencies.
     *
     * @param _nullifierRegistry Address of the NullifierRegistry contract.
     * @param _complianceTree Address of the ComplianceTree contract.
     * @param _circomVerifier Address of the Circom proof verifier contract.
     * @param _treasury Address to receive protocol fees.
     *
     * @dev REQUIREMENTS:
     *      - All addresses must be non-zero.
     *      - All referenced contracts must exist and be properly initialized.
     *      - Typical deployment order:
     *        1. Deploy NullifierRegistry.
     *        2. Deploy ComplianceTree.
     *        3. Deploy Circom verifier contract (generated from circuit).
     *        4. Deploy OkkultVerifier with all above addresses.
     *
     * @dev IMMUTABILITY:
     *      All dependencies are set once and cannot be changed.
     *      If any dependency needs upgrading, deploy new OkkultVerifier.
     *      Prevents accidental misconfiguration or compromised dependencies.
     *
     * @dev GAS:
     *      Constructor stores 4 addresses: ~80k gas.
     */
    constructor(
        address _nullifierRegistry,
        address _complianceTree,
        address _circomVerifier,
        address _treasury
    ) {
        require(
            _nullifierRegistry != address(0),
            "NullifierRegistry cannot be zero"
        );
        require(
            _complianceTree != address(0),
            "ComplianceTree cannot be zero"
        );
        require(
            _circomVerifier != address(0),
            "CircomVerifier cannot be zero"
        );
        require(_treasury != address(0), "Treasury cannot be zero");

        nullifierRegistry = NullifierRegistry(_nullifierRegistry);
        complianceTree = ComplianceTree(_complianceTree);
        circomVerifier = ICircomVerifier(_circomVerifier);
        treasury = _treasury;
    }

    /// ========================================
    /// Proof Verification (IOkkultVerifier)
    /// ========================================

    /**
     * @notice Verifies a zero-knowledge compliance proof and records validity if successful.
     *
     * @param proof_a First component of the zk-SNARK proof (G1 point).
     * @param proof_b Second component of the zk-SNARK proof (G2 point).
     * @param proof_c Third component of the zk-SNARK proof (G1 point).
     * @param publicInputs Array containing two public inputs:
     *      - publicInputs[0]: Merkle root of compliance tree (proof against this root).
     *      - publicInputs[1]: Nullifier hash (prevents proof replay).
     *
     * @return success True if proof is valid and recorded, false on failure.
     *
     * @dev REQUIRES (Reverts on failure):
     *      - msg.value >= PROOF_FEE ("Insufficient fee").
     *      - publicInputs[0] is a valid historical root ("Invalid root").
     *      - ComplianceTree's current root is not stale ("Tree outdated").
     *      - Nullifier hasn't been used ("Already used").
     *      - Circom verifier confirms proof is valid ("Invalid ZK proof").
     *
     * @dev PROOF CIRCUIT LOGIC (verified by Circom):
     *      The circuit proves (without revealing prover identity):
     *      1. Merkle proof: address is in tree rooted at publicInputs[0].
     *      2. Nullifier encoding: publicInputs[1] = hash(address_secret, salt).
     *      3. No additional constraints (circuit-dependent).
     *
     * @dev ALGORITHM:
     *      1. Check fee is sufficient.
     *      2. Extract root and nullifier from publicInputs.
     *      3. Validate root is in ComplianceTree (current or recent).
     *      4. Check ComplianceTree is not stale (updated within 48 hours).
     *      5. Check Circom verifier confirms proof.
     *      6. Check nullifier has not been used before.
     *      7. Mark nullifier as used in NullifierRegistry.
     *      8. Record proof validity: lastValidProof[msg.sender] = now + 30 days.
     *      9. Transfer fee to treasury.
     *      10. Emit ProofVerified event.
     *      11. Return true.
     *
     * @dev FEE MODEL:
     *      - User pays 0.001 ETH per proof submission.
     *      - Fee is non-refundable (sent to treasury immediately).
     *      - Excess ETH (msg.value > PROOF_FEE) is kept by contract.
     *      - Recommended: Send exactly PROOF_FEE (0.001 ETH).
     *      - Optional: Implement refund logic for overpayment (future).
     *
     * @dev PROOF EXPIRY:
     *      - After successful verification, user's proof is valid for 30 days.
     *      - After 30 days, hasValidProof(user) returns false.
     *      - User must re-submit new proof (new Circom proof generation).
     *      - Enforces compliance re-certification every 30 days.
     *
     * @dev NULLIFIER STORAGE:
     *      - Nullifier is marked as used in NullifierRegistry.
     *      - Same proof resubmitted (generates same nullifier) will revert ("Already used").
     *      - Off-chain systems can query NullifierRegistry to detect proof reuse attempts.
     *      - Nullifier is publicly visible on-chain but doesn't reveal prover identity.
     *
     * @dev NOT ATOMIC:
     *      - If Circom verification fails, all changes are reverted (revert before state change).
     *      - Each step reverts early on failure (fail-fast pattern).
     *
     * @dev GAS COST:
     *      - Circom verification: ~2-3M gas (dominant cost).
     *      - Root/nullifier checks: ~3-5k gas.
     *      - Nullifier marking: ~20k gas.
     *      - Fee transfer: ~5k gas.
     *      - Total: ~2-3M gas (bounded by Circom).
     *
     * @dev REVERTS ON:
     *      - msg.value < PROOF_FEE.
     *      - Root not in ComplianceTree.
     *      - ComplianceTree is stale (> 48 hours).
     *      - Nullifier already used.
     *      - Circom verifier confirms proof is invalid.
     *      - Fee transfer fails (treasury address reverts).
     */
    function verifyProof(
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c,
        uint[2] calldata publicInputs
    ) external payable returns (bool success) {
        // ========== Step 1: Check fee ==========
        require(msg.value >= PROOF_FEE, "Insufficient fee");

        // ========== Step 2 & 3: Extract public inputs ==========
        bytes32 root = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);

        // ========== Step 4: Validate root is known to ComplianceTree ==========
        require(
            complianceTree.isHistoricalRoot(root),
            "Invalid root"
        );

        // ========== Step 5: Check ComplianceTree is not stale ==========
        require(
            complianceTree.isRootValid(),
            "Tree outdated"
        );

        // ========== Step 6: Check nullifier hasn't been used ==========
        require(
            !nullifierRegistry.isUsed(nullifier),
            "Already used"
        );

        // ========== Step 7: Verify Circom proof ==========
        require(
            circomVerifier.verifyProof(proof_a, proof_b, proof_c, publicInputs),
            "Invalid ZK proof"
        );

        // ========== Step 8: Mark nullifier as used ==========
        nullifierRegistry.markUsed(nullifier);

        // ========== Step 9: Record proof validity (30 days from now) ==========
        lastValidProof[msg.sender] = block.timestamp + PROOF_VALIDITY;

        // ========== Step 10: Transfer fee to treasury ==========
        payable(treasury).transfer(msg.value);

        // ========== Step 11: Emit event ==========
        emit ProofVerified(msg.sender, nullifier, lastValidProof[msg.sender]);

        // ========== Step 12: Return success ==========
        return true;
    }

    /// ========================================
    /// Proof Status Queries (IOkkultVerifier)
    /// ========================================

    /**
     * @notice Returns whether a user currently has a valid, non-expired compliance proof.
     *
     * @param user The address to check for proof validity.
     *
     * @return valid True if user has submitted a valid proof and it has not expired,
     *               false if no proof exists or the proof has expired.
     *
     * @dev RETURNS TRUE IF:
     *      - lastValidProof[user] > block.timestamp (proof not yet expired).
     *
     * @dev RETURNS FALSE IF:
     *      - lastValidProof[user] == 0 (no proof ever submitted).
     *      - lastValidProof[user] <= block.timestamp (proof has expired).
     *
     * @dev VIEW FUNCTION:
     *      Non-reverting, safe to call from anywhere.
     *      Can be called from within other transactions (used by ComplianceGate, etc).
     *
     * @dev USAGE:
     *      Protocols gate operations on hasValidProof(user):
     *      ```solidity
     *      if (okkultVerifier.hasValidProof(msg.sender)) {
     *          // User is verified compliant, allow operation.
     *      }
     *      ```
     *
     * @dev EXPIRY SEMANTICS:
     *      - Proof set to expire at block.timestamp + 30 days.
     *      - At exactly 30 days: hasValidProof returns false (can't use expired proof).
     *      - User must re-submit proof to regain compliance.
     *      - No grace period (strict 30-day window).
     *
     * @dev GAS COST:
     *      ~100 gas (simple mapping read + comparison).
     */
    function hasValidProof(address user)
        external
        view
        returns (bool valid)
    {
        return lastValidProof[user] > block.timestamp;
    }

    /**
     * @notice Returns the block timestamp at which a user's proof expires.
     *
     * @param user The address whose proof expiry is being queried.
     *
     * @return expiryTimestamp The Unix timestamp when the user's proof expires.
     *                         Returns 0 if no proof has been submitted by the user.
     *
     * @dev RETURN VALUES:
     *      - 0: No proof ever submitted (lastValidProof[user] not set).
     *      - Future timestamp: Proof is valid until block.timestamp reaches this value.
     *      - Past timestamp: Proof has expired (should use hasValidProof instead).
     *
     * @dev VIEW FUNCTION:
     *      Non-reverting, safe to call from anywhere.
     *
     * @dev USAGE:
     *      Off-chain systems monitor this to alert users before proof expires:
     *      ```
     *      const expiryTime = await verifier.proofExpiry(userAddress);
     *      const hoursLeft = (expiryTime - Date.now() / 1000) / 3600;
     *      if (hoursLeft < 24) alert("Proof expires in less than 1 day!");
     *      ```
     *
     * @dev EXPIRY CALCULATION:
     *      Expiry timestamp = verifyProof submission time + 30 days.
     *      Example:
     *      - Proof submitted at 2026-04-22 12:00:00 UTC (timestamp: 1750689600).
     *      - Expiry timestamp: 1750689600 + 2592000 = 1753281600 (2026-05-22 12:00:00 UTC).
     *
     * @dev GAS COST:
     *      ~100 gas (simple mapping read).
     */
    function proofExpiry(address user)
        external
        view
        returns (uint256 expiryTimestamp)
    {
        return lastValidProof[user];
    }
}
