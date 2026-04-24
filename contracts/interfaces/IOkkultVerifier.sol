// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IOkkultVerifier
 * @author Okkult Protocol
 * @notice Standard interface for verifying zero-knowledge compliance proofs on-chain.
 *
 * Protocols integrate this interface to check if a user has submitted and verified
 * a valid Okkult compliance proof. The proof demonstrates the user's address is not
 * sanctioned without revealing the address itself.
 *
 * @dev Implementers MUST enforce proof expiry semantics and prevent proof reuse via nullifiers.
 */
interface IOkkultVerifier {
    ///@dev Structure tracking verified proofs per user
    /// Stores proof expiry timestamp and nullifier to prevent replay attacks

    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when a valid zero-knowledge proof is verified on-chain.
     * @param prover The address that submitted the proof.
     * @param nullifier The nullifier hash (prevents proof replay).
     * @param validUntil The timestamp when this proof expires and becomes invalid.
     *
     * @dev The nullifier is indexed to allow efficient filtering of submitted proofs.
     *      Once a proof with a given nullifier is verified, the same proof cannot be
     *      submitted again by any party (privacy-preserving replay protection).
     */
    event ProofVerified(
        address indexed prover,
        bytes32 indexed nullifier,
        uint256 validUntil
    );

    /// ========================================
    /// Proof Verification
    /// ========================================

    /**
     * @notice Verifies a zk-SNARK proof and records the prover's compliance status.
     *
     * @param proof_a The first component of the zk-SNARK proof (point on curve).
     * @param proof_b The second component of the zk-SNARK proof (pairing-friendly point).
     * @param proof_c The third component of the zk-SNARK proof (point on curve).
     * @param publicInputs Array containing public inputs to the proof circuit:
     *      - publicInputs[0]: Merkle root of the compliance tree (OFAC exclusion list).
     *      - publicInputs[1]: Nullifier hash (prevents proof reuse/replay attacks).
     *
     * @return success True if the proof verifies and is recorded, false otherwise.
     *
     * @dev Implementation MUST:
     *      1. Use a pairing-based verification algorithm (Groth16, Marlin, etc.).
     *      2. Validate the Merkle root is current or within acceptable staleness window.
     *      3. Check the nullifier has not been previously used (prevents replay attacks).
     *      4. Store the proof's expiry timestamp and emit ProofVerified event.
     *      5. Apply a proof submission fee (if implementing economic incentives).
     *
     * @dev Proof expiry is typically set to current block timestamp + 30 days, allowing
     *      users to prove compliance once per month. This prevents stale proofs from being
     *      reused after a user has been sanctioned.
     *
     * @dev The function accepts native ETH (payable) to support optional proof fees
     *      or incentive mechanisms, though core verification does not require payment.
     */
    function verifyProof(
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c,
        uint[2] calldata publicInputs
    ) external payable returns (bool success);

    /// ========================================
    /// Proof Status Queries
    /// ========================================

    /**
     * @notice Returns whether a user currently has a valid, non-expired compliance proof.
     *
     * @param user The address to check for proof validity.
     *
     * @return valid True if the user has submitted a valid proof and it has not expired,
     *               false if no proof exists or the proof has expired.
     *
     * @dev This function MUST return false if:
     *      - The user has not submitted any proof via verifyProof().
     *      - The proof's expiry timestamp has passed (block.timestamp >= proofExpiry).
     *
     * @dev Clients use this function to gate access to privacy-enabled features.
     *      Once a proof expires, users must re-generate and re-submit a new proof.
     */
    function hasValidProof(address user)
        external
        view
        returns (bool valid);

    /**
     * @notice Returns the block timestamp at which a user's proof expires.
     *
     * @param user The address whose proof expiry is being queried.
     *
     * @return expiryTimestamp The Unix timestamp when the user's proof expires.
     *                         Returns 0 if no proof has been submitted by the user.
     *
     * @dev Clients monitor this value to alert users when re-verification is needed.
     *      If block.timestamp >= expiryTimestamp, the proof is considered expired.
     *
     * @dev This function enables:
     *      1. Time-locked access patterns in protocols integrating Okkult.
     *      2. Batch proof re-submission campaigns (e.g., monthly rotation).
     *      3. Monitoring of proof freshness for compliance audits.
     */
    function proofExpiry(address user)
        external
        view
        returns (uint256 expiryTimestamp);
}
