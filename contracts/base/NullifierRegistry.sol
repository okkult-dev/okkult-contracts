// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NullifierRegistry
 * @author Okkult Protocol
 * @notice On-chain registry for storing used ZK proof nullifiers.
 *
 * Nullifiers are deterministic hash values derived from zero-knowledge proofs.
 * Each nullifier can be submitted exactly once. The NullifierRegistry prevents
 * proof replay attacks by maintaining a public record of all used nullifiers.
 *
 * CONTRACT DESIGN PRINCIPLES:
 * 1. Immutable by design (no upgradability, no admin functions).
 * 2. Single responsibility: Track nullifier usage only.
 * 3. Write access: Only the designated verifier contract can call markUsed().
 * 4. Read access: Anyone can query isUsed() to check nullifier status.
 * 5. Simple state: Single mapping (bytes32 → bool) for nullifier tracking.
 *
 * SECURITY PROPERTIES:
 * - Once a nullifier is marked as used, it cannot be unmarked (immutable).
 * - Only one verifier contract can write nullifiers (configured at deployment).
 * - Prevents double-spending of the same proof (crucial for privacy protocols).
 * - Public on-chain tracking enables off-chain indexing and auditing.
 *
 * NULLIFIER MODEL:
 * A nullifier is a hash that uniquely represents a specific zero-knowledge proof.
 * The verifier circuit deriving the nullifier ensures:
 * - Nullifier = hash(user_secret, proof_data) is deterministic per proof.
 * - Only the proof submitter can derive the nullifier (knowledge of user_secret).
 * - Revealing nullifier does not leak user_secret (one-way hash).
 * - Same proof resubmitted generates identical nullifier (replay detection).
 *
 * INTEGRATION:
 * After a ZK proof is verified (off-chain or via verifier contract),
 * the verifier calls markUsed(nullifier) to record usage on-chain.
 * Future proof submissions with the same nullifier are rejected.
 *
 * @dev This contract maintains no state beyond the mapping and verifier address.
 *      No governance, no upgrade paths, no external dependencies.
 *      Deploy once; use forever.
 */
contract NullifierRegistry {
    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice Mapping of nullifier → usage status.
    /// @dev true = nullifier has been used (proof already submitted).
    ///      false = nullifier is available (proof can still be submitted).
    ///      This is a public mapping; anyone can query the status.
    /// @dev NOTE: Once true, a nullifier CANNOT be reset to false.
    ///            Each nullifier represents exactly one proof submission.
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Address of the authorized verifier contract.
    /// @dev Only this address can call markUsed() to record new nullifiers.
    /// @dev Set once at deployment and immutable thereafter.
    address public verifier;

    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when a nullifier is marked as used.
     * @param nullifier The nullifier that has been consumed (proof submitted).
     *
     * @dev Off-chain indexers listen to this event to track:
     *      1. Real-time proof submission counts (metrics).
     *      2. Nullifier history (audit log).
     *      3. Proof replay attempts (nullifier reused → reverting transaction).
     *
     * @dev Indexed on nullifier to enable efficient filtering:
     *      - Query all uses of a specific nullifier (should be at most 1 via smart contract).
     *      - Filter logs by nullifier hash for off-chain verification.
     */
    event NullifierUsed(bytes32 indexed nullifier);

    /// ========================================
    /// Modifiers
    /// ========================================

    /**
     * @notice Restricts function access to the authorized verifier contract.
     * @dev Reverts with "Only verifier" if caller is not the verifier.
     *
     * @dev This is the only access control in the contract.
     *      Ensures critical state (usedNullifiers) cannot be modified by arbitrary callers.
     *      Verifier is set once at deployment and immutable (no way to reassign).
     */
    modifier onlyVerifier() {
        require(msg.sender == verifier, "Only verifier");
        _;
    }

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes the NullifierRegistry with a designated verifier contract.
     *
     * @param _verifier The address of the verifier contract authorized to mark nullifiers as used.
     *
     * @dev REQUIREMENTS:
     *      - _verifier must be a valid, non-zero address.
     *      - Typically, _verifier is the address of OkkultVerifier or similar proof verifier.
     *      - Once set, _verifier cannot be changed (immutable design).
     *
     * @dev DEPLOYMENT:
     *      1. Deploy NullifierRegistry first (no dependencies).
     *      2. Deploy OkkultVerifier, passing NullifierRegistry address.
     *      3. OkkultVerifier initializes with NullifierRegistry reference.
     *      4. Both contracts are now locked in (can never change pointer).
     *
     * @dev IMMUTABILITY:
     *      This contract intentionally has NO setVerifier() or admin functions.
     *      If verifier address needs updating, deploy a new NullifierRegistry
     *      and migrate to it (complex, but prevents accidental misconfiguration).
     *      Typically: verifier is deployed first in isolation, never changes.
     *
     * @dev GAS:
     *      Constructor stores verifier address once: ~20k gas.
     */
    constructor(address _verifier) {
        require(_verifier != address(0), "Verifier cannot be zero address");
        verifier = _verifier;
    }

    /// ========================================
    /// State Queries
    /// ========================================

    /**
     * @notice Checks whether a nullifier has already been used (proof already submitted).
     *
     * @param nullifier The nullifier to check.
     *
     * @return used True if nullifier has been marked as used (proof already submitted),
     *              false if nullifier is still available (proof can still be submitted).
     *
     * @dev VIEW FUNCTION — No state changes, safe to call from any contract/address.
     *
     * @dev USAGE PATTERNS:
     *      1. Off-chain: Before generating proof, check if nullifier already used (avoid wasted work).
     *      2. On-chain: Verifier checks isUsed() before accepting new proof submissions.
     *      3. Auditing: Query historical nullifiers to count proofs submitted for a given proof type.
     *
     * @dev GAS COST:
     *      - Storage read: ~2100 gas (cold access) or ~100 gas (warm access).
     *      - Repeated queries in same transaction are cheaper (warm cache).
     *
     * @dev IMMUTABILITY GUARANTEE:
     *      Once isUsed(nullifier) returns true, it will ALWAYS return true for that nullifier.
     *      There is no reset mechanism; this is by design to prevent proof reuse.
     */
    function isUsed(bytes32 nullifier)
        external
        view
        returns (bool used)
    {
        return usedNullifiers[nullifier];
    }

    /// ========================================
    /// Nullifier Management
    /// ========================================

    /**
     * @notice Records that a nullifier has been used (marks proof as submitted).
     *
     * @param nullifier The nullifier to mark as used.
     *
     * @dev REQUIRES:
     *      - caller must be the authorized verifier (enforced by onlyVerifier modifier).
     *      - nullifier must NOT already be in use (prevents duplicate marking).
     *      - nullifier must be non-zero (optional but recommended).
     *
     * @dev FLOW:
     *      1. Caller (verifier) submits nullifier.
     *      2. Check: require nullifier not already used (revert if duplicate).
     *      3. Action: Set usedNullifiers[nullifier] = true.
     *      4. Event: Emit NullifierUsed event.
     *      5. Return: Function completes successfully.
     *
     * @dev SAFETY:
     *      If markUsed() is called twice with same nullifier:
     *      - First call: Succeeds, marks nullifier as used.
     *      - Second call: Reverts with "Already used" (idempotency check fails).
     *      - This prevents accidental or malicious double-submission.
     *
     * @dev VERIFIER RESPONSIBILITY:
     *      The verifier contract is responsible for:
     *      1. Validating the proof before calling markUsed().
     *      2. Ensuring nullifier is correctly derived from the proof.
     *      3. Preventing the same proof from being verified twice.
     *      - If verifier fails to check, duplicate nullifiers can be submitted (bug in verifier logic).
     *
     * @dev ONE-WAY OPERATION:
     *      Once a nullifier is marked as used, there is NO reset or unmark function.
     *      Nullifiers are immutable once consumed.
     *      This ensures perfect replay attack prevention (no proof can ever be reused).
     *
     * @dev GAS COST:
     *      - Storage write: ~20k gas (cold) or ~3k gas (warm).
     *      - Event emission: ~375 gas.
     *      - Total: ~20-23k gas.
     *
     * @dev REVERTS ON:
     *      - msg.sender != verifier (modifier check).
     *      - usedNullifiers[nullifier] already true ("Already used").
     */
    function markUsed(bytes32 nullifier)
        external
        onlyVerifier
    {
        require(!usedNullifiers[nullifier], "Already used");
        usedNullifiers[nullifier] = true;
        emit NullifierUsed(nullifier);
    }
}
