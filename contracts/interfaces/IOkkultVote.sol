// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IOkkultVote
 * @author Okkult Protocol
 * @notice Standard interface for private on-chain governance via Okkult.
 *
 * OkkultVote enables decentralized governance where:
 * 1. Poll creators submit proposals with a voter root (Merkle tree of eligible voters).
 * 2. Eligible voters cast encrypted votes using zero-knowledge proofs.
 * 3. Votes remain private on-chain; only encrypted votes and nullifiers are visible.
 * 4. Vote tallying is performed via zk-SNARK, proving correct aggregation without revealing votes.
 *
 * This protocol combines ideas from MACI (Minimal Anti-Collusion Infrastructure) with
 * Okkult's zero-knowledge compliance layer to ensure:
 * - Voter privacy: Individual votes are encrypted and cannot be linked to voters.
 * - Compliance: Only non-sanctioned addresses (with valid Okkult proofs) can vote.
 * - Vote integrity: One-vote-per-person via nullifiers, impossible to double-vote.
 * - Tally correctness: Tallier must prove correct aggregation without decryption.
 *
 * @dev VOTING FLOW:
 *      1. Poll Creator submits createPoll() with title, description, voter Merkle root, start/end times.
 *      2. Poll enters ACTIVE state when block.timestamp >= startTime.
 *      3. Eligible voters generate ZK proof proving:
 *         - They are included in the voter Merkle root.
 *         - They have a valid Okkult compliance proof.
 *         - They have not previously voted (nullifier not used).
 *      4. Voters submit castVote() with encrypted vote and proof (vote remains encrypted on-chain).
 *      5. After poll ends (block.timestamp >= endTime), poll transitions to CLOSED state.
 *      6. Tallier generates off-chain ZK proof over all encrypted votes, proving:
 *         - Correct decryption and aggregation (yes + no counts).
 *         - All votes are valid (correct nullifiers, no duplicates).
 *      7. Tallier calls tallyVotes() with aggregated counts and proof.
 *      8. Poll transitions to TALLIED state; results are immutable.
 *
 * @dev NULLIFIER SEMANTICS:
 *      - Voter generates nullifier = hash(voter_secret, pollId).
 *      - Each voter can vote only once per poll (nullifier prevents replay within same poll).
 *      - Using hash(voter_secret, pollId) instead of global nullifier allows voting in multiple polls.
 *      - Tallier never learns the voter_secret; cannot forge votes.
 */

interface IOkkultVote {
    /// ========================================
    /// Poll Status Enum
    /// ========================================

    /**
     * @dev Poll lifecycle states:
     *
     * PENDING (0):
     *   - Poll created but startTime has not arrived.
     *   - Voting not yet permitted.
     *   - Transition: startTime arrives OR governance manually advances.
     *
     * ACTIVE (1):
     *   - startTime <= block.timestamp < endTime.
     *   - Voters may submit votes via castVote().
     *   - New votes are accepted and nullifiers checked for duplicates.
     *   - Transition: Automatic when endTime arrives (CLOSED).
     *
     * CLOSED (2):
     *   - endTime <= block.timestamp.
     *   - Voting is closed; no new votes accepted.
     *   - Tallier performs off-chain computation: decrypt votes and aggregate counts.
     *   - Transition: tallyVotes() called with proof and counts (TALLIED).
     *
     * TALLIED (3):
     *   - Results finalized; vote counts immutable.
     *   - No further state changes allowed.
     *   - Results are accessible via pollResults() or similar query.
     *   - Governance can now act on results (execute proposal, etc.).
     */
    enum PollStatus {
        PENDING,
        ACTIVE,
        CLOSED,
        TALLIED
    }

    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when a new poll is created.
     * @param pollId Unique identifier for this poll (typically sequential).
     * @param title Short title of the poll/proposal.
     * @param voterRoot Merkle root of voters eligible to participate in this poll.
     * @param startTime Unix timestamp when voting begins (block.timestamp >= startTime).
     * @param endTime Unix timestamp when voting ends (block.timestamp >= endTime).
     *
     * @dev Off-chain indexers listen to PollCreated to:
     *      1. Enable ballot interfaces (show proposals to eligible voters).
     *      2. Track voter Merkle roots (needed for proof generation).
     *      3. Monitor poll timing and readiness for voting.
     *
     * @dev voterRoot must be a Merkle root of all eligible voters' addresses (or identifiers).
     *      Implementation should allow governance to pre-compute and specify this root.
     *      Typically constructed from a DAO token snapshot at a block height.
     */
    event PollCreated(
        uint256 indexed pollId,
        string title,
        bytes32 voterRoot,
        uint256 startTime,
        uint256 endTime
    );

    /**
     * @notice Emitted when a voter submits an encrypted vote.
     * @param pollId The poll in which the vote was cast.
     * @param nullifier The voter's nullifier for this poll (prevents double-voting).
     * @param encryptedVote The encrypted vote (only tally executor can decrypt).
     *
     * @dev Indexed fields (pollId, nullifier) allow off-chain systems to:
     *      1. Reconstruct vote lists per poll.
     *      2. Detect duplicate nullifiers (would fail on-chain, event confirms success).
     *      3. Monitor participation rates.
     *
     * @dev The encryptedVote is typically:
     *      - A threshold encryption of a vote value (yes=1, no=0).
     *      - Encrypted under a tally executor's public key.
     *      - Only decryptable by entities holding the corresponding private key.
     *      - Format is implementation-specific (can be AES-GCM, ElGamal, etc.).
     *
     * @dev Sender (msg.sender) is NOT emitted in this event:
     *      - Vote privacy principle: on-chain system doesn't know who voted what.
     *      - Only the voter knows their address + encrypted vote relationship.
     *      - Tallier learns encryption but never learns voter identity.
     */
    event VoteCast(
        uint256 indexed pollId,
        bytes32 indexed nullifier,
        bytes32 encryptedVote
    );

    /**
     * @notice Emitted when poll results are finalized via tallying.
     * @param pollId The poll whose results are being published.
     * @param totalYes Count of votes for "yes" option.
     * @param totalNo Count of votes for "no" option.
     * @param totalVotes Total valid votes cast (totalYes + totalNo).
     *
     * @dev Results are immutable after this event. Governance contracts can listen
     *      to this event to trigger proposal execution, parameter updates, etc.
     *
     * @dev Tallier must prove (via ZK proof in tallyVotes()):
     *      1. Correct decryption of all submitted votes.
     *      2. Correct aggregation (sum of yes + no).
     *      3. No double-counting (each nullifier counted once).
     *      4. No data corruption (votes not modified post-cast).
     *
     * @dev Invalid/abstain votes are counted against totalVotes but not for yes/no:
     *      - Possible vote formats: YES=1, NO=0, ABSTAIN=2.
     *      - totalVotes includes all submitted votes.
     *      - Participation rate = totalVotes / pollEligibleVoters.
     */
    event PollTallied(
        uint256 indexed pollId,
        uint256 totalYes,
        uint256 totalNo,
        uint256 totalVotes
    );

    /// ========================================
    /// Poll Creation and Configuration
    /// ========================================

    /**
     * @notice Creates a new poll and collects a fee from the poll creator.
     *
     * @param title Human-readable poll title (e.g., "Increase treasury allocation to grants").
     * @param description Extended description of the poll (can be IPFS hash or short text).
     * @param voterRoot Merkle root of eligible voters (created off-chain from token snapshot).
     * @param startTime Unix timestamp when voting becomes active (must be >= block.timestamp).
     * @param endTime Unix timestamp when voting closes (must be > startTime).
     *
     * @return pollId Unique identifier for this poll (typically sequential counter).
     *
     * @dev REQUIRES:
     *      - msg.value == 0.01 ETH (poll creation fee, prevents spam).
     *      - startTime >= block.timestamp (cannot create poll in the past).
     *      - endTime > startTime (voting period must have positive duration).
     *      - voterRoot != 0 (must specify eligible voter set).
     *
     * @dev FEE MODEL:
     *      - 0.01 ETH is collected per poll to prevent governance spam.
     *      - Fees are either:
     *        1. Accumulated in contract for governance treasury withdrawal.
     *        2. Immediately forwarded to fee recipient (treasury address).
     *      - Refunds not provided (fee incentivizes quality proposals).
     *
     * @dev STATE TRANSITIONS:
     *      - Poll is created in PENDING state (startTime not yet reached).
     *      - After block.timestamp > startTime, poll moves to ACTIVE.
     *      - votingSystem may implement block.timestamp checks or explicit transitions.
     *
     * @dev voterRoot Derivation (Off-chain):
     *      Typical construction:
     *      1. Snapshot DAO token holders at specific block height.
     *      2. Build Merkle tree from address list (leaf = hash(address)).
     *      3. Root = Merkle(address_0, address_1, ..., address_n).
     *      4. Voters use Merkle proofs to prove their inclusion during castVote().
     *
     * @dev Governance Flexibility:
     *      Different polls can have different voter roots, enabling:
     *      - KULT holder voting (high threshold).
     *      - Community voting (low threshold, token-weighted snapshot).
     *      - Quadratic voting (snapshot with quadratic scaling).
     *      - Weighted voting (snapshot with explicit stake per voter).
     */
    function createPoll(
        string calldata title,
        string calldata description,
        bytes32 voterRoot,
        uint256 startTime,
        uint256 endTime
    ) external payable returns (uint256 pollId);

    /// ========================================
    /// Vote Submission and Tallying
    /// ========================================

    /**
     * @notice Casts an encrypted vote in an active poll using zero-knowledge proof.
     *
     * @param pollId The poll in which the vote is being cast.
     * @param encryptedVote The voter's vote, encrypted under the tally executor's public key.
     * @param nullifier The voter's nullifier for this poll (prevents double-voting).
     *      - Derived as: keccak256(voter_secret, pollId).
     *      - Unique per (voter, pollId) pair.
     *      - Prevents same voter from casting multiple votes in this poll.
     * @param proof_a First component of the zk-SNARK proof.
     * @param proof_b Second component of the zk-SNARK proof.
     * @param proof_c Third component of the zk-SNARK proof.
     *
     * @dev REQUIRES:
     *      - Poll is in ACTIVE state (startTime <= block.timestamp < endTime).
     *      - Nullifier has not been previously used in this poll (via hasVoted).
     *      - Zero-knowledge proof is valid.
     *
     * @dev PROOF CIRCUIT VERIFICATION:
     *      Proof must verify the following without revealing voter identity:
     *      1. Voter is in voterRoot (Merkle proof of inclusion).
     *      2. Voter has valid Okkult compliance proof (address not sanctioned).
     *      3. Nullifier = hash(voter_secret, pollId) (derives from voter's secret + poll).
     *      4. Vote format is valid (YES, NO, or ABSTAIN, not garbage).
     *      5. encryptedVote is correctly formed (cannot reveal vote, must check structure).
     *
     * @dev NULLIFIER STORAGE:
     *      After successful proof verification, implementation MUST:
     *      1. Check hasVoted(pollId, nullifier) returns false (prevent replay).
     *      2. Store nullifier as "used" (typically: usedNullifiers[pollId][nullifier] = true).
     *      3. Emit VoteCast event.
     *
     * @dev VOTE PRIVACY:
     *      - Encrypted vote remains opaque to contract (not decrypted on-chain).
     *      - Only tally executor (off-chain entity with private key) can decrypt.
     *      - Contract never learns individual votes; only aggregates in tallyVotes.
     *
     * @dev GAS CONSIDERATION:
     *      - Proof verification is expensive (typically 2M-3M gas for Groth16).
     *      - Nullifier storage and duplicate check adds ~500 gas.
     *      - Total: ~2.5M gas per vote (acceptable for L1, may batch on L2).
     *
     * @dev REVERTS IF:
     *      - Poll not in ACTIVE state.
     *      - Nullifier already used in this poll.
     *      - Proof verification fails.
     *      - Voter not in voterRoot (proof fails inclusion check).
     *      - Voter lacks Okkult compliance proof.
     */
    function castVote(
        uint256 pollId,
        bytes32 encryptedVote,
        bytes32 nullifier,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external;

    /**
     * @notice Finalizes poll results by tallying encrypted votes with a zero-knowledge proof.
     *
     * @param pollId The poll whose votes are being tallied.
     * @param totalYes Count of votes for the "yes" option.
     * @param totalNo Count of votes for the "no" option.
     * @param proof_a First component of the tally zk-SNARK proof.
     * @param proof_b Second component of the tally zk-SNARK proof.
     * @param proof_c Third component of the tally zk-SNARK proof.
     *
     * @dev REQUIRES:
     *      - Poll is in CLOSED state (endTime <= block.timestamp).
     *      - Poll is not already TALLIED (cannot double-tally).
     *      - Zero-knowledge tally proof is valid.
     *
     * @dev PROOF CIRCUIT VERIFICATION (Tally Proof):
     *      This is a more complex circuit than castVote. It must prove:
     *      1. Decryption: All submitted encryptedVotes are correctly decrypted to votes.
     *      2. Aggregation: sum(decrypted_votes == YES) == totalYes.
     *      3. Aggregation: sum(decrypted_votes == NO) == totalNo.
     *      4. Completeness: All votes are accounted for (no omissions).
     *      5. No tampering: Vote data (encryptedVote, nullifier) has not changed post-submission.
     *      6. Uniqueness: Each nullifier is counted exactly once (no double-counting).
     *
     * @dev PRACTICAL IMPLEMENTATION:
     *      - Tallier (off-chain entity) collects all VoteCast events from transaction logs.
     *      - Tallier decrypts encryptedVote fields using the tally executor's private key.
     *      - Tallier counts yes/no votes from decrypted values.
     *      - Tallier computes ZK proof over vote list + counts to prove correctness.
     *      - Tallier submits totalYes, totalNo, proof via tallyVotes().
     *
     * @dev STATE TRANSITION:
     *      - Poll transitions from CLOSED to TALLIED.
     *      - Emits PollTallied event with results (immutable).
     *      - totalVotes is computed as totalYes + totalNo (may exclude abstentions).
     *      - Results can now be acted upon by governance (execute proposal, etc.).
     *
     * @dev SECURITY NOTES:
     *      - Tallier must be trusted (holds encryption private key, can decrypt votes).
     *      - Incorrect tally proof (count mismatch) is cryptographically proven and rejected.
     *      - Multiple talliers can compete to submit first valid tally (race condition).
     *      - If multiple valid tallies possible (e.g., corrupted vote), only first is accepted.
     *
     * @dev REVERTS IF:
     *      - Poll not in CLOSED state.
     *      - Poll already TALLIED.
     *      - Tally proof does not verify.
     *      - Counts do not match expected vote structure (proof fails aggregation check).
     */
    function tallyVotes(
        uint256 pollId,
        uint256 totalYes,
        uint256 totalNo,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external;

    /// ========================================
    /// Vote Status Queries
    /// ========================================

    /**
     * @notice Checks whether a specific nullifier has already voted in a poll.
     *
     * @param pollId The poll to check voting history in.
     * @param nullifier The voter's nullifier for this poll.
     *
     * @return voted True if this nullifier has already submitted a vote in this poll,
     *               false if it has not voted yet.
     *
     * @dev PREVENTS DOUBLE-VOTING:
     *      - Each voter derives nullifier = hash(voter_secret, pollId).
     *      - After successful castVote(), nullifier is marked as used.
     *      - Any subsequent castVote() with same nullifier is rejected.
     *      - Only one vote per voter per poll is possible.
     *
     * @dev USAGE:
     *      1. Off-chain: Voters check before generating proof to avoid wasted computation.
     *      2. On-chain: castVote() calls this function to prevent replay attacks.
     *      3. Auditing: Governance can query to determine participation without revealing voters.
     *
     * @dev RETURNS FALSE FOR:
     *      - Nullifier never submitted (nonexistent voter or new voter).
     *      - Different poll (nullifier is per-poll-specific, polls are independent).
     *      - Previous poll (nullifier structure includes pollId, preventing cross-poll reuse).
     *
     * @dev GAS COST:
     *      - Simple mapping lookup: ~2100 gas (cold) or ~100 gas (warm).
     *      - Repeated queries in same transaction are cheaper (warm cache).
     */
    function hasVoted(uint256 pollId, bytes32 nullifier)
        external
        view
        returns (bool voted);
}
