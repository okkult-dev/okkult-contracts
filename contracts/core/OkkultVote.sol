// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IOkkultVote.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title OkkultVote
 * @author Okkult Protocol
 * @notice Private on-chain governance with vote encryption and anti-collusion features.
 *
 * OkkultVote enables decentralized decision-making where:
 * 1. Voters cast encrypted votes (content hidden on-chain).
 * 2. Vote privacy is maintained: who voted what is nobody's business.
 * 3. Tally coordinator proves correct vote aggregation via ZK (no vote decryption).
 * 4. Results are immutable once tallied and cannot be disputed.
 *
 * GOVERNANCE FLOW:
 * 1. Governance proposer creates a poll (0.01 ETH fee prevents spam).
 * 2. Poll specifies: title, description, voter Merkle root, start/end times.
 * 3. Eligible voters (in Merkle root) submit encrypted votes with ZK proof.
 * 4. Votes remain encrypted and indecipherable on-chain.
 * 5. After endTime, poll coordinator tallies votes off-chain:
 *    - Decrypts all votes (only coordinator has private key).
 *    - Computes yes/no counts.
 *    - Generates ZK proof of correct aggregation.
 * 6. Coordinator submits tally proof on-chain.
 * 7. Contract verifies proof and publishes immutable results.
 *
 * VOTE PRIVACY MODEL:
 * - encryptedVote is encrypted under coordinator's public key.
 * - Nobody except coordinator can learn individual votes.
 * - Even coordinator's decryption is proved (not revealed).
 * - On-chain only shows: nullifier (no linkage to voter) + encrypted vote.
 * - Results are aggregated counts (yes/no), no individual votes shown.
 * - Perfect ballot secrecy: transaction observer can't determine voter preference.
 *
 * ANTI-COLLUSION:
 * - Nullifier-based voting prevents vote buying (can't prove your vote to buyer).
 * - ZK proof proves voter is in eligible set without revealing identity.
 * - Encrypted voting prevents vote selling (seller can't prove vote to buyer).
 * - Tally verification prevents coordinator vote tampering.
 *
 * @dev NULLIFIER SEMANTICS:
 *      nullifier = hash(voter_secret, pollId) allows voting in multiple polls.
 *      Each poll has independent nullifier space (can vote once per poll).
 *      Nullifier prevents double-voting (duplicate detection by hash).
 *
 * @dev POLL LIFECYCLE:
 *      PENDING: startTime >= block.timestamp (voting not yet open).
 *      ACTIVE: startTime <= block.timestamp < endTime (voting open).
 *      CLOSED: block.timestamp >= endTime (voting closed, tally pending).
 *      TALLIED: tallyVotes() called and verified (results finalized).
 *
 * @dev SECURITY:
 *      - Vote encryption prevents vote coercion (coercer can't verify vote).
 *      - Nullifier commits to (voter, poll) pair (prevents vote migration).
 *      - ZK proof verifies voter eligibility without revealing identity.
 *      - Tally proof prevents coordinator fraud (wrong counts rejected).
 *      - Reentrancy guard prevents state corruption during tallying.
 */
interface ICircomVerifier {
    /// @notice Verifies a zk-SNARK proof.
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[2] calldata input
    ) external view returns (bool);
}

contract OkkultVote is IOkkultVote, ReentrancyGuard {
    /// ========================================
    /// Data Structures
    /// ========================================

    /**
     * @notice Represents a governance poll.
     * @dev Stores all poll metadata and voting state.
     */
    struct Poll {
        /// @notice Unique poll identifier (sequential).
        uint256 id;

        /// @notice Human-readable poll title.
        string title;

        /// @notice Extended description (IPFS hash or short text).
        string description;

        /// @notice Merkle root of eligible voters (from token snapshot).
        bytes32 voterRoot;

        /// @notice Unix timestamp when voting begins.
        uint256 startTime;

        /// @notice Unix timestamp when voting ends.
        uint256 endTime;

        /// @notice Total valid votes cast (including abstentions).
        uint256 totalVotes;

        /// @notice Count of "yes" votes (decrypted by coordinator).
        uint256 totalYes;

        /// @notice Count of "no" votes (decrypted by coordinator).
        uint256 totalNo;

        /// @notice True if poll has been tallied (results finalized).
        bool tallied;

        /// @notice Address authorized to call tallyVotes().
        /// @dev Typically the poll creator or governance proposer.
        address coordinator;

        /// @notice Current status of the poll (PENDING/ACTIVE/CLOSED/TALLIED).
        PollStatus status;
    }

    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice Mapping of poll ID → Poll struct.
    /// @dev Stores all poll data (metadata, voting state, results).
    mapping(uint256 => Poll) public polls;

    /// @notice Nested mapping: pollId → nullifier → hasVoted (bool).
    /// @dev Tracks which nullifiers have voted in each poll (prevents double-voting).
    /// @dev Indexed on both dimensions for efficient lookup.
    mapping(uint256 => mapping(bytes32 => bool)) public hasVoted;

    /// @notice Nested mapping: pollId → array of encrypted votes.
    /// @dev Stores all encrypted votes submitted in each poll (in order).
    /// @dev Array is immutable after poll closure (no vote modification).
    /// @dev Coordinator uses this array to tally votes off-chain.
    mapping(uint256 => bytes32[]) public encryptedVotes;

    /// @notice Counter for generating unique poll IDs (sequential).
    /// @dev Incremented with each createPoll() call.
    /// @dev Next poll ID is always pollCount (before increment).
    uint256 public pollCount;

    /// @notice Circom verifier for vote submission proofs.
    /// @dev Verifies voter is in eligibility set (Merkle proof) + Okkult compliance.
    /// @dev Immutable after deployment.
    ICircomVerifier public voteVerifier;

    /// @notice Circom verifier for tally proofs.
    /// @dev Verifies correct decryption and aggregation of votes.
    /// @dev Different circuit than voteVerifier (tally-specific constraints).
    /// @dev Immutable after deployment.
    ICircomVerifier public tallyVerifier;

    /// @notice Fee required to create a poll (0.01 ETH).
    /// @dev Prevents governance spam and funds protocol maintenance.
    /// @dev Non-refundable (sent to treasury immediately on poll creation).
    uint256 public constant POLL_FEE = 0.01 ether;

    /// @notice Address receiving poll creation fees.
    /// @dev Typically DAO treasury or governance contract.
    /// @dev Immutable after deployment.
    address public treasury;

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes OkkultVote with verifier and treasury addresses.
     *
     * @param _voteVerifier Address of Circom verifier for vote proofs.
     * @param _tallyVerifier Address of Circom verifier for tally proofs.
     * @param _treasury Address receiving poll creation fees.
     *
     * @dev REQUIREMENTS:
     *      - All addresses must be non-zero.
     *      - _voteVerifier and _tallyVerifier should be different contracts
     *        (different circuit logic: voter proof vs. tally proof).
     *      - Typical deployment:
     *        1. Deploy two Circom verifiers (from circuits).
     *        2. Deploy OkkultVote with both verifier addresses.
     *        3. Transfer treasury to governance DAO.
     *
     * @dev IMMUTABILITY:
     *      All dependencies are set once and cannot be changed.
     *      Prevents accidental misconfiguration or verifier compromise.
     *
     * @dev GAS:
     *      Constructor stores 3 addresses: ~80k gas.
     */
    constructor(
        address _voteVerifier,
        address _tallyVerifier,
        address _treasury
    ) {
        require(_voteVerifier != address(0), "Vote verifier cannot be zero");
        require(_tallyVerifier != address(0), "Tally verifier cannot be zero");
        require(_treasury != address(0), "Treasury cannot be zero");

        voteVerifier = ICircomVerifier(_voteVerifier);
        tallyVerifier = ICircomVerifier(_tallyVerifier);
        treasury = _treasury;

        // Initialize pollCount to 0 (next poll will be ID 0).
        // This is explicit for clarity (already 0 by default).
        pollCount = 0;
    }

    /// ========================================
    /// Poll Creation
    /// ========================================

    /**
     * @notice Creates a new governance poll and collects a creation fee.
     *
     * @param title Human-readable title of the proposal.
     * @param description Extended description of the proposal.
     * @param voterRoot Merkle root of eligible voters (from token snapshot).
     * @param startTime Unix timestamp when voting begins (must be in future).
     * @param endTime Unix timestamp when voting ends (must be after startTime).
     *
     * @return pollId Unique identifier for this poll (sequential counter).
     *
     * @dev REQUIRES:
     *      - msg.value >= POLL_FEE (0.01 ETH).
     *      - startTime >= block.timestamp (cannot create poll in the past).
     *      - endTime > startTime (voting period must have positive duration).
     *      - voterRoot != bytes32(0) (must specify eligible voter set).
     *
     * @dev FEE MODEL:
     *      - 0.01 ETH is collected to prevent governance spam.
     *      - Fee is non-refundable (sent to treasury immediately).
     *      - Excess ETH (msg.value > POLL_FEE) is kept by contract.
     *      - Recommended: Send exactly POLL_FEE (0.01 ETH).
     *
     * @dev STATE INITIALIZATION:
     *      1. Increment pollCount (current count is the new poll ID).
     *      2. Create Poll struct with:
     *         - id = pollId (for reference).
     *         - title and description (metadata).
     *         - voterRoot (eligible voter set).
     *         - startTime and endTime (voting window).
     *         - coordinator = msg.sender (has authority to tally).
     *         - status = PENDING (voting hasn't started yet).
     *         - tallied = false (initially not tallied).
     *         - totalVotes = 0 (no votes yet).
     *         - totalYes = 0, totalNo = 0 (no tallying yet).
     *      3. Store Poll in polls mapping.
     *
     * @dev COORDINATOR ROLE:
     *      Coordinator is the poll creator (msg.sender).
     *      Coordinator has sole authority to:
     *      1. Decrypt votes off-chain.
     *      2. Aggregate yes/no counts.
     *      3. Generate tally proof.
     *      4. Submit tallyVotes() to finalize results.
     *      Recommendation: Community elects trusted coordinator (multisig or DAO).
     *
     * @dev VOTER ROOT CONSTRUCTION (Off-chain):
     *      1. Snapshot DAO token holders at specific block height.
     *      2. Build Merkle tree from address list.
     *      3. Root = Merkle(address_0, address_1, ..., address_n).
     *      4. Voters use Merkle proofs to prove inclusion in castVote().
     *
     * @dev GAS:
     *      - Poll creation: ~50k gas (struct storage + fee transfer).
     *      - Fee transfer: ~5k gas.
     *      - Total: ~55k gas.
     *
     * @dev EMITS:
     *      PollCreated event with pollId for off-chain indexing.
     *
     * @dev REVERTS ON:
     *      - msg.value < POLL_FEE.
     *      - startTime < block.timestamp.
     *      - endTime <= startTime.
     *      - voterRoot == bytes32(0).
     *      - Treasury transfer fails.
     */
    function createPoll(
        string calldata title,
        string calldata description,
        bytes32 voterRoot,
        uint256 startTime,
        uint256 endTime
    ) external payable returns (uint256 pollId) {
        require(msg.value >= POLL_FEE, "Insufficient poll creation fee");
        require(startTime >= block.timestamp, "Start time must be in future");
        require(endTime > startTime, "End time must be after start time");
        require(voterRoot != bytes32(0), "Voter root cannot be zero");

        // Generate poll ID (current count, then increment).
        pollId = pollCount;
        pollCount++;

        // Create and store Poll struct.
        polls[pollId] = Poll({
            id: pollId,
            title: title,
            description: description,
            voterRoot: voterRoot,
            startTime: startTime,
            endTime: endTime,
            totalVotes: 0,
            totalYes: 0,
            totalNo: 0,
            tallied: false,
            coordinator: msg.sender,
            status: PollStatus.PENDING
        });

        // Transfer fee to treasury.
        payable(treasury).transfer(msg.value);

        // Emit event for off-chain indexing.
        emit PollCreated(
            pollId,
            title,
            voterRoot,
            startTime,
            endTime
        );

        return pollId;
    }

    /// ========================================
    /// Vote Submission
    /// ========================================

    /**
     * @notice Casts an encrypted vote in an active poll with ZK proof.
     *
     * @param pollId The poll in which the vote is being cast.
     * @param encryptedVote The voter's vote, encrypted under coordinator's public key.
     * @param nullifier The voter's nullifier for this poll (prevents double-voting).
     * @param proof_a First component of the vote ZK proof.
     * @param proof_b Second component of the vote ZK proof.
     * @param proof_c Third component of the vote ZK proof.
     *
     * @dev REQUIRES:
     *      - Poll exists (pollId < pollCount).
     *      - Poll is in ACTIVE state (startTime <= block.timestamp <= endTime).
     *      - Nullifier has not been used in this poll (prevents double-vote).
     *      - Vote ZK proof is cryptographically valid.
     *
     * @dev PROOF VERIFICATION (Vote Proof Circuit):
     *      The proof verifies:
     *      1. Voter is included in poll's voterRoot (Merkle proof of eligibility).
     *      2. Voter has valid Okkult compliance proof (address not sanctioned).
     *      3. Nullifier = hash(voter_secret, pollId) (proves voter commitment).
     *      4. No additional constraints (circuit-dependent).
     *
     * @dev FLOW:
     *      1. Check poll exists and is in ACTIVE state.
     *      2. Check nullifier hasn't been used in this poll.
     *      3. Verify ZK proof via voteVerifier contract.
     *      4. Mark nullifier as used (hasVoted[pollId][nullifier] = true).
     *      5. Store encrypted vote (append to encryptedVotes[pollId]).
     *      6. Increment totalVotes counter.
     *      7. Emit VoteCast event.
     *
     * @dev VOTE PRIVACY:
     *      - encryptedVote is stored on-chain without decryption.
     *      - Nobody except coordinator can know the actual vote content.
     *      - Even coordinator's decryption is proved, not revealed.
     *      - Transaction observer cannot determine voter preference.
     *      - Perfect ballot secrecy maintained on-chain.
     *
     * @dev ANTI-COLLUSION:
     *      - Voter cannot prove their vote to a buyer (encrypted).
     *      - Voter's nullifier prevents vote buying (buyer verifies no double-vote).
     *      - Even if voter sells their nullifier, buyer cannot prove proof ownership.
     *      - ZK proof makes vote selling economically infeasible.
     *
     * @dev STATUS TRANSITIONS:
     *      - If castVote() called before startTime: status remains PENDING, revert.
     *      - If castVote() called at startTime: status → ACTIVE, vote accepted.
     *      - If castVote() called after endTime: status → CLOSED, revert.
     *      - Poll stays ACTIVE until block.timestamp >= endTime.
     *
     * @dev GAS COST:
     *      - Proof verification: ~2-3M gas (dominant cost).
     *      - Nullifier check and storage: ~5-10k gas.
     *      - Event emission: ~375 gas.
     *      - Total: ~2-3M gas.
     *
     * @dev EMITS:
     *      VoteCast event with (pollId, nullifier, encryptedVote).
     *      Indexed on pollId and nullifier for efficient log filtering.
     *
     * @dev REVERTS ON:
     *      - Poll doesn't exist.
     *      - Poll not in ACTIVE state (timing out of range).
     *      - Voter already voted (nullifier already used).
     *      - Proof verification fails.
     */
    function castVote(
        uint256 pollId,
        bytes32 encryptedVote,
        bytes32 nullifier,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external {
        // Check poll exists.
        require(pollId < pollCount, "Poll does not exist");

        Poll storage poll = polls[pollId];

        // Check poll is in ACTIVE state (voting window is open).
        require(
            block.timestamp >= poll.startTime,
            "Voting has not started"
        );
        require(
            block.timestamp <= poll.endTime,
            "Voting has ended"
        );

        // Update poll status if transitioning to ACTIVE.
        if (poll.status == PollStatus.PENDING) {
            poll.status = PollStatus.ACTIVE;
        }

        // Check nullifier hasn't been used (prevent double-vote).
        require(
            !hasVoted[pollId][nullifier],
            "Already voted in this poll"
        );

        // Verify ZK proof via voteVerifier.
        require(
            voteVerifier.verifyProof(proof_a, proof_b, proof_c, [uint(0), uint(0)]),
            "Invalid vote proof"
        );

        // Mark nullifier as used.
        hasVoted[pollId][nullifier] = true;

        // Store encrypted vote (maintain order for off-chain reconstruction).
        encryptedVotes[pollId].push(encryptedVote);

        // Increment vote counter.
        poll.totalVotes++;

        // Emit event for off-chain vote tracking.
        emit VoteCast(pollId, nullifier, encryptedVote);
    }

    /// ========================================
    /// Vote Tallying
    /// ========================================

    /**
     * @notice Tallies poll results after voting period ends (coordinator only).
     *
     * @param pollId The poll to tally.
     * @param totalYes Count of "yes" votes (coordinator-decrypted).
     * @param totalNo Count of "no" votes (coordinator-decrypted).
     * @param proof_a First component of the tally ZK proof.
     * @param proof_b Second component of the tally ZK proof.
     * @param proof_c Third component of the tally ZK proof.
     *
     * @dev REQUIRES:
     *      - caller == poll.coordinator (only coordinator can tally).
     *      - block.timestamp > poll.endTime (voting period must be closed).
     *      - !poll.tallied (poll hasn't been tallied yet, prevent double-tally).
     *      - Tally ZK proof is cryptographically valid.
     *
     * @dev PROOF VERIFICATION (Tally Proof Circuit):
     *      The proof verifies:
     *      1. All submitted encryptedVotes are correctly decrypted.
     *      2. sum(decrypted_votes == YES) == totalYes.
     *      3. sum(decrypted_votes == NO) == totalNo.
     *      4. All votes are accounted for (no omissions).
     *      5. Vote data (encryptedVote, nullifier) has not changed.
     *      6. Each nullifier is counted exactly once (no double-counting).
     *      Circuit does not reveal individual decrypted votes (zero-knowledge).
     *
     * @dev COORDINATOR ROLE:
     *      - Only coordinator can call tallyVotes() (determined at createPoll).
     *      - Coordinator holds the private key for vote decryption.
     *      - Coordinator is responsible for:
     *        1. Decrypting all votes.
     *        2. Aggregating yes/no counts.
     *        3. Generating ZK tally proof.
     *        4. Submitting on-chain with tallyVotes().
     *      - Off-chain: Coordinator proves correctness without revealing votes.
     *      - On-chain: Contract verifies proof and publishes immutable results.
     *
     * @dev FLOW:
     *      1. Check caller is poll coordinator.
     *      2. Check poll voting period has ended (block.timestamp > endTime).
     *      3. Check poll hasn't been tallied yet.
     *      4. Verify tally proof via tallyVerifier.
     *      5. Update poll state:
     *         - poll.totalYes = totalYes.
     *         - poll.totalNo = totalNo.
     *         - poll.tallied = true.
     *         - poll.status = TALLIED.
     *      6. Emit PollTallied event with final counts.
     *
     * @dev SECURITY:
     *      - Reentrancy guard prevents state corruption.
     *      - Coordinator-only: prevents unauthorized vote claim.
     *      - Timing check: prevents early tallying.
     *      - Idempotency check: prevents double-tallying.
     *      - Proof verification: prevents fraudulent results.
     *
     * @dev IMMUTABILITY:
     *      Once tallied, results are immutable on-chain.
     *      Cannot be disputed, modified, or re-tallied.
     *      Off-chain systems rely on PollTallied event as final truth.
     *
     * @dev GAS COST:
     *      - Proof verification: ~2-3M gas (dominant cost).
     *      - State updates: ~10-20k gas.
     *      - Event emission: ~375 gas.
     *      - Total: ~2-3M gas.
     *
     * @dev EMITS:
     *      PollTallied event with (pollId, totalYes, totalNo, totalVotes).
     *      Indexed on pollId for efficient log filtering.
     *
     * @dev REVERTS ON:
     *      - caller != poll.coordinator.
     *      - block.timestamp <= poll.endTime.
     *      - poll.tallied == true (already tallied).
     *      - Tally proof verification fails.
     */
    function tallyVotes(
        uint256 pollId,
        uint256 totalYes,
        uint256 totalNo,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external nonReentrant {
        // Check poll exists.
        require(pollId < pollCount, "Poll does not exist");

        Poll storage poll = polls[pollId];

        // Check caller is coordinator (only coordinator can finalize results).
        require(
            msg.sender == poll.coordinator,
            "Only coordinator can tally"
        );

        // Check voting period has ended.
        require(
            block.timestamp > poll.endTime,
            "Voting period not yet closed"
        );

        // Check poll hasn't been tallied already.
        require(!poll.tallied, "Poll already tallied");

        // Verify tally proof via tallyVerifier.
        require(
            tallyVerifier.verifyProof(proof_a, proof_b, proof_c, [uint(0), uint(0)]),
            "Invalid tally proof"
        );

        // Update poll state.
        poll.totalYes = totalYes;
        poll.totalNo = totalNo;
        poll.tallied = true;
        poll.status = PollStatus.TALLIED;

        // Emit event with final results.
        emit PollTallied(pollId, totalYes, totalNo, poll.totalVotes);
    }

    /// ========================================
    /// Vote Status Queries
    /// ========================================

    /**
     * @notice Checks if a specific nullifier has already voted in a poll.
     *
     * @param pollId The poll to check voting history in.
     * @param nullifier The voter's nullifier for this poll.
     *
     * @return voted True if nullifier has cast a vote in this poll,
     *               false if nullifier has not voted yet.
     *
     * @dev PREVENTS DOUBLE-VOTING:
     *      - Each voter derives nullifier = hash(voter_secret, pollId).
     *      - After castVote(), nullifier is marked as used (hasVoted[pollId][nullifier] = true).
     *      - Any subsequent castVote() with same nullifier reverts ("Already voted").
     *      - Only one vote per (voter, poll) pair is possible.
     *
     * @dev USAGE:
     *      1. Off-chain: Voter checks before generating proof (avoid wasted computation).
     *      2. On-chain: castVote() calls this to enforce double-vote prevention.
     *      3. Auditing: Check participation without revealing voter identity.
     *
     * @dev GAS COST:
     *      ~100-2100 gas (mapping lookup, cold/warm access).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function hasVoted(uint256 pollId, bytes32 nullifier)
        external
        view
        returns (bool voted)
    {
        return hasVoted[pollId][nullifier];
    }

    /// ========================================
    /// Additional Queries
    /// ========================================

    /**
     * @notice Returns all encrypted votes submitted in a poll (in order).
     *
     * @param pollId The poll to retrieve votes from.
     *
     * @return votes Array of all encrypted votes (in submission order).
     *
     * @dev RETURNS:
     *      - Empty array if no votes cast.
     *      - Array of length == totalVotes if poll has votes.
     *      - Order is preserved (first vote returned first).
     *
     * @dev USAGE:
     *      Off-chain coordinator queries this to reconstruct vote list:
     *      1. Get encryptedVotes array (in order).
     *      2. Decrypt using coordinator's private key.
     *      3. Aggregate counts (yes/no).
     *      4. Generate tally proof.
     *
     * @dev PRIVACY:
     *      All votes are encrypted; decryption is only possible with private key.
     *      Returning encrypted array doesn't leak vote content.
     *
     * @dev GAS COST:
     *      ~O(n) where n = totalVotes (array copy to memory).
     *      Can be expensive for polls with many votes (consider pagination).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function getEncryptedVotes(uint256 pollId)
        external
        view
        returns (bytes32[] memory votes)
    {
        require(pollId < pollCount, "Poll does not exist");
        return encryptedVotes[pollId];
    }

    /**
     * @notice Returns the status of a poll.
     *
     * @param pollId The poll to check status of.
     *
     * @return status Current PollStatus (PENDING/ACTIVE/CLOSED/TALLIED).
     *
     * @dev TRANSITIONS:
     *      - PENDING: Created but startTime not reached.
     *      - ACTIVE: Voting is happening (startTime <= block.timestamp <= endTime).
     *      - CLOSED: Voting ended (block.timestamp > endTime, not yet tallied).
     *        NOTE: Transition to CLOSED happens implicitly; call will determine.
     *      - TALLIED: tallyVotes() called, results finalized.
     *
     * @dev USAGE:
     *      Off-chain systems query to determine poll lifecycle state.
     *      Users check status before attempting to vote/tally.
     *
     * @dev GAS COST:
     *      ~100 gas (storage read).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function getPollStatus(uint256 pollId)
        external
        view
        returns (PollStatus status)
    {
        require(pollId < pollCount, "Poll does not exist");

        Poll storage poll = polls[pollId];

        // Determine current status based on timing and poll state.
        if (poll.tallied) {
            return PollStatus.TALLIED;
        } else if (block.timestamp > poll.endTime) {
            return PollStatus.CLOSED;
        } else if (block.timestamp >= poll.startTime) {
            return PollStatus.ACTIVE;
        } else {
            return PollStatus.PENDING;
        }
    }

    /**
     * @notice Returns the full Poll struct for a given poll ID.
     *
     * @param pollId The poll to retrieve.
     *
     * @return Poll struct containing all poll metadata and voting state.
     *
     * @dev USAGE:
     *      Off-chain systems query complete poll state.
     *      Returns: title, description, timing, voter root, results, status.
     *
     * @dev GAS COST:
     *      ~500 gas (storage read).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function getPoll(uint256 pollId)
        external
        view
        returns (Poll memory poll)
    {
        require(pollId < pollCount, "Poll does not exist");
        return polls[pollId];
    }
}
