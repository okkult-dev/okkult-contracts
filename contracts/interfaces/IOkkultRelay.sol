// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IOkkultRelay
 * @author Okkult Protocol
 * @notice Standard interface for the Okkult decentralized transaction relay network.
 *
 * OkkultRelay enables private transaction submission and execution through a permissionless
 * network of relayers. Key features:
 * 1. Users submit encrypted transactions (content remains private on-chain).
 * 2. Relayers compete to execute transactions and collect fees.
 * 3. Fees paid in any ERC-20 token (not just ETH).
 * 4. Refund mechanism if no relayer executes within deadline.
 * 5. On-chain commitment tracking prevents transaction replay/forgery.
 *
 * Use cases:
 * - Private DEX swaps (hide trade intent from MEV searchers).
 * - Shielded pool interactions (private deposit/withdrawal).
 * - Private governance voting (hide vote intent).
 * - Anonymous donation submissions (hide donor and recipient).
 *
 * @dev TRANSACTION FLOW:
 *      1. User off-chain: Generate transaction data for target contract call.
 *      2. User off-chain: Encrypt transaction data under relayer network's public key.
 *      3. User on-chain: Call relay() with encryptedTx, commitment, fee, feeToken.
 *         - commitment = hash(encryptedTx, nonce) prevents forgery.
 *         - fee is transferred to contract escrow (not yet to relayer).
 *         - Contract emits TransactionQueued event.
 *      4. Relayer off-chain: Monitors TransactionQueued events.
 *      5. Relayer off-chain: Decrypts encryptedTx using network private key.
 *      6. Relayer on-chain: Executes transaction by calling target contract.
 *      7. Relayer on-chain: Calls markRelayed(commitment, txHash) to claim achievement.
 *         - Contract verifies commitment is valid.
 *         - Contract emits TransactionRelayed event.
 *      8. Relayer on-chain: Calls claimFee(txHash) to collect fee.
 *         - Contract transfers fee from escrow to relayer.
 *         - Fee must be claimed within deadline or refund opens.
 *      9. If deadline passes and no relayer claimed:
 *         - User calls refund(txHash) to recover fee from escrow.
 *
 * @dev COMMITMENT SEMANTICS:
 *      commitment = hash(encryptedTx || nonce) is deterministic per transaction.
 *      Once commitment is created, it uniquely identifies this transaction.
 *      Prevents malicious actors from:
 *      - Modifying the encryptedTx and claiming it's the same transaction.
 *      - Submitting same transaction twice (same commitment used twice).
 *      - Forging fake transactions (commitment doesn't match submitted data).
 */

interface IOkkultRelay {
    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when a user submits an encrypted transaction for relay.
     * @param commitment Unique identifier for this transaction (hash of encryptedTx + nonce).
     * @param fee Amount of feeToken the relayer will receive upon successful execution.
     * @param feeToken ERC-20 token address in which fee is paid (allows flexible tokenomics).
     * @param deadline Unix timestamp by which relayer must execute and claim fee.
     *                Currently unused if no relayer claims before deadline, user can refund.
     *
     * @dev Indexing on commitment allows off-chain systems to:
     *      1. Track transactions by their commitment hash.
     *      2. Detect duplicate submissions (same commitment reused).
     *      3. Build efficient pending transaction indices.
     *
     * @dev Fee Semantics:
     *      - User's ERC-20 tokens (feeToken) transferred to contract escrow immediately.
     *      - Relayer does not receive tokens until claimFee() called.
     *      - Fee is incentive for relayer; larger fee attracts relayers faster.
     *      - feeToken can be any token (USDC, USDT, DAI, KULT, etc.).
     *
     * @dev Deadline Purpose:
     *      - Relayer must execute and claim before deadline to earn fee.
     *      - After deadline, fee can be refunded to user.
     *      - Typical deadline: current block.timestamp + 60 minutes.
     *      - Prevents relayers from claiming fees for stale transactions.
     */
    event TransactionQueued(
        bytes32 indexed commitment,
        uint256 fee,
        address feeToken,
        uint256 deadline
    );

    /**
     * @notice Emitted when a relayer successfully executes and claims a relay transaction.
     * @param txHash Hash of the executed transaction (e.g., keccak256(transactionData)).
     * @param relayer Address of the relayer that executed the transaction.
     * @param fee Amount of feeToken earned by the relayer.
     *
     * @dev Indexing on txHash and relayer enables:
     *      1. Relayer reputation tracking (how many txs relayed, fees earned).
     *      2. Transaction execution verification (off-chain systems confirm txHash matches expected).
     *      3. Double-spend prevention (same txHash relayed only once).
     *
     * @dev Event Emission Timing:
     *      - Emitted by markRelayed(), which associates commitment with txHash.
     *      - Must be emitted BEFORE claimFee() is called (to record relayer ownership).
     *      - Ensures immutable on-chain record of relayer's achievement.
     *
     * @dev Fee Transfer:
     *      - Fee is NOT transferred when TransactionRelayed is emitted.
     *      - Transfer happens later in claimFee() when relayer claims.
     *      - Allows multiple claimants to dispute (first to claimFee() wins).
     */
    event TransactionRelayed(
        bytes32 indexed txHash,
        address indexed relayer,
        uint256 fee
    );

    /// ========================================
    /// Transaction Submission
    /// ========================================

    /**
     * @notice Submits an encrypted transaction for relay to the network.
     *
     * @param encryptedTx The encrypted transaction data (encrypted under relay network's public key).
     * @param commitment Unique identifier for this transaction (typically hash of encryptedTx + nonce).
     * @param fee Amount of feeToken the relayer will earn upon successful execution.
     * @param feeToken ERC-20 token address for fee payment (allows payment in any token).
     *
     * @return txHash Transaction identifier assigned by the relay system.
     *               Used later in markRelayed(), claimFee(), refund() calls.
     *
     * @dev REQUIRES:
     *      - User has approved contract to transfer fee amount of feeToken.
     *      - commitment has not been previously submitted (prevents duplicate relay).
     *      - fee > 0 (relayers won't relay with 0 incentive).
     *      - feeToken is a valid ERC-20 token (can be any token, USDC, DAI, etc.).
     *      - deadline > block.timestamp (deadlines must be in the future).
     *
     * @dev FLOW:
     *      1. User provides encryptedTx (encrypted off-chain so only relayers can decrypt).
     *      2. User provides commitment to prevent transaction tampering/forgery.
     *      3. Contract transfers fee amount of feeToken from user to contract escrow.
     *      4. Contract records commitment → fee/feeToken/deadline mapping.
     *      5. Contract emits TransactionQueued event.
     *      6. Returns txHash (internal identifier for this relay request).
     *
     * @dev COMMITMENT CHECK:
     *      Implementation should verify (off-chain or via additional proof):
     *      - commitment = hash(encryptedTx || nonce)
     *      - This ensures commitment matches the data being relayed.
     *      - Alternative: commitment can be arbitrary (user-provided), verified post-relay.
     *
     * @dev TRANSACTION PRIVACY:
     *      - encryptedTx is stored on-chain in event or calldata.
     *      - Only entities with relay network's private key can decrypt.
     *      - prevents external parties from seeing transaction intent.
     *      - Relayer(s) can decrypt and execute internally (without revealing content).
     *
     * @dev FEE ESCROW:
     *      - Fees are locked in contract until relayer claims or deadline expires.
     *      - Prevents user from withdrawing fee before relayer executes.
     *      - Ensures relayer payment is certain once markRelayed() is called.
     *
     * @dev DEADLINE SEMANTICS:
     *      Deadline is passed to the function (typically block.timestamp + 1 hour):
     *      - Relayer must execute before this deadline to claim fee.
     *      - After deadline, user can call refund() to recover fee.
     *      - Prevents relayers from claiming fees for very old transactions.
     *      - Typical deadline: current time + 60 minutes.
     */
    function relay(
        bytes calldata encryptedTx,
        bytes32 commitment,
        uint256 fee,
        address feeToken
    ) external returns (bytes32 txHash);

    /// ========================================
    /// Relay Execution and Fee Claims
    /// ========================================

    /**
     * @notice Marks a transaction as successfully relayed and claims the relayer's fee.
     *
     * @param commitment The commitment of the transaction being relayed (from relay() call).
     * @param txHash Hash of the executed transaction result (to prevent fee theft).
     *
     * @dev SECURITY MODEL:
     *      - This function is called by relayer after successful transaction execution.
     *      - tx txHash proves relayer actually executed the transaction (prevents theft).
     *      - Associates commitment → txHash, enabling later claimFee() call.
     *      - Emits TransactionRelayed event (immutable record of relayer's achievement).
     *
     * @dev REQUIRES:
     *      - commitment was previously submitted via relay().
     *      - commitment has not been marked as relayed (prevents double-relay).
     *      - block.timestamp <= deadline (relayer within execution window).
     *      - txHash must match the executed transaction (verified off-chain or post-hoc).
     *
     * @dev FLOW:
     *      1. Relayer decrypts encryptedTx from TransactionQueued event.
     *      2. Relayer constructs transaction and sends to target contract.
     *      3. Relayer observes transaction success (reads receipt/logs).
     *      4. Relayer calls markRelayed(commitment, txHash) to claim success.
     *         - txHash = keccak256(target || calldata || result) or similar.
     *      5. Contract updates mapping: commitment → relayed = true.
     *      6. Contract emits TransactionRelayed(txHash, relayer, fee).
     *
     * @dev RACE CONDITIONS:
     *      If multiple relayers execute same transaction:
     *      - First to call markRelayed() is recorded as "the" relayer.
     *      - Subsequent relayers calling markRelayed() with same commitment revert (already marked).
     *      - Fee is collected by the first relayer (in claimFee()).
     *      - Other relayers wasted gas on execution (incentive to coordinate or check beforehand).
     *
     * @dev OPTIONAL PROOF VERIFICATION:
     *      Advanced implementations may require proof (ZK): (txHash is valid execution result for encryptedTx)
     *      This prevents relayers from claiming arbitrary txHash values.
     *      For simplicity, basic implementation just stores mapping.
     */
    function markRelayed(
        bytes32 commitment,
        bytes32 txHash
    ) external;

    /**
     * @notice Allows the relayer to claim their fee after successfully relaying a transaction.
     *
     * @param txHash The transaction hash (from markRelayed() call).
     *
     * @dev REQUIRES:
     *      - Transaction has been marked as relayed (markRelayed() was called).
     *      - Fee has not been claimed yet (prevents double-claiming).
     *      - caller address matches the relayer address (only relayer can claim).
     *
     * @dev FLOW:
     *      1. Relayer calls claimFee(txHash) with their address (msg.sender = relayer).
     *      2. Contract verifies msg.sender == recorded relayer address.
     *      3. Contract transfers fee amount of feeToken to relayer.
     *      4. Contract marks fee as claimed (prevents re-entry).
     *      5. Success: Relayer receives their fee.
     *
     * @dev REVERTS IF:
     *      - txHash is not marked as relayed.
     *      - Fee already claimed for this txHash.
     *      - msg.sender is not the relayer.
     *      - ERC-20 transfer fails (feeToken not transferable).
     *
     * @dev FEE PAYMENT:
     *      - feeToken is transferred from contract escrow to relayer.
     *      - Amount transferred is exact fee specified in relay() call.
     *      - No additional fees or withholdings.
     *      - Relayer can then freely trade or hold received tokens.
     */
    function claimFee(bytes32 txHash) external;

    /// ========================================
    /// Refund and Recovery
    /// ========================================

    /**
     * @notice Refunds the user's fee if no relayer claims it before the deadline.
     *
     * @param txHash The transaction hash (from relay() return value).
     *
     * @dev REQUIRES:
     *      - transaction deadline has passed (block.timestamp >= deadline).
     *      - transaction has NOT been marked as relayed (markRelayed() not called).
     *      - transaction has NOT been refunded yet (prevents double-refunds).
     *      - caller is the user who originally submitted via relay() (msg.sender).
     *
     * @dev FLOW:
     *      1. User calls refund(txHash) after deadline expires.
     *      2. Contract verifies deadline has passed.
     *      3. Contract checks transaction is NOT marked as relayed.
     *      4. Contract verifies caller is the original user (msg.sender == submitter).
     *      5. Contract transfers fee from escrow back to user.
     *      6. Contract marks fee as refunded (prevents double-refunds).
     *      7. User receives full fee back.
     *
     * @dev REVERTS IF:
     *      - Deadline has not passed yet (must wait until deadline).
     *      - Transaction has been marked as relayed (relayer already earned it).
     *      - Fee already refunded (double-refund protection).
     *      - caller is not the original user.
     *      - ERC-20 transfer fails.
     *
     * @dev DEADLINE LOGIC:
     *      - Deadline = submission time + 1 hour (or user-specified).
     *      - If no relayer executes within deadline, user can recover fee.
     *      - Typical use: User waits past deadline and refunds after high-fee market calms down.
     *
     * @dev GAME THEORY:
     *      - User sets fee to attract relayers; if too low, no relayer picks it up.
     *      - After deadline, user can refund and resubmit with higher fee.
     *      - Relayers race to claim before deadline (incentive structure).
     *      - If transaction fails (revert), relayer doesn't call markRelayed() (loses fee).
     */
    function refund(bytes32 txHash) external;

    /// ========================================
    /// State Queries
    /// ========================================

    /**
     * @notice Checks whether a transaction identified by commitment has been successfully relayed.
     *
     * @param commitment The commitment of the transaction (from relay() call).
     *
     * @return relayed True if the transaction has been marked as relayed (markRelayed() called),
     *                 false if still pending or refunded.
     *
     * @dev USAGE:
     *      1. Off-chain: Relayers check before attempting relay (avoid race with other relayers).
     *      2. On-chain: Protocol integrations verify transaction was relayed before trusting result.
     *      3. Auditing: Users check relay status to determine if fee was earned or can be refunded.
     *
     * @dev RETURNS FALSE FOR:
     *      - Transaction not yet submitted (commitment never used).
     *      - Transaction submitted but not yet executed (pending relay).
     *      - Transaction deadline passed and refunded (no relayer executed).
     *      - Transaction marked as relayed but fee not yet claimed (returns true, fee will be claimed).
     *
     * @dev RETURNS TRUE ONLY FOR:
     *      - Transaction marked as relayed (markRelayed() successfully called).
     *      - Immutable until contract upgrade or reset (no state reversion).
     *
     * @dev GAS COST:
     *      - Simple mapping lookup: ~2100 gas (cold access) or ~100 gas (warm access).
     *      - Repeated queries in same transaction are cheaper (warm cache).
     */
    function isRelayed(bytes32 commitment)
        external
        view
        returns (bool relayed);
}
