// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ComplianceTree
 * @author Okkult Protocol
 * @notice On-chain registry for OFAC sanctions compliance Merkle roots.
 *
 * The ComplianceTree maintains a current and historical record of Merkle roots
 * representing addresses that have not been sanctioned by OFAC or other compliance authorities.
 *
 * Users prove their address is in this tree (not sanctioned) using zero-knowledge proofs.
 * The root is updated every 6 hours by an off-chain service ingesting OFAC/sanctions data.
 * Historical roots are stored to support proof staleness windows (allow proofs from recent roots).
 *
 * COMPLIANCE FLOW:
 * 1. Off-chain service monitors OFAC sanctions list (updated daily).
 * 2. Service computes new Merkle tree of non-sanctioned addresses.
 * 3. Service calls updateRoot() with new root every 6 hours.
 * 4. Users generate ZK proofs of inclusion in currentRoot (address not sanctioned).
 * 5. Verifier checks proof against currentRoot or recent historical root.
 * 6. If root is stale (>48 hours), new proof required before transaction proceeds.
 *
 * STALENESS PROTECTION:
 * - currentRoot is valid for 48 hours (MAX_ROOT_AGE).
 * - After 48 hours without update, all proofs fail isRootValid() check.
 * - Users must re-verify with fresh proof using current root.
 * - Prevents sanctioned-then-desanctioned addresses (or vice versa) from exploiting old proofs.
 *
 * DESIGN PRINCIPLES:
 * 1. Immutable updater address (set once at deployment).
 * 2. Centralized root source (off-chain service is single point of truth).
 * 3. Public history (anyone can audit root changes and staleness).
 * 4. No upgradability (simple, auditable, immutable).
 *
 * @dev HISTORICAL ROOTS:
 *      The contract maintains a circular buffer of up to 100 roots (ROOT_HISTORY_SIZE).
 *      Once 100 roots are stored, new updates overwrite the oldest root.
 *      This allows proofs to be verified against roots from the past ~25 days (100 roots * 6 hours each).
 *      Older roots are permanently discarded (off-chain storage recommended for archival).
 *
 * @dev UPDATER RESPONSIBILITY:
 *      - Must update root every 6 hours (or compliance becomes stale).
 *      - Must monitor OFAC/sanctions data for new sanctions.
 *      - If update fails for >48 hours, all transactions are blocked (fail-safe).
 *      - Recommended: Decentralized updater network or governance control.
 *      - Current: Single updater for simplicity (later: multi-sig or DAO).
 */
contract ComplianceTree {
    /// ========================================
    /// Constants
    /// ========================================

    /// @notice Maximum age for a root to be considered valid (48 hours).
    /// @dev After this period, proofs using this root are no longer accepted.
    /// @dev Enforces regular proof re-submission and guards against stale sanctioned-list data.
    /// @dev Value: 48 * 3600 = 172,800 seconds.
    uint256 public constant MAX_ROOT_AGE = 48 hours;

    /// @notice Maximum number of historical roots to maintain (circular buffer).
    /// @dev Once this limit is reached, oldest root is overwritten by new updates.
    /// @dev 100 roots * 6-hour updates = ~25 days of history retention.
    /// @dev Supports proof verification against roots from past ~25 days.
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice The current Merkle root of non-sanctioned addresses.
    /// @dev Used for proving inclusion (address not sanctioned) in ZK proofs.
    /// @dev Updated approximately every 6 hours by the off-chain updater service.
    /// @dev Must be non-zero; zero root is rejected as invalid.
    bytes32 public currentRoot;

    /// @notice Circular buffer of historical Merkle roots.
    /// @dev Stores up to ROOT_HISTORY_SIZE (100) past roots.
    /// @dev Enables proof verification against recent historical roots (staleness tolerance).
    /// @dev When full (length == 100), next update overwrites index 0, then 1, etc.
    /// @dev Off-chain indexers can track full history by monitoring RootUpdated events.
    bytes32[] public rootHistory;

    /// @notice Address authorized to update the compliance root.
    /// @dev Only this address can call updateRoot().
    /// @dev Set once at deployment; immutable thereafter (no way to reassign).
    /// @dev Typically: off-chain service address or multi-sig wallet (future: DAO).
    address public updater;

    /// @notice Timestamp of the last successful root update.
    /// @dev Used to determine if currentRoot is stale (> MAX_ROOT_AGE).
    /// @dev Updated every time updateRoot() is called.
    /// @dev Clients check isRootValid() before trusting currentRoot.
    uint256 public lastUpdated;

    /// ========================================
    /// Private State (For Circular Buffer Management)
    /// ========================================

    /// @notice Index for circular buffer insertion (next position to write).
    /// @dev Tracks position in rootHistory array for circular overwriting.
    /// @dev Increments with each update; wraps around at ROOT_HISTORY_SIZE.
    /// @dev Private to reduce clutter; history length visible via getRootHistoryLength().
    uint256 private nextInsertIndex;

    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when the compliance Merkle root is updated.
     * @param newRoot The newly updated Merkle root (non-sanctioned addresses).
     * @param oldRoot The previous Merkle root being replaced.
     * @param timestamp Block timestamp at which the update occurred.
     *
     * @dev Indexed on both newRoot and oldRoot to enable filtering:
     *      - Track specific root values across time.
     *      - Detect when a particular root becomes historical.
     *      - Monitor updater activity for compliance auditing.
     *
     * @dev Off-chain systems listen to this event to:
     *      1. Refresh their Merkle root in caches (critical for proof generation).
     *      2. Invalidate proofs that used oldRoot (if staleness rules enforce it).
     *      3. Update historical root tracking (for audit and archival).
     *      4. Alert users that new proofs are required (if they want to maintain freshness).
     *
     * @dev Event history on-chain forever (immutable audit trail).
     *      Allows historical verification: "Was this root ever current?" and "When?".
     */
    event RootUpdated(
        bytes32 indexed newRoot,
        bytes32 indexed oldRoot,
        uint256 timestamp
    );

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes the ComplianceTree with an initial root and designated updater.
     *
     * @param _initialRoot The initial Merkle root of non-sanctioned addresses.
     * @param _updater The address authorized to update the compliance root.
     *
     * @dev REQUIREMENTS:
     *      - _initialRoot must be non-zero (zero root is invalid by design).
     *      - _updater must be a valid, non-zero address.
     *      - Typically deployed fresh (currentRoot starts at _initialRoot).
     *
     * @dev INITIALIZATION:
     *      1. Set currentRoot = _initialRoot.
     *      2. Set updater = _updater.
     *      3. Set lastUpdated = block.timestamp (current block).
     *      4. Initialize rootHistory array with _initialRoot (first element).
     *      5. Initialize nextInsertIndex = 0 (circular buffer starts empty).
     *
     * @dev DEPLOYMENT NOTES:
     *      - _initialRoot should be computed from first OFAC/sanctions snapshot.
     *      - _updater can be single address (simple) or multi-sig (recommended).
     *      - Once deployed, updater cannot be changed (immutable by design).
     *      - If updater needs rotation, deploy new ComplianceTree and migrate.
     *
     * @dev GAS:
     *      Constructor stores state and initializes rootHistory: ~40k gas.
     */
    constructor(bytes32 _initialRoot, address _updater) {
        require(_initialRoot != bytes32(0), "Initial root cannot be zero");
        require(_updater != address(0), "Updater cannot be zero address");

        currentRoot = _initialRoot;
        updater = _updater;
        lastUpdated = block.timestamp;

        // Initialize root history with the initial root.
        rootHistory.push(_initialRoot);
    }

    /// ========================================
    /// Root Management
    /// ========================================

    /**
     * @notice Updates the compliance Merkle root (called by off-chain updater service).
     *
     * @param newRoot The newly computed Merkle root of non-sanctioned addresses.
     *
     * @dev REQUIRES:
     *      - msg.sender must be the authorized updater (access control).
     *      - newRoot must be non-zero (zero root is invalid marker).
     *      - No other constraints (new root can be same as old root if no sanctions changed).
     *
     * @dev FLOW:
     *      1. Check caller is updater (else revert).
     *      2. Check newRoot is non-zero (else revert).
     *      3. Store old root for event emission.
     *      4. Update currentRoot = newRoot.
     *      5. Update lastUpdated = block.timestamp.
     *      6. Add newRoot to rootHistory (circular buffer):
     *         - If rootHistory.length < ROOT_HISTORY_SIZE (100), append.
     *         - If rootHistory.length == 100, overwrite at nextInsertIndex and increment.
     *      7. Emit RootUpdated event with both old and new roots.
     *
     * @dev CIRCULAR BUFFER LOGIC:
     *      - rootHistory is initialized with [_initialRoot].
     *      - First update: append to index 1.
     *      - When length reaches 100, begin overwriting from index 0.
     *      - nextInsertIndex tracks where to write next (wraps: 0..99..0..99..).
     *      - No explicit resizing; old roots naturally overwritten.
     *
     * @dev STALENESS MODEL:
     *      - lastUpdated is updated to current block.timestamp.
     *      - Clock restarts; isRootValid() again returns true.
     *      - Typical cadence: Every 6 hours (36k blocks on Ethereum mainnet).
     *      - If update fails for 48 hours, all transactions requiring fresh roots fail.
     *
     * @dev USAGE:
     *      1. Off-chain service monitors OFAC/sanctions list.
     *      2. Service computes new Merkle tree every 6 hours.
     *      3. Service calls updateRoot() with new root.
     *      4. Users can now generate new proofs with the updated root.
     *      5. Old proofs using previous root are still valid (within staleness window).
     *
     * @dev GAS COST:
     *      - State updates: ~5k gas (write currentRoot, lastUpdated).
     *      - Array append (if < 100): ~20k gas (cold, ~5k warm).
     *      - Array overwrite (if == 100): ~5k gas (warm write).
     *      - Event emission: ~375 gas.
     *      - Total: ~5-25k gas depending on history size.
     *
     * @dev REVERTS ON:
     *      - msg.sender != updater ("Only updater").
     *      - newRoot == bytes32(0) ("Invalid root").
     */
    function updateRoot(bytes32 newRoot) external {
        require(msg.sender == updater, "Only updater");
        require(newRoot != bytes32(0), "Invalid root");

        bytes32 oldRoot = currentRoot;

        // Update state.
        currentRoot = newRoot;
        lastUpdated = block.timestamp;

        // Add to root history (circular buffer).
        if (rootHistory.length < ROOT_HISTORY_SIZE) {
            // Buffer not full yet, append new root.
            rootHistory.push(newRoot);
        } else {
            // Buffer full, overwrite at nextInsertIndex and wrap around.
            rootHistory[nextInsertIndex] = newRoot;
            nextInsertIndex = (nextInsertIndex + 1) % ROOT_HISTORY_SIZE;
        }

        // Emit event with old and new roots for auditing.
        emit RootUpdated(newRoot, oldRoot, block.timestamp);
    }

    /// ========================================
    /// Root Validity Queries
    /// ========================================

    /**
     * @notice Checks if the current root is fresh (not stale due to lack of updates).
     *
     * @return valid True if currentRoot has been updated within MAX_ROOT_AGE (48 hours),
     *               false if root is stale (no update for >48 hours).
     *
     * @dev STALENESS THRESHOLD:
     *      - If block.timestamp - lastUpdated <= MAX_ROOT_AGE, root is valid.
     *      - If block.timestamp - lastUpdated > MAX_ROOT_AGE, root is stale.
     *      - MAX_ROOT_AGE = 48 hours = 172,800 seconds.
     *
     * @dev USAGE:
     *      1. Verifier checks isRootValid() before accepting new proofs.
     *      2. If false, users must generate fresh proof with newer historical root (if available).
     *      3. Fail-safe: If root stale, all transactions requiring compliance fail.
     *      4. Off-chain indexers monitor this metric for alerts.
     *
     * @dev STALENESS IMPLICATIONS:
     *      - If off-chain updater stops working for >48 hours, protocol stops accepting proofs.
     *      - Forces regular root updates to keep protocol operational.
     *      - Prevents exploitation of outdated sanctions data (drift).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     *      Gas cost: ~100 gas (simple arithmetic).
     *
     * @dev EDGE CASES:
     *      - First update: lastUpdated = block.timestamp, isRootValid() = true.
     *      - Exactly at deadline: isRootValid() returns true (uses <=).
     *      - One second past deadline: isRootValid() returns false.
     */
    function isRootValid()
        external
        view
        returns (bool valid)
    {
        return block.timestamp - lastUpdated <= MAX_ROOT_AGE;
    }

    /// ========================================
    /// Root History Queries
    /// ========================================

    /**
     * @notice Checks if a given root exists in the historical root record.
     *
     * @param root The Merkle root to check for historical presence.
     *
     * @return exists True if root has ever been set as currentRoot (is in rootHistory),
     *                false if root was never the current root.
     *
     * @dev ITERATION:
     *      Linear search through rootHistory array.
     *      Compares each element against the target root.
     *      Returns true on first match; false if no match found.
     *
     * @dev USAGE:
     *      1. Verifiers check if a proof's root is valid (within recent history).
     *      2. Off-chain systems verify historical root validity for archival proofs.
     *      3. Auditors trace root lineage (confirm specific root was ever current).
     *
     * @dev STALENESS TOLERANCE:
     *      This function returns true for ANY historical root (even very old ones).
     *      Staleness enforcement happens separately via isRootValid().
     *      Example:
     *      - isHistoricalRoot(oldRoot) = true (root was current, now old).
     *      - isRootValid() = false (current root is stale, >48 hours).
     *      - Verifier can still accept proofs from oldRoot if within acceptable staleness.
     *
     * @dev BUFFER WRAPPING:
     *      Once ROOT_HISTORY_SIZE (100) updates have occurred:
     *      - Oldest root is overwritten (permanently lost on-chain).
     *      - Older proofs using very ancient roots will fail isHistoricalRoot() check.
     *      - Off-chain archival recommended for long-term proof verification.
     *
     * @dev GAS COST:
     *      - Worst case: O(n) = 100 comparisons = ~1200 gas.
     *      - Best case (early match): ~400 gas.
     *      - Average case: ~700 gas.
     *      - Expensive query, not suitable for tight loops or frequent calls.
     *      - Recommended: Off-chain verification using events (more efficient).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function isHistoricalRoot(bytes32 root)
        external
        view
        returns (bool exists)
    {
        for (uint256 i = 0; i < rootHistory.length; i++) {
            if (rootHistory[i] == root) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Returns the number of roots currently stored in the history buffer.
     *
     * @return length The current length of rootHistory array.
     *
     * @dev RETURN VALUES:
     *      - Immediately after deployment: length = 1 (initial root only).
     *      - After first update: length = 2.
     *      - After 99 updates: length = 100 (buffer full).
     *      - After 100+ updates: length = 100 (stays at max, circular overwrite).
     *
     * @dev USAGE:
     *      1. Clients determine if history is full (length == ROOT_HISTORY_SIZE).
     *      2. Off-chain systems estimate how far back proofs can be verified.
     *      - Example: length = 100, updates every 6 hours → 25 days of history.
     *      3. Auditors verify history is being maintained properly.
     *
     * @dev GAS COST:
     *      ~300 gas (simple array length read).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function getRootHistoryLength()
        external
        view
        returns (uint256 length)
    {
        return rootHistory.length;
    }
}
