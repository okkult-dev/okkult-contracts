// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UTXOTree
 * @author Okkult Protocol
 * @notice Incremental append-only Merkle tree for storing shielded UTXO commitments.
 *
 * UTXOTree enables efficient UTXO tracking for OkkultShield:
 * 1. Each shielded deposit creates a commitment (UTXO) added to the tree.
 * 2. Users prove their UTXO is in the tree using Merkle proofs (off-chain).
 * 3. Tree is append-only: leaves can only be added, never removed or modified.
 * 4. Incremental computation: each insert operation updates only O(log n) tree nodes.
 *
 * TREE STRUCTURE:
 * - Tree depth: 20 levels (0-19).
 * - Maximum leaves: 2^20 = 1,048,576 (supports ~1M UTXOs).
 * - Leaf hash: Each leaf is a keccak256 hash of a commitment.
 * - Parent hash: keccak256(left_child || right_child).
 * - Empty subtrees: Represented by zero hashes (keccak256 chain).
 *
 * ZERO HASHES:
 * - zeros[0] = bytes32(0).
 * - zeros[i] = keccak256(zeros[i-1] || zeros[i-1]) for i = 1..20.
 * - zeros[20] = root of completely empty tree.
 * - Used to represent uninitialized subtrees (compression, saves storage).
 *
 * INCREMENTAL INSERTION:
 * When a new commitment is inserted:
 * 1. Compute leaf index from leafCount.
 * 2. Walk up the tree, hashing with siblings.
 * 3. For uninitialized levels, use zeros[level] as right sibling.
 * 4. For initialized levels, use filledSubtrees[level] (rightmost node).
 * 5. Update filledSubtrees[level] as we walk up.
 * 6. Compute new root; store in roots array (circular buffer).
 * 7. Emit LeafInserted event.
 *
 * PROOF GENERATION (Off-chain):
 * To prove a commitment is in the tree:
 * 1. Get the leafIndex from LeafInserted event.
 * 2. Reconstruct the path from leaf to root.
 * 3. For each level, determine if we're on left or right.
 * 4. Collect sibling hashes (from tree structure).
 * 5. Verify: hash(left, right) matches the parent, etc.
 * 6. Final hash must match currentRoot or historical root.
 *
 * ROOT HISTORY:
 * - Stores up to 100 historical roots (circular buffer).
 * - Allows proofs to be verified against recent roots (~72 hours of deposits).
 * - Off-chain systems can generate proofs for "stale" roots (slight staleness tolerance).
 * - Beyond ~100 updates, oldest root is overwritten (archival via events recommended).
 *
 * DESIGN NOTES:
 * - Append-only: No update, deletion, or modification of existing leaves.
 * - Efficient: O(log n) time per insert, O(log n) space for filledSubtrees.
 * - Privacy-friendly: Tree structure is public, commitment preimages are private.
 * - Production: Replace keccak256 with Poseidon hash (SNARK-friendly, cheaper in circuits).
 *
 * @dev SECURITY:
 *      - Tree supports max 2^20 leaves (limits pre-computation attacks).
 *      - No tree rebalancing (incremental only, prevents subtle bugs).
 *      - Historical roots allow time-window for proof verification.
 *      - keccak256 is collision-resistant (no false proofs via preimage).
 *
 * @dev GAS OPTIMIZATION (CIRCUIT COMPATIBILITY):
 *      In production, keccak256 should be replaced with Poseidon precompile
 *      for circuits that use Groth16/PlonK (keccak256 is expensive in circuits).
 *      For now, using keccak256 for simplicity and Ethereum compatibility.
 */
contract UTXOTree {
    /// ========================================
    /// Constants
    /// ========================================

    /// @notice Depth of the Merkle tree (number of levels).
    /// @dev Maximum tree depth is 20 (supports 2^20 = 1,048,576 leaves).
    /// @dev This is sufficient for ~1M UTXOs, enough for multi-billion-dollar protocol.
    uint256 public constant TREE_DEPTH = 20;

    /// @notice Maximum number of leaves the tree can hold.
    /// @dev Equals 2^TREE_DEPTH = 2^20 = 1,048,576.
    /// @dev Once this limit is reached, no more UTXOs can be added (revert on insert).
    uint256 public constant MAX_LEAVES = 2 ** 20;

    /// @notice Maximum number of historical roots to maintain (circular buffer).
    /// @dev Once this limit is reached, oldest roots are overwritten by new ones.
    /// @dev 100 roots supports ~72 hours of history (assuming 1 insert per minute).
    /// @dev Allows proofs to be verified against recent historical roots.
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    /// ========================================
    /// State Variables
    /// ========================================

    /// @notice Number of leaves currently in the tree.
    /// @dev Ranges from 0 to MAX_LEAVES.
    /// @dev Also serves as the next leaf index for new insertions.
    /// @dev Incremented with each insert() call.
    uint256 public leafCount;

    /// @notice Current Merkle root of the tree.
    /// @dev Updated after each insert() call.
    /// @dev Used by proofs to verify leaf inclusion.
    /// @dev Initially equals zeros[TREE_DEPTH] (empty tree root).
    bytes32 public currentRoot;

    /// @notice Array of historical Merkle roots (circular buffer).
    /// @dev Stores up to ROOT_HISTORY_SIZE (100) recent roots.
    /// @dev Oldest root is overwritten when new roots exceed capacity.
    /// @dev Allows time-window for proof verification against recent roots.
    bytes32[] public roots;

    /// @notice Filled subtrees at each level (rightmost nodes, one per level).
    /// @dev filledSubtrees[i] = rightmost node at level i (non-zero).
    /// @dev Updated during insert() to track the rightmost branch of the tree.
    /// @dev Used to compute parent hashes when inserting new leaves.
    /// @dev Length: TREE_DEPTH = 20.
    bytes32[20] public filledSubtrees;

    /// @notice Zero hashes at each level of the tree (empty subtree roots).
    /// @dev zeros[0] = bytes32(0).
    /// @dev zeros[i] = keccak256(zeros[i-1] || zeros[i-1]).
    /// @dev zeros[TREE_DEPTH] = root of completely empty tree.
    /// @dev Used to hash with missing siblings during insertion.
    /// @dev Length: TREE_DEPTH + 1 = 21.
    bytes32[21] public zeros;

    /// @notice Index tracker for circular buffer insertion (roots array).
    /// @dev Tracks position in roots array for circular overwriting.
    /// @dev Increments with each insert; wraps around at ROOT_HISTORY_SIZE.
    /// @dev Private to reduce state size; history length visible via getRootsCount().
    uint256 private nextRootInsertIndex;

    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when a new UTXO commitment is inserted into the tree.
     * @param commitment The commitment hash being inserted (new UTXO).
     * @param leafIndex The index of this leaf in the tree (0-based).
     * @param newRoot The new Merkle root after this insertion.
     *
     * @dev Indexed on commitment and leafIndex for efficient filtering:
     *      - Track specific UTXO insertions by commitment value.
     *      - Filter insertions by leaf index range.
     *      - Off-chain systems listen to reconstruct tree and generate proofs.
     *
     * @dev CRITICAL FOR OFF-CHAIN PROOF GENERATION:
     *      Users must listen to LeafInserted events to:
     *      1. Determine their UTXO's leafIndex.
     *      2. Reconstruct tree state from genesis.
     *      3. Generate Merkle proofs for UTXO inclusion.
     *      4. Verify against currentRoot before proof submission.
     *
     * @dev EVENT ARCHIVE:
     *      Full event history is immutable on-chain forever.
     *      Off-chain indexers can replay events to reconstruct entire tree history.
     *      Enables long-term proof verification even after roots are overwritten.
     *
     * @dev newRoot can be queried to verify this is the current state tree.
     */
    event LeafInserted(
        bytes32 indexed commitment,
        uint256 indexed leafIndex,
        bytes32 newRoot
    );

    /// ========================================
    /// Constructor
    /// ========================================

    /**
     * @notice Initializes the UTXOTree with zero hashes and empty state.
     *
     * @dev INITIALIZATION:
     *      1. Compute zero hash chain: zeros[i] = keccak256(zeros[i-1] || zeros[i-1]).
     *      2. Set currentRoot = zeros[TREE_DEPTH] (empty tree root).
     *      3. Push currentRoot to roots array (first entry).
     *      4. Initialize filledSubtrees array (all zeros by default).
     *      5. Initialize leafCount = 0.
     *
     * @dev GAS COST:
     *      - Computing 21 zero hashes: ~21 * 400 gas = ~8.4k gas.
     *      - Array initialization and push: ~10k gas.
     *      - Total: ~18k gas.
     *
     * @dev IMMUTABILITY:
     *      Zero hashes are computed once and stored. They never change.
     *      This allows efficient circuit design (zeros can be hardcoded).
     */
    constructor() {
        // Initialize zero hash chain.
        zeros[0] = bytes32(0);
        for (uint256 i = 1; i <= TREE_DEPTH; i++) {
            zeros[i] = keccak256(
                abi.encodePacked(zeros[i - 1], zeros[i - 1])
            );
        }

        // Set initial root to empty tree root.
        currentRoot = zeros[TREE_DEPTH];

        // Initialize roots array with empty tree root.
        roots.push(currentRoot);

        // filledSubtrees is initialized to all zeros (default state).
        // leafCount is initialized to 0 (default state).
    }

    /// ========================================
    /// Merkle Tree Insertion
    /// ========================================

    /**
     * @notice Inserts a new UTXO commitment into the tree and updates the root.
     *
     * @param commitment The commitment hash representing the new UTXO.
     *
     * @return leafIndex The index of the inserted leaf (0-based).
     *
     * @dev REQUIRES:
     *      - leafCount < MAX_LEAVES (tree not full).
     *
     * @dev ALGORITHM (Incremental Merkle Tree):
     *      1. Check tree has capacity (leafCount < MAX_LEAVES).
     *      2. Record leafIndex = leafCount.
     *      3. Increment leafCount (reserve this index).
     *      4. Start with leaf = commitment (the new leaf hash).
     *      5. Walk up tree from level 0 to TREE_DEPTH - 1:
     *         a. Check if we're on left or right path:
     *            - If (leafIndex >> level) & 1 == 0: left path (bit is 0).
     *            - If (leafIndex >> level) & 1 == 1: right path (bit is 1).
     *         b. If left path:
     *            - Right sibling = zeros[level] (empty right subtree).
     *            - parent = hash(leaf, zeros[level]).
     *            - Store: filledSubtrees[level] = parent (for future inserts).
     *         c. If right path:
     *            - Left sibling = filledSubtrees[level] (previously filled right-most node).
     *            - parent = hash(filledSubtrees[level], leaf).
     *            - Don't update filledSubtrees[level] (it's already set).
     *         d. Advance: leaf = parent (move up to next level).
     *      6. After loop: currentRoot = parent from last level.
     *      7. Add currentRoot to roots array (circular buffer):
     *         - If roots.length < ROOT_HISTORY_SIZE, append.
     *         - Otherwise, overwrite at nextRootInsertIndex and wrap.
     *      8. Emit LeafInserted event.
     *      9. Return leafIndex.
     *
     * @dev BIT POSITION LOGIC:
     *      leafIndex's binary representation determines path in tree:
     *      - Bit i tells us if we're on left (0) or right (1) at level i.
     *      - (leafIndex >> i) & 1 extracts bit i.
     *      - Example: leafIndex = 5 = 0b101.
     *        - Level 0: bit 0 = 1 (right path) → use filledSubtrees[0] as left sibling.
     *        - Level 1: bit 1 = 0 (left path) → use zeros[1] as right sibling.
     *        - Level 2: bit 2 = 1 (right path) → use filledSubtrees[2] as left sibling.
     *
     * @dev FILLEDSUBTREES UPDATES:
     *      Only updated when on left path (bit is 0).
     *      When on right path, we're hashing within an already-filled subtree (no update needed).
     *      Result: filledSubtrees tracks the rightmost path through the tree.
     *
     * @dev ROOT HISTORY (CIRCULAR BUFFER):
     *      After ROOT_HISTORY_SIZE (100) inserts:
     *      - roots[0] is overwritten by the 101st insert.
     *      - roots[1] is overwritten by the 102nd insert.
     *      - Pattern continues (nextRootInsertIndex wraps around).
     *      - Allows time-window for proof verification.
     *
     * @dev EMIT EVENT:
     *      LeafInserted event includes:
     *      - commitment: new UTXO being added.
     *      - leafIndex: where it was added (for proof generation).
     *      - newRoot: updated tree root (for users to verify state).
     *
     * @dev GAS COST:
     *      - Tree walk: 20 levels * (hash + storage update) = ~20k-60k gas.
     *      - Root history management: ~5-20k gas.
     *      - Event emission: ~375 gas.
     *      - Total: ~25-80k gas (depends on history buffer state).
     *
     * @dev REVERTS IF:
     *      - leafCount >= MAX_LEAVES ("Tree is full").
     *
     * @dev PRIVACY NOTE:
     *      commitment preimage is NOT stored (privacy-preserving).
     *      Only the hash is stored on-chain.
     *      Prover reveals nothing except Merkle proof of inclusion.
     */
    function insert(bytes32 commitment)
        internal
        returns (uint256 leafIndex)
    {
        require(leafCount < MAX_LEAVES, "Tree is full");

        leafIndex = leafCount;
        leafCount++;

        bytes32 leaf = commitment;

        // Walk up tree from leaf to root.
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            // Determine if we're on left (bit = 0) or right (bit = 1) path.
            if ((leafIndex >> level) & 1 == 0) {
                // Left path: right sibling is zero, update filledSubtrees.
                leaf = hashLeftRight(leaf, zeros[level]);
                filledSubtrees[level] = leaf;
            } else {
                // Right path: left sibling is filledSubtrees.
                leaf = hashLeftRight(filledSubtrees[level], leaf);
                // Don't update filledSubtrees (it's already correct).
            }
        }

        // leaf is now the new root.
        currentRoot = leaf;

        // Add to root history (circular buffer).
        if (roots.length < ROOT_HISTORY_SIZE) {
            roots.push(currentRoot);
        } else {
            roots[nextRootInsertIndex] = currentRoot;
            nextRootInsertIndex = (nextRootInsertIndex + 1) % ROOT_HISTORY_SIZE;
        }

        emit LeafInserted(commitment, leafIndex, currentRoot);

        return leafIndex;
    }

    /// ========================================
    /// Root Verification
    /// ========================================

    /**
     * @notice Checks if a given root was ever the current root of the tree.
     *
     * @param root The Merkle root to check for historical presence.
     *
     * @return known True if root has been a currentRoot at some point,
     *               false if root was never the current root.
     *
     * @dev USAGE:
     *      1. Verifiers check if a proof's root is valid (was ever the current state).
     *      2. Off-chain systems verify historical root validity.
     *      3. Auditors trace root lineage and insertion state.
     *
     * @dev STALENESS TOLERANCE:
     *      This function returns true for ANY historical root (even very old ones).
     *      The verifier circuit can determine staleness separately (e.g., leaf age).
     *      Example:
     *      - isKnownRoot(oldRoot) = true (root was valid, now historic).
     *      - Users can prove leaf against oldRoot, but may require freshness checks.
     *
     * @dev BUFFER WRAPPING:
     *      Once ROOT_HISTORY_SIZE (100) inserts have occurred:
     *      - Oldest root is overwritten (permanently lost from on-chain storage).
     *      - Older proofs using very ancient roots will fail this check.
     *      - Off-chain archival (via events) recommended for long-term proof verification.
     *
     * @dev GAS COST:
     *      - Worst case: O(n) = 100 comparisons = ~1200 gas.
     *      - Best case (early match): ~400 gas.
     *      - Average case: ~700 gas.
     *      - Expensive query, not suitable for tight loops.
     *      - Recommended: Off-chain verification via RPC queries (more efficient).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function isKnownRoot(bytes32 root)
        public
        view
        returns (bool known)
    {
        for (uint256 i = 0; i < roots.length; i++) {
            if (roots[i] == root) {
                return true;
            }
        }
        return false;
    }

    /// ========================================
    /// Hashing
    /// ========================================

    /**
     * @notice Hashes two child nodes to compute their parent hash.
     *
     * @param left Left child hash.
     * @param right Right child hash.
     *
     * @return parent Hash of the parent node (left || right).
     *
     * @dev CONSTRUCTION:
     *      parent = keccak256(abi.encodePacked(left, right)).
     *      Uses Solidity's standard keccak256 (Keccak-256, not SHA-256).
     *
     * @dev CIRCUIT NOTE:
     *      In production, this should use Poseidon hash for SNARK efficiency:
     *      - Poseidon is SNARK-friendly (polynomial arithmetic, not bitwise).
     *      - Cheaper in circuits: ~600 constraints vs 40k for Keccak-256.
     *      - However, Poseidon has no Ethereum precompile (yet).
     *      - For now, Keccak-256 is used for Ethereum compatibility.
     *      - TODO: Migrate to Poseidon precompile once available on Ethereum.
     *
     * @dev ASSOCIATIVITY:
     *      Hash is deterministic: same inputs always produce same output.
     *      Enables off-chain tree reconstruction and proof verification.
     *      Users can verify: hash(A, hash(B, C)) = parent over (B, C).
     *
     * @dev GAS COST:
     *      - keccak256 with packed input: ~300-400 gas.
     *      - Executed during each insert level step.
     *      - 20 levels * ~350 gas = ~7k gas per insert (hash component).
     *
     * @dev SECURITY:
     *      keccak256 is collision-resistant (no two different inputs hash to same output).
     *      Prevents false proofs via preimage attacks.
     *      Approved for cryptographic use (used in Ethereum protocol itself).
     */
    function hashLeftRight(bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32 parent)
    {
        return keccak256(abi.encodePacked(left, right));
    }

    /// ========================================
    /// History Queries
    /// ========================================

    /**
     * @notice Returns the number of roots currently stored in the history.
     *
     * @return count Length of the roots array.
     *
     * @dev RETURN VALUES:
     *      - After deployment: count = 1 (empty tree root).
     *      - After 1st insert: count = 2.
     *      - After 99 inserts: count = 100 (buffer full).
     *      - After 100+ inserts: count = 100 (stays at max, circular overwrite).
     *
     * @dev USAGE:
     *      1. Clients determine if root history is full (count == ROOT_HISTORY_SIZE).
     *      2. Off-chain systems estimate how far back tree proofs are valid.
     *         - Example: count = 100, ~1 insert per minute → ~100 minutes of history.
     *      3. Auditors verify history is being maintained properly.
     *
     * @dev GAS COST:
     *      ~300 gas (simple array length read).
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     */
    function getRootsCount()
        public
        view
        returns (uint256 count)
    {
        return roots.length;
    }

    /**
     * @notice Returns the current maximum leaf capacity of the tree.
     *
     * @return maxLeaves Maximum number of leaves the tree can hold.
     *
     * @dev ALWAYS RETURNS:
     *      2^TREE_DEPTH = 2^20 = 1,048,576.
     *
     * @dev PURPOSE:
     *      Allows contracts to determine tree limits without hardcoding constant.
     *      Useful for scaling estimates and protocol upgrades.
     *
     * @dev USAGE:
     *      - Monitor tree saturation: if leafCount approaches MAX_LEAVES, upgrade needed.
     *      - Calculate insertion window remaining: MAX_LEAVES - leafCount.
     *      - Gas estimation: tree is full when leafCount == MAX_LEAVES.
     *
     * @dev VIEW FUNCTION:
     *      No state changes, safe to call from anywhere.
     *      Gas cost: constant (returns hardcoded value).
     */
    function getMaxLeaves()
        public
        pure
        returns (uint256 maxLeaves)
    {
        return MAX_LEAVES;
    }
}
