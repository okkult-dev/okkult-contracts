// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title UTXOTree
/// @notice Incremental append-only Merkle tree for UTXO commitments
/// @dev Stores commitment hashes of shielded UTXOs.
///      Tree is append-only — leaves can never be modified or removed.
///      Uses keccak256 as hash function.
///      In production ZK circuits use Poseidon — verified off-chain.
abstract contract UTXOTree {

    // ── Constants ─────────────────────────────────────────────

    /// @notice Depth of the Merkle tree
    uint256 public constant TREE_DEPTH = 20;

    /// @notice Maximum number of leaves (2^20)
    uint256 public constant MAX_LEAVES = 1 << 20;

    /// @notice Number of historical roots to store
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    // ── State ─────────────────────────────────────────────────

    /// @notice Total number of leaves inserted
    uint256 public leafCount;

    /// @notice Current Merkle root
    bytes32 public currentRoot;

    /// @notice Circular buffer of historical roots
    bytes32[100] public roots;

    /// @notice Index for root circular buffer
    uint256 private rootIndex;

    /// @notice Filled subtrees for incremental insertion
    bytes32[20] public filledSubtrees;

    /// @notice Zero values for each level
    bytes32[21] public zeros;

    // ── Events ────────────────────────────────────────────────

    /// @notice Emitted when a leaf is inserted into the tree
    event LeafInserted(
        bytes32 indexed commitment,
        uint256 indexed leafIndex,
        bytes32         newRoot
    );

    // ── Errors ────────────────────────────────────────────────

    error TreeFull();
    error InvalidLeaf();

    // ── Constructor ───────────────────────────────────────────

    constructor() {
        // Initialize zero values bottom-up
        zeros[0] = bytes32(0);
        for (uint256 i = 1; i <= TREE_DEPTH; i++) {
            zeros[i] = _hash(zeros[i - 1], zeros[i - 1]);
        }

        // Initialize filled subtrees with zeros
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            filledSubtrees[i] = zeros[i];
        }

        // Initial root = hash of all zeros
        currentRoot = zeros[TREE_DEPTH];

        // Store initial root in history
        roots[0]   = currentRoot;
        rootIndex  = 1;
    }

    // ── Internal functions ────────────────────────────────────

    /// @notice Insert a leaf into the tree
    /// @param commitment The commitment hash to insert
    /// @return index The index of the inserted leaf
    function _insert(bytes32 commitment)
        internal
        returns (uint256 index)
    {
        if (commitment == bytes32(0)) revert InvalidLeaf();
        if (leafCount >= MAX_LEAVES)  revert TreeFull();

        index = leafCount;
        leafCount++;

        uint256 currentIndex = index;
        bytes32 currentLevelHash = commitment;
        bytes32 left;
        bytes32 right;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                // Current node is left child
                left  = currentLevelHash;
                right = zeros[i];
                filledSubtrees[i] = currentLevelHash;
            } else {
                // Current node is right child
                left  = filledSubtrees[i];
                right = currentLevelHash;
            }

            currentLevelHash = _hash(left, right);
            currentIndex >>= 1;
        }

        // Update current root
        currentRoot = currentLevelHash;

        // Store in circular buffer
        roots[rootIndex % ROOT_HISTORY_SIZE] = currentRoot;
        rootIndex++;

        emit LeafInserted(commitment, index, currentRoot);
    }

    /// @notice Hash two nodes together
    /// @dev Using keccak256 for gas efficiency.
    ///      ZK circuits use Poseidon — verified by proof.
    /// @param left  Left node
    /// @param right Right node
    /// @return hash The parent hash
    function _hash(bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(left, right));
    }

    // ── External view functions ───────────────────────────────

    /// @notice Get the current Merkle root
    /// @return Current root
    function getRoot()
        external
        view
        returns (bytes32)
    {
        return currentRoot;
    }

    /// @notice Check if a root is known (current or historical)
    /// @param root The root to check
    /// @return True if root is known
    function isKnownRoot(bytes32 root)
        public
        view
        returns (bool)
    {
        if (root == bytes32(0)) return false;

        uint256 check = rootIndex;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (roots[check % ROOT_HISTORY_SIZE] == root)
                return true;
            if (check == 0) break;
            check--;
        }
        return false;
    }
}
