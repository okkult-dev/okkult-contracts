// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ComplianceTree
/// @notice Manages the on-chain Merkle root of the compliance set
/// @dev Root is updated every 6 hours by an off-chain service
///      that reads OFAC sanctions data and Chainalysis oracle.
///      Stores historical roots to allow recently-generated proofs
///      to remain valid during root rotation.
contract ComplianceTree {

    // ── Constants ─────────────────────────────────────────────

    /// @notice Maximum age of a root before it is considered stale
    uint256 public constant MAX_ROOT_AGE = 48 hours;

    /// @notice Maximum number of historical roots to store
    /// @dev Circular buffer — oldest root is overwritten
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    // ── State ─────────────────────────────────────────────────

    /// @notice Current active Merkle root
    bytes32 public currentRoot;

    /// @notice Circular buffer of historical roots
    bytes32[100] public rootHistory;

    /// @notice Current position in circular buffer
    uint256 public rootHistoryIndex;

    /// @notice Total number of roots stored (capped at ROOT_HISTORY_SIZE)
    uint256 public rootHistoryCount;

    /// @notice Address authorized to update the root
    address public updater;

    /// @notice Timestamp of last root update
    uint256 public lastUpdated;

    // ── Events ────────────────────────────────────────────────

    /// @notice Emitted when the Merkle root is updated
    event RootUpdated(
        bytes32 indexed newRoot,
        bytes32 indexed oldRoot,
        uint256         timestamp
    );

    /// @notice Emitted when updater address is changed
    event UpdaterChanged(
        address indexed oldUpdater,
        address indexed newUpdater
    );

    // ── Errors ────────────────────────────────────────────────

    error OnlyUpdater();
    error InvalidRoot();
    error SameRoot();

    // ── Modifiers ─────────────────────────────────────────────

    modifier onlyUpdater() {
        if (msg.sender != updater) revert OnlyUpdater();
        _;
    }

    // ── Constructor ───────────────────────────────────────────

    /// @param _initialRoot Initial Merkle root
    /// @param _updater     Address authorized to update root
    constructor(bytes32 _initialRoot, address _updater) {
        require(_updater != address(0), 'Invalid updater');

        currentRoot   = _initialRoot;
        updater       = _updater;
        lastUpdated   = block.timestamp;

        // Store initial root in history
        rootHistory[0]    = _initialRoot;
        rootHistoryIndex  = 1;
        rootHistoryCount  = 1;
    }

    // ── External functions ────────────────────────────────────

    /// @notice Update the compliance Merkle root
    /// @dev Only callable by authorized updater
    /// @param newRoot The new Merkle root
    function updateRoot(bytes32 newRoot)
        external
        onlyUpdater
    {
        if (newRoot == bytes32(0))   revert InvalidRoot();
        if (newRoot == currentRoot)  revert SameRoot();

        bytes32 oldRoot = currentRoot;
        currentRoot     = newRoot;
        lastUpdated     = block.timestamp;

        // Store in circular buffer
        rootHistory[rootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        rootHistoryIndex++;
        if (rootHistoryCount < ROOT_HISTORY_SIZE) {
            rootHistoryCount++;
        }

        emit RootUpdated(newRoot, oldRoot, block.timestamp);
    }

    /// @notice Change the authorized updater
    /// @param newUpdater New updater address
    function setUpdater(address newUpdater)
        external
        onlyUpdater
    {
        require(newUpdater != address(0), 'Invalid updater');
        address old = updater;
        updater = newUpdater;
        emit UpdaterChanged(old, newUpdater);
    }

    /// @notice Check if the current root is still valid
    /// @return True if root was updated within MAX_ROOT_AGE
    function isRootValid()
        external
        view
        returns (bool)
    {
        return block.timestamp - lastUpdated <= MAX_ROOT_AGE;
    }

    /// @notice Check if a given root is in the history
    /// @param root The root to check
    /// @return True if root is known
    function isHistoricalRoot(bytes32 root)
        external
        view
        returns (bool)
    {
        if (root == bytes32(0)) return false;

        uint256 count = rootHistoryCount < ROOT_HISTORY_SIZE
            ? rootHistoryCount
            : ROOT_HISTORY_SIZE;

        for (uint256 i = 0; i < count; i++) {
            if (rootHistory[i] == root) return true;
        }
        return false;
    }

    /// @notice Get the number of roots stored in history
    /// @return Number of historical roots
    function getRootHistoryLength()
        external
        view
        returns (uint256)
    {
        return rootHistoryCount < ROOT_HISTORY_SIZE
            ? rootHistoryCount
            : ROOT_HISTORY_SIZE;
    }
}
