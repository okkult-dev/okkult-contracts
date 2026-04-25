// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { UTXOTree } from '../base/UTXOTree.sol';

/// @title TestUTXOTree
/// @notice Exposes UTXOTree internal functions for testing
/// @dev NEVER deploy to mainnet
contract TestUTXOTree is UTXOTree {

    constructor() UTXOTree() {}

    /// @notice Expose internal _insert for testing
    function testInsert(bytes32 commitment)
        external
        returns (uint256)
    {
        return _insert(commitment);
    }
}
