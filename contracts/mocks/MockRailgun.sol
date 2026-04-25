// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title MockRailgun
/// @notice Mock Railgun contract for testing adapter
/// @dev NEVER deploy to mainnet
contract MockRailgun {
    using SafeERC20 for IERC20;

    event MockShield(address token, uint256 amount);
    event MockUnshield(address token, uint256 amount, address recipient);

    /// @notice Mock shield into Railgun
    function shield(
        address token,
        uint256 amount
    ) external {
        IERC20(token).safeTransferFrom(
            msg.sender, address(this), amount
        );
        emit MockShield(token, amount);
    }

    /// @notice Mock unshield from Railgun
    function unshield(
        address token,
        uint256 amount,
        address recipient
    ) external {
        IERC20(token).safeTransfer(recipient, amount);
        emit MockUnshield(token, amount, recipient);
    }
}
