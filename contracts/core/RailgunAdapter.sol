// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from
    '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import { SafeERC20 } from
    '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import { ReentrancyGuard } from
    '@openzeppelin/contracts/utils/ReentrancyGuard.sol';

/// @title RailgunAdapter
/// @notice Adapter enabling OkkultShield to interact with Railgun Protocol
/// @dev Deployed at: 0xDe8d4FaD0c6b283f6FC997858388F6C995928065
///      ENS: railgun.okkult.eth
///
///      This contract acts as a bridge between OkkultShield
///      and Railgun Protocol. All calls are gated by onlyShield
///      — only OkkultShield can invoke this contract.
///
///      What Railgun sees: OkkultShield (this adapter) interacting.
///      What is hidden:    which user initiated the operation.
///
///      Trust model:
///      - Trusts OkkultShield (onlyShield modifier)
///      - Trusts Railgun contracts as external protocol
///      - No admin keys — immutable after deployment
contract RailgunAdapter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ── Interfaces ────────────────────────────────────────────

    /// @dev Minimal Railgun interface needed for adapter
    interface IRailgunPool {
        function shield(
            address token,
            uint256 amount
        ) external;

        function unshield(
            address token,
            uint256 amount,
            address recipient
        ) external;
    }

    // ── State ─────────────────────────────────────────────────

    /// @notice OkkultShield contract — only caller allowed
    address public immutable okkultShield;

    /// @notice Railgun Pool contract
    IRailgunPool public immutable railgunPool;

    // ── Events ────────────────────────────────────────────────

    /// @notice Emitted when tokens are forwarded to Railgun
    event ShieldedToRailgun(
        address indexed token,
        uint256         amount
    );

    /// @notice Emitted when tokens are received from Railgun
    event UnshieldedFromRailgun(
        address indexed token,
        uint256         amount,
        address indexed recipient
    );

    // ── Errors ────────────────────────────────────────────────

    error OnlyShield();
    error InvalidAmount();
    error InvalidAddress();

    // ── Modifiers ─────────────────────────────────────────────

    /// @dev Restricts all functions to OkkultShield only
    modifier onlyShield() {
        if (msg.sender != okkultShield) revert OnlyShield();
        _;
    }

    // ── Constructor ───────────────────────────────────────────

    /// @param _okkultShield Address of OkkultShield contract
    /// @param _railgunPool  Address of Railgun pool contract
    constructor(address _okkultShield, address _railgunPool) {
        require(_okkultShield != address(0), 'Invalid shield');
        require(_railgunPool  != address(0), 'Invalid railgun');

        okkultShield = _okkultShield;
        railgunPool  = IRailgunPool(_railgunPool);
    }

    // ── External functions ────────────────────────────────────

    /// @notice Forward tokens from OkkultShield to Railgun
    /// @dev Only callable by OkkultShield
    ///      OkkultShield transfers tokens to this contract first,
    ///      then this contract forwards to Railgun.
    /// @param token  ERC-20 token address
    /// @param amount Amount to shield in Railgun
    function shieldToRailgun(address token, uint256 amount)
        external
        nonReentrant
        onlyShield
    {
        if (amount == 0)           revert InvalidAmount();
        if (token == address(0))   revert InvalidAddress();

        // Pull tokens from OkkultShield
        IERC20(token).safeTransferFrom(
            msg.sender, address(this), amount
        );

        // Approve Railgun to spend tokens
        IERC20(token).approve(address(railgunPool), amount);

        // Shield into Railgun
        railgunPool.shield(token, amount);

        // Reset approval to zero (security best practice)
        IERC20(token).approve(address(railgunPool), 0);

        emit ShieldedToRailgun(token, amount);
    }

    /// @notice Receive tokens from Railgun and forward to recipient
    /// @dev Only callable by OkkultShield
    /// @param token     ERC-20 token address
    /// @param amount    Amount to unshield from Railgun
    /// @param recipient Final recipient of the tokens
    function unshieldFromRailgun(
        address token,
        uint256 amount,
        address recipient
    )
        external
        nonReentrant
        onlyShield
    {
        if (amount == 0)              revert InvalidAmount();
        if (token == address(0))      revert InvalidAddress();
        if (recipient == address(0))  revert InvalidAddress();

        // Unshield from Railgun to this contract
        railgunPool.unshield(token, amount, address(this));

        // Forward to final recipient
        IERC20(token).safeTransfer(recipient, amount);

        emit UnshieldedFromRailgun(token, amount, recipient);
    }

    /// @notice Emergency token recovery
    /// @dev Only callable by OkkultShield
    ///      Recovers tokens accidentally sent to this contract
    /// @param token     Token to recover
    /// @param recipient Address to send recovered tokens
    function recoverTokens(address token, address recipient)
        external
        onlyShield
    {
        if (recipient == address(0)) revert InvalidAddress();
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance > 0) {
            IERC20(token).safeTransfer(recipient, balance);
        }
    }
}
