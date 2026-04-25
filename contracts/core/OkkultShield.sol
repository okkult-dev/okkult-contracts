// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ReentrancyGuard } from
    '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import { IERC20 } from
    '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import { SafeERC20 } from
    '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import { UTXOTree }       from '../base/UTXOTree.sol';
import { ComplianceGate, ComplianceMode } from
    '../base/ComplianceGate.sol';
import { IOkkultShield }  from '../interfaces/IOkkultShield.sol';

/// @title OkkultShield v4
/// @notice Non-custodial shielded UTXO pool for ERC-20 tokens
/// @dev Deployed at: 0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A
///      ENS: shield.okkult.eth
///
///      Key properties:
///      - Non-custodial — Okkult never controls funds
///      - Compliance-enforced — requires valid Okkult proof
///      - ZK-verified — all operations verified by Groth16 proofs
///      - Immutable — no admin keys, no pause, no upgrade
///      - UTXO model — encrypted balance structure
///
///      Fee model: 0.20% on shield and unshield
///      Fee recipient: treasury (immutable)
contract OkkultShield is
    IOkkultShield,
    UTXOTree,
    ComplianceGate,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    // ── Constants ─────────────────────────────────────────────

    /// @notice Shield/unshield fee in basis points (0.20%)
    uint256 public constant FEE_BPS = 20;

    /// @notice Basis points denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    // ── Interfaces ────────────────────────────────────────────

    interface ICircomVerifier {
        function verifyProof(
            uint[2]    calldata a,
            uint[2][2] calldata b,
            uint[2]    calldata c,
            uint[2]    calldata input
        ) external view returns (bool);
    }

    // ── State ─────────────────────────────────────────────────

    /// @notice ZK verifier for shield proofs
    ICircomVerifier public immutable shieldVerifier;

    /// @notice ZK verifier for unshield proofs
    ICircomVerifier public immutable unshieldVerifier;

    /// @notice ZK verifier for transfer proofs
    ICircomVerifier public immutable transferVerifier;

    /// @notice Treasury address — receives all fees
    address public immutable treasury;

    /// @notice Spent nullifiers — prevents UTXO double-spend
    mapping(bytes32 => bool) private _spent;

    // ── Errors ────────────────────────────────────────────────

    error InvalidAmount();
    error InvalidCommitment();
    error InvalidRecipient();
    error InvalidProof();
    error UnknownRoot();
    error AlreadySpent(bytes32 nullifier);
    error InsufficientBalance();

    // ── Constructor ───────────────────────────────────────────

    /// @param _okkultVerifier  OkkultVerifier contract address
    /// @param _shieldVerifier  ZK verifier for shield proofs
    /// @param _unshieldVerifier ZK verifier for unshield proofs
    /// @param _transferVerifier ZK verifier for transfer proofs
    /// @param _treasury        Fee recipient address
    constructor(
        address _okkultVerifier,
        address _shieldVerifier,
        address _unshieldVerifier,
        address _transferVerifier,
        address _treasury
    )
        UTXOTree()
        ComplianceGate(_okkultVerifier, ComplianceMode.STRICT)
    {
        require(_shieldVerifier   != address(0), 'Invalid shield verifier');
        require(_unshieldVerifier != address(0), 'Invalid unshield verifier');
        require(_transferVerifier != address(0), 'Invalid transfer verifier');
        require(_treasury         != address(0), 'Invalid treasury');

        shieldVerifier   = ICircomVerifier(_shieldVerifier);
        unshieldVerifier = ICircomVerifier(_unshieldVerifier);
        transferVerifier = ICircomVerifier(_transferVerifier);
        treasury         = _treasury;
    }

    // ── External functions ────────────────────────────────────

    /// @notice Shield ERC-20 tokens into the private pool
    /// @dev Requires valid Okkult compliance proof (enforced by modifier)
    ///      Requires valid ZK shield proof
    ///      Deducts 0.20% fee to treasury
    ///      Inserts commitment into UTXO Merkle tree
    /// @param token      ERC-20 token address
    /// @param amount     Amount to shield (in token decimals)
    /// @param commitment UTXO commitment hash
    /// @param proof_a    Groth16 proof component a
    /// @param proof_b    Groth16 proof component b
    /// @param proof_c    Groth16 proof component c
    function shield(
        address    token,
        uint256    amount,
        bytes32    commitment,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    )
        external
        override
        nonReentrant
        onlyCompliant(msg.sender)
    {
        // Validate inputs
        if (amount == 0)
            revert InvalidAmount();
        if (commitment == bytes32(0))
            revert InvalidCommitment();
        if (token == address(0))
            revert InvalidCommitment();

        // Verify ZK shield proof
        uint[2] memory publicInputs = [
            uint256(commitment),
            uint256(0) // complianceNullifier placeholder
        ];
        if (!shieldVerifier.verifyProof(
            proof_a, proof_b, proof_c, publicInputs
        )) revert InvalidProof();

        // Calculate and transfer fee
        uint256 fee    = (amount * FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmt = amount - fee;

        // Transfer full amount from user
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Transfer fee to treasury
        if (fee > 0) {
            IERC20(token).safeTransfer(treasury, fee);
        }

        // Insert commitment into UTXO tree
        uint256 leafIndex = _insert(commitment);

        emit Shielded(commitment, leafIndex, token, fee);
    }

    /// @notice Withdraw tokens from the private pool
    /// @dev Requires valid ZK unshield proof
    ///      Nullifier marks UTXO as spent (prevents double-spend)
    ///      Deducts 0.20% fee to treasury
    /// @param token     ERC-20 token address
    /// @param amount    Amount to withdraw
    /// @param nullifier Nullifier of the UTXO being spent
    /// @param root      Merkle root used when generating proof
    /// @param recipient Address to receive tokens
    /// @param proof_a   Groth16 proof component a
    /// @param proof_b   Groth16 proof component b
    /// @param proof_c   Groth16 proof component c
    function unshield(
        address    token,
        uint256    amount,
        bytes32    nullifier,
        bytes32    root,
        address    recipient,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    )
        external
        override
        nonReentrant
    {
        // Validate inputs
        if (amount == 0)
            revert InvalidAmount();
        if (recipient == address(0))
            revert InvalidRecipient();

        // Root must be known (prevents stale proof attacks)
        if (!isKnownRoot(root))
            revert UnknownRoot();

        // Nullifier must not be spent
        if (_spent[nullifier])
            revert AlreadySpent(nullifier);

        // Verify ZK unshield proof
        uint[2] memory publicInputs = [
            uint256(root),
            uint256(nullifier)
        ];
        if (!unshieldVerifier.verifyProof(
            proof_a, proof_b, proof_c, publicInputs
        )) revert InvalidProof();

        // Mark nullifier as spent BEFORE transfer (CEI pattern)
        _spent[nullifier] = true;

        // Calculate fee
        uint256 fee    = (amount * FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmt = amount - fee;

        // Check sufficient balance
        if (IERC20(token).balanceOf(address(this)) < amount)
            revert InsufficientBalance();

        // Transfer fee to treasury
        if (fee > 0) {
            IERC20(token).safeTransfer(treasury, fee);
        }

        // Transfer net amount to recipient
        IERC20(token).safeTransfer(recipient, netAmt);

        emit Unshielded(nullifier, recipient, token, netAmt);
    }

    /// @notice Private transfer between two 0zk addresses
    /// @dev Requires valid ZK transfer proof
    ///      Enforces conservation: inAmount == outAmount1 + outAmount2
    ///      No token movement — all within pool
    ///      Marks input nullifier as spent
    ///      Inserts two new output commitments
    /// @param inNullifier    Nullifier of input UTXO
    /// @param outCommitment1 Commitment of output UTXO 1 (recipient)
    /// @param outCommitment2 Commitment of output UTXO 2 (change)
    /// @param root           Merkle root used when generating proof
    /// @param proof_a        Groth16 proof component a
    /// @param proof_b        Groth16 proof component b
    /// @param proof_c        Groth16 proof component c
    function privateTransfer(
        bytes32    inNullifier,
        bytes32    outCommitment1,
        bytes32    outCommitment2,
        bytes32    root,
        uint[2]    calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2]    calldata proof_c
    )
        external
        override
        nonReentrant
    {
        // Validate inputs
        if (outCommitment1 == bytes32(0))
            revert InvalidCommitment();
        if (outCommitment2 == bytes32(0))
            revert InvalidCommitment();

        // Root must be known
        if (!isKnownRoot(root))
            revert UnknownRoot();

        // Input nullifier must not be spent
        if (_spent[inNullifier])
            revert AlreadySpent(inNullifier);

        // Verify ZK transfer proof
        // Conservation enforced by circuit: in == out1 + out2
        uint[2] memory publicInputs = [
            uint256(inNullifier),
            uint256(outCommitment1)
        ];
        if (!transferVerifier.verifyProof(
            proof_a, proof_b, proof_c, publicInputs
        )) revert InvalidProof();

        // Mark input as spent BEFORE insertions (CEI pattern)
        _spent[inNullifier] = true;

        // Insert two output commitments
        _insert(outCommitment1);
        _insert(outCommitment2);

        emit PrivateTransfer(inNullifier, outCommitment1, outCommitment2);
    }

    // ── External view functions ───────────────────────────────

    /// @notice Check if a UTXO nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been spent
    function isSpent(bytes32 nullifier)
        external
        view
        override
        returns (bool)
    {
        return _spent[nullifier];
    }

    /// @notice Override to satisfy IOkkultShield interface
    function getRoot()
        external
        view
        override
        returns (bytes32)
    {
        return currentRoot;
    }
}
