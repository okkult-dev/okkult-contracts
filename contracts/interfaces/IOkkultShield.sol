// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IOkkultShield
 * @author Okkult Protocol
 * @notice Standard interface for the Okkult shielded pool protocol.
 *
 * OkkultShield is a non-custodial UTXO-based shielded pool enabling users to:
 * 1. Shield: Convert public ERC-20 tokens into private commitments.
 * 2. Unshield: Withdraw private UTXOs back to public addresses without revealing history.
 * 3. Private Transfer: Transfer value between private addresses on-chain.
 *
 * The protocol uses:
 * - Merkle trees to track unspent UTXOs (commitments).
 * - Nullifiers to prevent UTXO double-spending.
 * - Zero-knowledge proofs to verify operations without revealing sender/receiver.
 *
 * @dev UTXO Model:
 *      - Each UTXO is represented by a commitment: keccak256(amount, token, salt, owner_secret).
 *      - Users prove ownership via private key without revealing the preimage.
 *      - Nullifiers (deterministic per UTXO) are published on-chain to prevent reuse.
 *      - The Merkle tree root is updated only when new commitments are added (shielding or transfers).
 *
 * @dev Compliance:
 *      All operations require a valid Okkult compliance proof demonstrating the user's address
 *      is not sanctioned. This is enforced at the proof circuit level.
 */
interface IOkkultShield {
    /// ========================================
    /// Events
    /// ========================================

    /**
     * @notice Emitted when tokens are shielded (converted to private commitments).
     * @param commitment The Merkle tree commitment representing the newly created UTXO.
     * @param leafIndex The index of this commitment in the UTXO Merkle tree.
     * @param token The ERC-20 token address being shielded.
     * @param fee The protocol fee in basis points deducted from the shielded amount.
     *
     * @dev The commitment is derived from: keccak256(amount - fee, token, salt, user_secret).
     *      Leaf indices allow off-chain indexers to reconstruct the tree and generate proofs.
     *      Fees support the protocol (bridge to KULT governance treasury).
     */
    event Shielded(
        bytes32 indexed commitment,
        uint256 indexed leafIndex,
        address token,
        uint256 fee
    );

    /**
     * @notice Emitted when tokens are unshielded (converted private → public).
     * @param nullifier The nullifier of the spent UTXO (prevents double-spending).
     * @param recipient The public address receiving the unshielded tokens.
     * @param token The ERC-20 token address being unshielded.
     * @param amount The amount of tokens transferred to the recipient.
     *
     * @dev The nullifier is publicly revealed (indexed for efficient lookup).
     *      Off-chain systems monitor this event to detect spent UTXOs.
     *      Recipients are linkable to the unshield operation but not to prior shielding.
     */
    event Unshielded(
        bytes32 indexed nullifier,
        address indexed recipient,
        address token,
        uint256 amount
    );

    /**
     * @notice Emitted when private tokens are transferred between anonymous addresses.
     * @param inNullifier The nullifier of the consumed input UTXO.
     * @param outCommitment1 The first output commitment (recipient 1).
     * @param outCommitment2 The second output commitment (change or recipient 2).
     *
     * @dev Enables on-chain private transactions with perfect transaction graph privacy.
     *      Neither inputs nor outputs are linkable to real identities; only nullifier is public.
     *      Both output commitments are added to the Merkle tree simultaneously.
     *
     * @dev Change handling: Protocols typically use 2-in-2-out transactions:
     *      - Input: User's UTXO being spent.
     *      - Outputs: Payment to recipient + change back to user.
     *      Both receiver and change are hidden in zero-knowledge.
     */
    event PrivateTransfer(
        bytes32 indexed inNullifier,
        bytes32 indexed outCommitment1,
        bytes32 indexed outCommitment2
    );

    /// ========================================
    /// Shield Operation (Public → Private)
    /// ========================================

    /**
     * @notice Converts ERC-20 tokens from public to private form (shielding).
     *
     * @param token The ERC-20 token to shield.
     * @param amount The amount of tokens to shield.
     * @param commitment The Merkle tree commitment representing the newly private UTXO.
     *                   Derived as: keccak256(amount_after_fee, token, salt, user_secret).
     * @param proof_a First component of the zk-SNARK proof.
     * @param proof_b Second component of the zk-SNARK proof.
     * @param proof_c Third component of the zk-SNARK proof.
     *
     * @dev FLOW:
     *      1. User transfers `amount` ERC-20 tokens to the contract (via safeTransferFrom).
     *      2. Protocol deducts a fee (e.g., 5 bps) and stores fee amount for governance.
     *      3. Proof is verified, proving the user's address is not sanctioned.
     *      4. The commitment is appended to the UTXO Merkle tree.
     *      5. Emits Shielded event with leafIndex for off-chain proof generation.
     *
     * @dev The proof circuit MUST verify:
     *      - Okkult compliance proof (user not sanctioned).
     *      - Commitment format is correct (prevents invalid UTXOs).
     *      - Commitment is not already spent (collision safety).
     *
     * @dev Off-chain:
     *      Users listen to Shielded events to construct their UTXO set.
     *      To spend later, they generate zero-knowledge proofs incorporating the leafIndex.
     *
     * @dev Fee Model:
     *      - Fees are paid from the shielded amount (before commitment).
     *      - Fee percentage is configurable via governance.
     *      - Unclaimed fees are redeemable by protocol (KULT stakers).
     */
    function shield(
        address token,
        uint256 amount,
        bytes32 commitment,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external;

    /// ========================================
    /// Unshield Operation (Private → Public)
    /// ========================================

    /**
     * @notice Withdraws tokens from their private form back to a public address (unshielding).
     *
     * @param token The ERC-20 token to unshield.
     * @param amount The amount of tokens to withdraw.
     * @param nullifier The nullifier of the UTXO being spent (prevents double-spending).
     * @param root The Merkle tree root at the time the proof was generated.
     * @param recipient The public address that will receive the unshielded tokens.
     * @param proof_a First component of the zk-SNARK proof.
     * @param proof_b Second component of the zk-SNARK proof.
     * @param proof_c Third component of the zk-SNARK proof.
     *
     * @dev FLOW:
     *      1. Proof verifies that the nullifier corresponds to a valid unspent UTXO.
     *      2. Proof verifies the UTXO amount and token match the unshield parameters.
     *      3. Proof proves the caller knew the UTXO's preimage (ownership).
     *      4. Proof verifies user's address is not sanctioned (Okkult compliance).
     *      5. Nullifier is marked as spent (prevents replay).
     *      6. Tokens are transferred to recipient via safeTransfer.
     *      7. Emits Unshielded event.
     *
     * @dev Root Parameter:
     *      Users provide the Merkle root they used when generating the proof.
     *      Implementation verifies this root is current or within acceptable staleness window.
     *      Staleness prevents stale proofs from accessing newly valid trees (reorg safety).
     *
     * @dev Nullifier Checking:
     *      Before accepting proof, implementation MUST check:
     *      - Nullifier has not been previously spent (via isSpent).
     *      - Nullifier format is valid (prevents collision attacks).
     *
     * @dev Recipient Unlinkability:
     *      The recipient address is NOT part of the proof. Any recipient can claim a proof,
     *      creating a withdrawal mechanism: user generates proof off-chain, passes URL/file to
     *      recipient who calls unshield() with the proof and their address.
     *      This enables donation/payment workflows while preserving sender anonymity.
     *
     * @dev Proof Circuit Requirements:
     *      - Merkle proof of commitment in tree == root.
     *      - Nullifier == hash(commitment, user_secret).
     *      - Commitment == hash(amount, token, salt, user_secret).
     *      - User has valid Okkult compliance proof.
     *      - Token and amount match parameters.
     */
    function unshield(
        address token,
        uint256 amount,
        bytes32 nullifier,
        bytes32 root,
        address recipient,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external;

    /// ========================================
    /// Private Transfer Operation (Private → Private)
    /// ========================================

    /**
     * @notice Transfers tokens between private addresses without revealing sender or receiver.
     *
     * @param inNullifier The nullifier of the UTXO being spent (input).
     * @param outCommitment1 The first newly created commitment (output).
     * @param outCommitment2 The second newly created commitment (output).
     * @param root The Merkle tree root at the time the proof was generated.
     * @param proof_a First component of the zk-SNARK proof.
     * @param proof_b Second component of the zk-SNARK proof.
     * @param proof_c Third component of the zk-SNARK proof.
     *
     * @dev FLOW:
     *      1. Proof verifies that inNullifier corresponds to a valid unspent UTXO.
     *      2. Proof proves the input UTXO's amount and token are correct.
     *      3. Proof proves input amount == outCommitment1 amount + outCommitment2 amount (balance).
     *      4. Proof proves caller knew the input UTXO's preimage (spending authority).
     *      5. Proof verifies caller's address is not sanctioned (Okkult compliance).
     *      6. inNullifier is marked as spent.
     *      7. Both output commitments are appended to the Merkle tree.
     *      8. Emits PrivateTransfer event with nullifier and both commitments.
     *
     * @dev Output Nullifiers:
     *      Off-chain systems derive the output commitments' nullifiers without seeing them:
     *      - Nullifier1 == hash(outCommitment1, output1_secret).
     *      - Nullifier2 == hash(outCommitment2, output2_secret).
     *      Only the recipient of each output knows the corresponding secret.
     *
     * @dev Change Pattern (Most Common):
     *      Typical private transaction: (1 input) → (recipient payment, change to sender).
     *      - Commitment 1: Payment to recipient (only recipient knows receiver_secret).
     *      - Commitment 2: Change to sender (only sender knows change_secret).
     *      External observer sees nullified input and two opaque outputs (perfect privacy).
     *
     * @dev Token Preservation:
     *      Proof must enforce sum of output amounts == input amount (no token creation/destruction).
     *      Token address remains constant throughout the transaction.
     *
     * @dev Root and Staleness:
     *      See unshield() documentation for root staleness semantics.
     *      Contracts SHOULD accept proofs for recent roots (e.g., last 256 blocks on Ethereum).
     *
     * @dev Proof Circuit:
     *      - Merkle proof: commitment_in in tree == root.
     *      - Amount check: input_amount == output_amount1 + output_amount2.
     *      - Nullifier enforcement: inNullifier == hash(commitment_in, user_secret).
     *      - Output commitments: outCommitment1 == hash(amount1, token, salt1, secret1).
     *      - Output commitments: outCommitment2 == hash(amount2, token, salt2, secret2).
     *      - Compliance: User has valid Okkult proof.
     */
    function privateTransfer(
        bytes32 inNullifier,
        bytes32 outCommitment1,
        bytes32 outCommitment2,
        bytes32 root,
        uint[2] calldata proof_a,
        uint[2][2] calldata proof_b,
        uint[2] calldata proof_c
    ) external;

    /// ========================================
    /// State Queries
    /// ========================================

    /**
     * @notice Checks whether a UTXO nullifier has already been spent (preventing replay).
     *
     * @param nullifier The nullifier to check.
     *
     * @return spent True if the nullifier has been used (UTXO already spent), false otherwise.
     *
     * @dev Implementation:
     *      - Maintains a mapping of nullifier → bool (spent status).
     *      - Can also use a set or bloom filter for gas optimization on large trees.
     *      - MUST return false for nullifiers not yet submitted (prevents false positives).
     *
     * @dev Usage:
     *      Off-chain: Check spent status before generating proofs to avoid wasted computation.
     *      On-chain: Proof generation checks nullifier status to prevent invalid proofs.
     */
    function isSpent(bytes32 nullifier)
        external
        view
        returns (bool spent);

    /**
     * @notice Returns the current Merkle tree root of all unspent UTXOs.
     *
     * @return root The current Merkle tree root.
     *
     * @dev Updates when:
     *      - shield() appends a new commitment (after fee deduction).
     *      - privateTransfer() appends two new commitments.
     *      - Tree rebalancing (if using dynamic Merkle tree implementations).
     *
     * @dev Does NOT update when:
     *      - unshield() is called (nullifier marked spent, but tree unchanged).
     *      - Fee is collected (not tree-related).
     *
     * @dev Usage:
     *      Off-chain: Users query root before generating proofs to ensure freshness.
     *      Root inclusion: Proofs must reference this root to be valid.
     *      Staleness safeguard: Contracts accept proofs only for roots in acceptable window.
     *
     * @dev Starting Value:
     *      Initial root is typically the empty tree (keccak256("OkkultShield") for leaves).
     *      First shield() call extends the tree to depth 1.
     */
    function getRoot()
        external
        view
        returns (bytes32 root);
}
