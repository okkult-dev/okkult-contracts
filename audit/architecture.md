# Architecture Overview — Okkult Protocol

## System Summary

Okkult is a zero-knowledge privacy infrastructure
built natively on Ethereum L1.

It consists of a shielded UTXO pool with:
- Compliance enforcement at the contract level
- ZK proof verification for all operations
- Native integration with Railgun Protocol
- Non-custodial, immutable contract design

## Component Diagram
```
User Wallet
│
├──► ComplianceGate.onlyCompliant()
│         │
│         ▼
│    OkkultVerifier.hasValidProof()
│         │
▼         ▼
OkkultShield.sol ──────────────── UTXOTree.sol
│                                  │
├── shield()    → insert leaf      │
├── unshield()  → spend UTXO      │
└── transfer()  → spend + insert  │
│                                  │
├──► ShieldVerifier.verifyProof()
├──► UnshieldVerifier.verifyProof()
└──► TransferVerifier.verifyProof()
│
└──► RailgunAdapter.sol
│
└──► Railgun Protocol
```
## UTXO Model

Every shielded balance is a UTXO:
commitment = Poseidon(amount, token, secret, owner)
nullifier  = Poseidon(commitment, secret)

Only the commitment is stored on-chain.
Amount, token, and owner remain encrypted.

## Shield Flow

User calls shield(token, amount, commitment, proof)
ComplianceGate verifies user has valid Okkult proof
ShieldVerifier.verifyProof() validates commitment
ERC20.transferFrom(user → OkkultShield)
Fee deducted and sent to treasury (0.20%)
Commitment inserted into UTXOTree
Shielded event emitted


## Unshield Flow

User calls unshield(token, amount, nullifier, root, recipient, proof)
UnshieldVerifier.verifyProof() validates ownership
NullifierRegistry checks nullifier not used
NullifierRegistry marks nullifier as spent
ERC20.transfer(OkkultShield → recipient, netAmount)
Fee deducted and sent to treasury (0.20%)
Unshielded event emitted


## Transfer Flow

User calls privateTransfer(inNullifier, out1, out2, root, proof)
TransferVerifier verifies conservation: in == out1 + out2
NullifierRegistry marks inNullifier as spent
Two new commitments inserted into UTXOTree
PrivateTransfer event emitted
No token movement — all within pool


## Railgun Integration
RailgunAdapter wraps OkkultShield interactions
with Railgun Protocol.
modifier onlyShield:
Only OkkultShield can call RailgunAdapter.
Trust model:
RailgunAdapter trusts OkkultShield.
OkkultShield trusts RailgunAdapter as a whitelisted adapter.
No trust extended to Railgun contracts beyond standard ERC-20.

## Key Invariants

Every shield requires a valid compliance proof
Each nullifier can only be used once — ever
Shield amount == unshield amount + fee (conservation)
Fee always goes to immutable treasury address
No admin can pause, upgrade, or drain the contract
Merkle tree is append-only — no leaf modification


## Admin Privileges
OkkultShield:
admin → whitelist/blacklist adapters only
No pause, no upgrade, no drain
RailgunAdapter:
No admin functions
onlyShield modifier — immutable
UTXOTree:
No admin functions
Append-only — immutable
ComplianceGate:
admin → whitelist addresses (for contracts/DAOs)
admin → set compliance mode (STRICT/SOFT)
admin → transferAdmin

## Fee Model
Shield fee:   0.20% of amount
Unshield fee: 0.20% of amount
Treasury:     0x641ca4b49098e11fe4735c58bafD4bbB781Eba49
Fee calculation:
fee    = amount * 20 / 10000
net    = amount - fee
ERC20.transfer(treasury, fee)
ERC20.transfer(recipient, net)

## Dependencies
OpenZeppelin v5:

IERC20
SafeERC20
ReentrancyGuard

Circom-generated:

ShieldVerifier (Groth16)
UnshieldVerifier (Groth16)
TransferVerifier (Groth16)

External protocols:

Railgun Protocol (trusted adapter)
Chainalysis Oracle (sanctions data)
