# Known Issues & Accepted Risks

## Accepted Risks

### 1. Anonymity Set Size
Small pool size = lower privacy guarantees.
Larger anonymity set = harder to trace.
This is a privacy property, not a security bug.
Accepted as a known and documented limitation.

### 2. Poseidon Hash Implementation
Current UTXOTree uses keccak256 as a placeholder
in some helper functions.
Production verifiers use Poseidon via Groth16 circuits.
Auditors should verify Poseidon consistency across
circuit and contract implementations.

### 3. Client-side Proof Generation
ZK proofs are generated in the user's browser.
If the user's device is compromised, privacy may degrade.
This is a property of the ZK system — not a contract bug.
The contract only verifies proof validity — it does not
control how proofs are generated.

### 4. Compliance Tree Staleness
ComplianceTree root has a 48-hour maximum age.
If the off-chain updater fails to refresh the root,
shield operations will revert with "Tree outdated".
This is intentional — stale sanctions data is rejected.
The risk is DoS on shield operations, not fund loss.

### 5. ZK Verifier Trust
ShieldVerifier, UnshieldVerifier, and TransferVerifier
are generated from Circom circuits.
Their correctness depends on circuit correctness.
A separate ZK circuit audit is recommended.

### 6. Railgun Protocol Dependency
RailgunAdapter trusts Railgun contract addresses.
If Railgun contracts are compromised or malicious,
the adapter may behave unexpectedly.
This is a third-party dependency risk — mitigated
by Railgun's own audit history with Zokyo.

## Out of Scope Issues

- Gas optimization suggestions
- Frontend (okkult-app) vulnerabilities
- Off-chain relayer vulnerabilities
- Railgun protocol internal vulnerabilities
- Chainalysis oracle data accuracy
- Network-level privacy (IP metadata)

## Notes for Auditors

All contracts are deployed on Ethereum Mainnet
and source-verified on Etherscan.

Etherscan links:
- OkkultShield: etherscan.io/address/0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A#code
- RailgunAdapter: etherscan.io/address/0xDe8d4FaD0c6b283f6FC997858388F6C995928065#code
