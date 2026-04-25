# Audit Scope — Okkult Protocol

## Contracts In Scope

| Contract | Address | Description |
|----------|---------|-------------|
| OkkultShield.sol | `0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A` | Core shielded UTXO pool |
| RailgunAdapter.sol | `0xDe8d4FaD0c6b283f6FC997858388F6C995928065` | Railgun integration adapter |
| ShieldVerifier.sol | `0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c` | ZK shield proof verifier |
| UnshieldVerifier.sol | `0x0bf8136db4c13925724f4f7f436911e2b285d7c9` | ZK unshield proof verifier |
| TransferVerifier.sol | `0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8` | ZK transfer proof verifier |
| UTXOTree.sol | pending | Incremental Merkle tree |
| ComplianceGate.sol | pending | Compliance enforcement base |
| ComplianceTree.sol | pending | Merkle root manager |
| NullifierRegistry.sol | pending | Double-spend prevention |

## Focus Areas

1. **Reentrancy** — shield, unshield, transfer flows
2. **Double-spend** — nullifier registry integrity
3. **Merkle tree** — manipulation and proof forgery
4. **ZK verification** — bypass and malformed proofs
5. **Access control** — admin and modifier correctness
6. **Token handling** — SafeERC20, fee calculation
7. **Railgun integration** — trust assumptions and attack surface
8. **Integer arithmetic** — overflow, underflow, rounding
9. **Front-running** — MEV and ordering attacks
10. **Compliance bypass** — onlyCompliant modifier integrity

## Out of Scope

- ZK circuits (Circom) — separate audit track
- Frontend application
- Off-chain relayer software
- Third-party contracts (Railgun, Uniswap, Aave)
- Gas optimization

## Technical Details

| Property | Value |
|----------|-------|
| Network | Ethereum Mainnet (Chain ID: 1) |
| Solidity | 0.8.20 |
| Framework | Hardhat |
| Dependencies | OpenZeppelin v5 |
| Test coverage | >80% |

## External Integrations

| Protocol | Address | Trust Level |
|----------|---------|-------------|
| Railgun Shield | `0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9` | External |
| Chainalysis Oracle | `0x40C57923924B5c5c5455c48D93317139ADDaC8fb` | External |
| Uniswap V3 Router | `0xE592427A0AEce92De3Edee1F18E0157C05861564` | External |
