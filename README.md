# okkult-contracts

```bash
$ cat description.txt
> Smart contracts for Okkult Protocol.
> Deployed on Ethereum Mainnet.
```

---

## Contracts

```bash
$ ls contracts/core/
> OkkultVerifier   → Verifies ZK compliance proofs on-chain
> OkkultShield     → Non-custodial shielded asset pool (UTXO)
> OkkultVote       → Private on-chain governance (MACI-based)
> OkkultRelay      → Decentralized transaction relay network

$ ls contracts/base/
> ComplianceGate   → Plug-in compliance gate for any protocol
> ComplianceTree   → On-chain Merkle root manager (OFAC data)
> NullifierRegistry → Prevents ZK proof from being reused
> UTXOTree          → Incremental encrypted Merkle tree

$ ls contracts/token/
> KULTToken        → $KULT ERC-20 governance token (100M supply)

$ ls contracts/adapters/
> UniswapAdapter   → Private swaps via Uniswap V3
> AaveAdapter      → Private lending via Aave V3
```

---

## Integration

```solidity
import "@okkult/contracts/ComplianceGate.sol";

contract MyProtocol is ComplianceGate {

    constructor(address okkultVerifier)
        ComplianceGate(okkultVerifier, ComplianceMode.STRICT)
    {}

    function deposit(uint256 amount)
        external
        onlyCompliant(msg.sender)
    {
        // your existing logic — unchanged
    }
}
```

---

## Deployed Contracts

### Ethereum Mainnet — Live

| Contract | ENS | Address | Status |
|----------|-----|---------|--------|
| OkkultShield v4 | shield.okkult.eth | `0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A` | ✅ Active |
| ShieldVerifier | verifier.okkult.eth | `0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c` | ✅ Active |
| UnshieldVerifier | unshield.okkult.eth | `0x0bf8136db4c13925724f4f7f436911e2b285d7c9` | ✅ Active |
| TransferVerifier | transfer.okkult.eth | `0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8` | ✅ Active |
| RailgunAdapter | railgun.okkult.eth | `0xDe8d4FaD0c6b283f6FC997858388F6C995928065` | ✅ Active |

### Relay / Treasury

| Role | Address |
|------|---------|
| Treasury | `0x641ca4b49098e11fe4735c58bafD4bbB781Eba49` |
---

## Install

```bash
git clone https://github.com/okkult-dev/okkult-contracts
cd okkult-contracts
npm install
```

---

## Test

```bash
npm test
```

---

## Deploy

```bash
# Sepolia testnet
npx hardhat run scripts/deploy.ts --network sepolia

# Mainnet
npx hardhat run scripts/deploy.ts --network mainnet
```

---

## Verify on Etherscan

```bash
npx hardhat verify --network mainnet CONTRACT_ADDRESS
```

---

## Audit

| Auditor | Scope | Status |
|---------|-------|--------|
| — | Smart contracts | Pending |
| — | ZK verifiers | Pending |


---

## Part of Okkult Protocol

```bash
$ cat ecosystem.txt
> okkult-proof      Core ZK compliance circuit
> okkult-sdk        TypeScript SDK
> okkult-contracts  ← you are here
> okkult-circuits   ZK circuits
> okkult-app        Frontend
> okkult-subgraph   The Graph indexer
> okkult-docs       Documentation
```

---

## License

```bash
$ cat license.txt
> MIT — okkult.io · @Okkult_
```
