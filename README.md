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

### Ethereum Mainnet

| Contract | Address | Etherscan |
|----------|---------|-----------|
| OkkultShield | `0xDAB93E727B2382972C0863a7Ac22e8b80bfBbC88` | [View ↗](https://etherscan.io/address/0xDAB93E727B2382972C0863a7Ac22e8b80bfBbC88) |
| ShieldVerifier | `0xCe5ac79201892C60EaaeD69607354721219b5737` | [View ↗](https://etherscan.io/address/0xCe5ac79201892C60EaaeD69607354721219b5737) |
| UnshieldVerifier | `0xFD7888c3C0f47bd8D3C8699075Cf15b487373482` | [View ↗](https://etherscan.io/address/0xFD7888c3C0f47bd8D3C8699075Cf15b487373482) |
| TransferVerifier | `0x20dE927843cdc0CEfd3c82510cF835982c4313EE` | [View ↗](https://etherscan.io/address/0x20dE927843cdc0CEfd3c82510cF835982c4313EE) |
| OkkultVerifier | `pending` | — |
| ComplianceTree | `pending` | — |
| NullifierRegistry | `pending` | — |
| OkkultVote | `pending` | — |
| OkkultRelay | `pending` | — |
| $KULT Token | `pending` | — |

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
