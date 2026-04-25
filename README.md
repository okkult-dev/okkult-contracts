# okkult-contracts

```bash
$ cat description.txt
> Smart contracts for Okkult Protocol.
> Deployed and source-verified on Ethereum Mainnet.
```

---

## Deployed Contracts

### Core Protocol — Ethereum Mainnet

| Contract | ENS | Address | Status |
|----------|-----|---------|--------|
| OkkultShield v4 | shield.okkult.eth | [`0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A`](https://etherscan.io/address/0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A#code) | Active — Verified |
| ShieldVerifier | verifier.okkult.eth | [`0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c`](https://etherscan.io/address/0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c#code) | Active — Verified |
| UnshieldVerifier | unshield.okkult.eth | [`0x0bf8136db4c13925724f4f7f436911e2b285d7c9`](https://etherscan.io/address/0x0bf8136db4c13925724f4f7f436911e2b285d7c9#code) | Active — Verified |
| TransferVerifier | transfer.okkult.eth | [`0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8`](https://etherscan.io/address/0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8#code) | Active — Verified |
| RailgunAdapter | railgun.okkult.eth | [`0xDe8d4FaD0c6b283f6FC997858388F6C995928065`](https://etherscan.io/address/0xDe8d4FaD0c6b283f6FC997858388F6C995928065#code) | Active |

### Relay / Treasury

| Role | Address |
|------|---------|
| Treasury | [`0x641ca4b49098e11fe4735c58bafD4bbB781Eba49`](https://etherscan.io/address/0x641ca4b49098e11fe4735c58bafD4bbB781Eba49) |

### Pending Deployment

| Contract | Status |
|----------|--------|
| OkkultVerifier | Pending |
| ComplianceTree | Pending |
| NullifierRegistry | Pending |
| OkkultVote | Pending |
| OkkultRelay | Pending |
| $KULT Token | Pending |

### Supported Tokens

| Symbol | Address | Decimals |
|--------|---------|----------|
| USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | 6 |
| WETH | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | 18 |
| DAI | `0x6B175474E89094C44Da98b954EedeAC495271d0F` | 18 |
| WBTC | `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` | 8 |
| USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | 6 |

---

## Structure

```bash
$ ls contracts/
> core/         OkkultShield.sol · RailgunAdapter.sol
> verifiers/    ShieldVerifier · UnshieldVerifier · TransferVerifier
> base/         UTXOTree · ComplianceGate · ComplianceTree · NullifierRegistry
> interfaces/   IOkkultShield · IComplianceGate
> mocks/        MockERC20 · MockRailgun · MockVerifier
```

---

## Audit

```bash
$ cat audit/status.txt
> Status   : Submitted to Zokyo
> Scope    : audit/scope.md
> Arch     : audit/architecture.md
> Issues   : audit/known-issues.md
```

---

## Install

```bash
git clone https://github.com/okkult-dev/okkult-contracts
cd okkult-contracts
npm install
cp .env.example .env
```

---

## Test

```bash
npm test
```

---

## Coverage

```bash
npm run coverage
```

---

## Security

```bash
$ cat security.txt
> Report : security@okkult.io
> Bounty : Up to $1,000 USDC
> Policy : SECURITY.md
```

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
