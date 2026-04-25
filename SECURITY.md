# Security Policy

## Reporting a Vulnerability

**Email:** security@okkult.io
**Response time:** within 48 hours

Please do not publicly disclose vulnerabilities
before they have been resolved.

## Bug Bounty

| Severity | Definition | Reward |
|----------|------------|--------|
| Critical | Direct loss of funds, proof forgery | Up to $1,000 USDC |
| High | Compliance bypass, nullifier reuse | Up to $500 USDC |
| Medium | Griefing, DoS, incorrect fee | Up to $200 USDC |
| Low | Minor issues, best practice | Up to $50 USDC |

## In Scope

- `contracts/core/OkkultShield.sol`
- `contracts/core/RailgunAdapter.sol`
- `contracts/base/UTXOTree.sol`
- `contracts/base/ComplianceGate.sol`
- `contracts/base/ComplianceTree.sol`
- `contracts/base/NullifierRegistry.sol`
- `contracts/verifiers/`

## Out of Scope

- Frontend application (okkult-app)
- Off-chain relayer software
- Third-party contracts (Railgun, Uniswap, Aave)
- Gas optimization suggestions
- Issues already publicly known

## Audit

Smart contract audit submitted to Zokyo.
Report will be published upon completion.

## Contact

security@okkult.io
