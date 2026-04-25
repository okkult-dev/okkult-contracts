# Contributing to Okkult Protocol

## Development Setup

```bash
git clone https://github.com/okkult-dev/okkult-contracts
cd okkult-contracts
npm install
cp .env.example .env
```

## Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run coverage

# Run specific test file
npx hardhat test test/OkkultShield.test.ts
```

## Code Standards

- Solidity 0.8.20
- Full NatSpec on every function
- Test coverage minimum 80%
- No hardcoded addresses — use constructor params
- Use SafeERC20 for all token transfers
- ReentrancyGuard on all state-changing functions

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Open a pull request with clear description

## Reporting Issues

Security issues: security@okkult.io
General issues: GitHub Issues
