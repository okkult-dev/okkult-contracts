# Test Coverage Report

## Summary

| Metric | Coverage |
|--------|----------|
| Lines | >80% |
| Statements | >80% |
| Functions | >80% |
| Branches | >70% |

## Test Files

| File | Tests | Description |
|------|-------|-------------|
| OkkultShield.test.ts | 25 | Shield, unshield, transfer, security |
| RailgunAdapter.test.ts | 10 | Adapter operations, access control |
| UTXOTree.test.ts | 12 | Tree insertion, root history |
| integration.test.ts | 10 | Full end-to-end flows |

**Total: 57 test cases**

## How to Run

```bash
# Install
npm install

# Run all tests
npm test

# Run with coverage
npm run coverage

# View report
open coverage/index.html
```

## CI Status

All tests run automatically on every push via GitHub Actions.
See: .github/workflows/ci.yml
