#!/bin/bash
set -e

echo ""
echo "========================================"
echo "  Okkult Contracts — Coverage Report"
echo "========================================"
echo ""

# Run coverage
npx hardhat coverage --solcoverjs .solcover.js

echo ""
echo "========================================"
echo "  Coverage report saved to:"
echo "  coverage/index.html"
echo "========================================"
echo ""

# Check minimum coverage threshold
THRESHOLD=80

echo "Checking coverage threshold: ${THRESHOLD}%"
echo ""

# Parse coverage from output
# If below threshold, exit with error
node -e "
const fs    = require('fs')
const data  = JSON.parse(
  fs.readFileSync('coverage/coverage-summary.json', 'utf8')
)
const total = data.total
const lines = total.lines.pct
const stmts = total.statements.pct
const funcs = total.functions.pct
const branches = total.branches.pct

console.log('Lines:      ' + lines + '%')
console.log('Statements: ' + stmts + '%')
console.log('Functions:  ' + funcs + '%')
console.log('Branches:   ' + branches + '%')
console.log('')

const threshold = ${THRESHOLD}
if (
  lines < threshold ||
  stmts < threshold ||
  funcs < threshold
) {
  console.error('Coverage below ' + threshold + '% threshold!')
  process.exit(1)
} else {
  console.log('Coverage OK — above ' + threshold + '% threshold.')
}
"
