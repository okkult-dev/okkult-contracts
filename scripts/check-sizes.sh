#!/bin/bash
set -e

echo ""
echo "========================================"
echo "  Okkult Contracts — Contract Sizes"
echo "========================================"
echo ""

# EVM max is 24576 bytes
npx hardhat size-contracts

echo ""
echo "EVM limit: 24576 bytes"
echo "Contracts above 20KB should be considered for optimization."
echo ""
