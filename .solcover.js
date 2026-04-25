module.exports = {
  skipFiles: [
    // Exclude mocks from coverage — not production code
    'mocks/MockERC20.sol',
    'mocks/MockVerifier.sol',
    'mocks/MockOkkultVerifier.sol',
    'mocks/MockRailgun.sol',
    'mocks/TestUTXOTree.sol',
  ],
  configureYulOptimizer: true,
  solcOptimizerDetails: {
    yul:        true,
    yulDetails: {
      stackAllocation: true
    }
  },
  // Coverage report output
  istanbulReporter: ['html', 'lcov', 'text', 'json'],
}
