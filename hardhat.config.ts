import { HardhatUserConfig } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import * as dotenv from 'dotenv'
dotenv.config()

const ALCHEMY_URL        = process.env.ALCHEMY_MAINNET_URL  || ''
const DEPLOYER_KEY       = process.env.DEPLOYER_PRIVATE_KEY ||
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const ETHERSCAN_API_KEY  = process.env.ETHERSCAN_API_KEY    || ''

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.20',
    settings: {
      optimizer: {
        enabled: true,
        runs:    200
      }
    }
  },

  networks: {
    hardhat: {
      // Only fork if ALCHEMY_URL is provided
      // Without it, tests run on local network
      ...(ALCHEMY_URL ? {
        forking: {
          url:         ALCHEMY_URL,
          enabled:     true,
          blockNumber: 22340000
        }
      } : {}),
      chainId: 31337
    },
    localhost: {
      url:     'http://127.0.0.1:8545',
      chainId: 31337
    },
    mainnet: {
      url:      ALCHEMY_URL,
      accounts: [DEPLOYER_KEY],
      chainId:  1
    },
    sepolia: {
      url:      process.env.ALCHEMY_SEPOLIA_URL || '',
      accounts: [DEPLOYER_KEY],
      chainId:  11155111
    }
  },

  etherscan: {
    apiKey: ETHERSCAN_API_KEY
  },

  gasReporter: {
    enabled: !!process.env.REPORT_GAS
  },

  mocha: {
    timeout: 120_000
  }
}

export default config
