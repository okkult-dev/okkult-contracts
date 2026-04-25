import { HardhatUserConfig } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import 'solidity-coverage'
import * as dotenv from 'dotenv'
dotenv.config()

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.20',
    settings: {
      optimizer: {
        enabled: true,
        runs:    200
      },
      viaIR: false
    }
  },
  networks: {
    hardhat: {
      forking: {
        url:     process.env.ALCHEMY_MAINNET_URL!,
        enabled: true
      }
    },
    mainnet: {
      url:      process.env.ALCHEMY_MAINNET_URL!,
      accounts: [process.env.DEPLOYER_PRIVATE_KEY!],
      gasPrice: 'auto'
    }
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY!
  },
  gasReporter: {
    enabled:  !!process.env.REPORT_GAS,
    currency: 'USD'
  },
  paths: {
    sources:   './contracts',
    tests:     './test',
    cache:     './cache',
    artifacts: './artifacts'
  }
}

export default config
