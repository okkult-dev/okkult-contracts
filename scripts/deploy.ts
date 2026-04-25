import { ethers } from 'hardhat'
import * as fs    from 'fs'
import * as path  from 'path'

async function main() {
  const [deployer] = await ethers.getSigners()

  console.log('')
  console.log('========================================')
  console.log('  Okkult Contracts — Deploy')
  console.log('========================================')
  console.log('')
  console.log('Deployer:', deployer.address)
  console.log('Balance: ', ethers.formatEther(
    await ethers.provider.getBalance(deployer.address)
  ), 'ETH')
  console.log('')

  const TREASURY = deployer.address // update to multisig

  // Note: OkkultShield and verifiers are already deployed.
  // This script deploys the remaining contracts.

  const EXISTING = {
    okkultShield:     '0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A',
    shieldVerifier:   '0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c',
    unshieldVerifier: '0x0bf8136db4c13925724f4f7f436911e2b285d7c9',
    transferVerifier: '0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8',
    railgunAdapter:   '0xDe8d4FaD0c6b283f6FC997858388F6C995928065',
    treasury:         '0x641ca4b49098e11fe4735c58bafD4bbB781Eba49',
  }

  console.log('Existing contracts loaded.')
  console.log('')

  // Deploy NullifierRegistry
  console.log('Deploying NullifierRegistry...')
  const NullifierRegistry =
    await ethers.getContractFactory('NullifierRegistry')
  const nullifierRegistry = await NullifierRegistry.deploy(
    ethers.ZeroAddress // temp — updated after verifier deploy
  )
  await nullifierRegistry.waitForDeployment()
  const nullifierRegistryAddr = await nullifierRegistry.getAddress()
  console.log('✅ NullifierRegistry:', nullifierRegistryAddr)
  console.log('')

  // Deploy ComplianceTree
  console.log('Deploying ComplianceTree...')
  const ComplianceTree =
    await ethers.getContractFactory('ComplianceTree')
  const complianceTree = await ComplianceTree.deploy(
    ethers.ZeroHash, // initial root
    deployer.address  // updater
  )
  await complianceTree.waitForDeployment()
  const complianceTreeAddr = await complianceTree.getAddress()
  console.log('✅ ComplianceTree:', complianceTreeAddr)
  console.log('')

  // Save deployments
  const deployments = {
    network:    'mainnet',
    chainId:    1,
    deployedAt: new Date().toISOString(),
    treasury:   EXISTING.treasury,
    contracts: {
      ...EXISTING,
      nullifierRegistry: nullifierRegistryAddr,
      complianceTree:    complianceTreeAddr,
      okkultVerifier:    'pending',
      okkultVote:        'pending',
      okkultRelay:       'pending',
      kultToken:         'pending',
    }
  }

  const outPath = path.join(__dirname, '../deployments/mainnet.json')
  fs.mkdirSync(path.dirname(outPath), { recursive: true })
  fs.writeFileSync(outPath, JSON.stringify(deployments, null, 2))

  console.log('========================================')
  console.log('  Deployment complete.')
  console.log('  Saved to deployments/mainnet.json')
  console.log('========================================')
  console.log('')
}

main().catch(console.error)
