import { run }   from 'hardhat'
import mainnet   from '../deployments/mainnet.json'

interface VerifyParams {
  name:    string
  address: string
  args:    any[]
}

async function verify({ name, address, args }: VerifyParams) {
  try {
    console.log(`Verifying: ${name} at ${address}`)
    await run('verify:verify', {
      address,
      constructorArguments: args
    })
    console.log(`✅ Verified: ${name}`)
  } catch (err: any) {
    if (err.message?.includes('Already Verified')) {
      console.log(`⏭️  Already verified: ${name}`)
    } else {
      console.log(`❌ Failed: ${name} — ${err.message}`)
    }
  }
  console.log('')
}

async function main() {
  console.log('')
  console.log('========================================')
  console.log('  Okkult Contracts — Etherscan Verify')
  console.log('========================================')
  console.log('')

  const c = mainnet.contracts

  await verify({
    name:    'NullifierRegistry',
    address: c.nullifierRegistry,
    args:    [c.okkultVerifier]
  })

  await verify({
    name:    'ComplianceTree',
    address: c.complianceTree,
    args:    [
      '0x0000000000000000000000000000000000000000000000000000000000000000',
      mainnet.treasury
    ]
  })

  console.log('========================================')
  console.log('  Verification complete.')
  console.log('========================================')
}

main().catch(console.error)
