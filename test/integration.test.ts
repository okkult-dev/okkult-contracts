import { expect }      from 'chai'
import { ethers }      from 'hardhat'
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers'
import { time }        from '@nomicfoundation/hardhat-toolbox/network-helpers'

describe('Okkult Protocol — Integration', function () {
  this.timeout(120_000)

  async function deployAll() {
    const [
      owner, treasury,
      alice, bob, carol,
      attacker
    ] = await ethers.getSigners()

    // Tokens
    const MockERC20 = await ethers.getContractFactory('MockERC20')
    const usdc = await MockERC20.deploy('USDC', 'USDC', 6)
    const weth = await MockERC20.deploy('WETH', 'WETH', 18)

    // Verifiers
    const MockVerifier = await ethers.getContractFactory('MockVerifier')
    const shieldV   = await MockVerifier.deploy()
    const unshieldV = await MockVerifier.deploy()
    const transferV = await MockVerifier.deploy()

    // OkkultVerifier
    const MockOV = await ethers.getContractFactory('MockOkkultVerifier')
    const okkultVerifier = await MockOV.deploy()

    // OkkultShield
    const OkkultShield = await ethers.getContractFactory('OkkultShield')
    const shield = await OkkultShield.deploy(
      await okkultVerifier.getAddress(),
      await shieldV.getAddress(),
      await unshieldV.getAddress(),
      await transferV.getAddress(),
      treasury.address
    )

    const shieldAddr = await shield.getAddress()
    const usdcAddr   = await usdc.getAddress()
    const wethAddr   = await weth.getAddress()

    // Setup
    const MINT = ethers.parseUnits('1000000', 6)
    for (const user of [alice, bob, carol, attacker]) {
      await usdc.mint(user.address, MINT)
      await usdc.connect(user).approve(shieldAddr, ethers.MaxUint256)
      await weth.mint(user.address, ethers.parseUnits('1000', 18))
      await weth.connect(user).approve(shieldAddr, ethers.MaxUint256)
    }

    // Give alice, bob, carol compliance proofs
    for (const user of [alice, bob, carol]) {
      await okkultVerifier.setValidProof(user.address, true)
    }

    const proof = {
      a: ['0', '0'] as [string, string],
      b: [['0', '0'], ['0', '0']] as [[string, string], [string, string]],
      c: ['0', '0'] as [string, string],
    }

    return {
      shield, usdc, weth, okkultVerifier,
      shieldV, unshieldV, transferV,
      owner, treasury, alice, bob, carol, attacker,
      shieldAddr, usdcAddr, wethAddr, proof
    }
  }

  // ── Full Shield → Transfer → Unshield flow ────────────────

  describe('Full Privacy Flow', () => {

    it('Alice shields → transfers to Bob → Bob unshields', async () => {
      const {
        shield, usdc, alice, bob, treasury,
        usdcAddr, proof
      } = await loadFixture(deployAll)

      const shieldAmt = ethers.parseUnits('1000', 6)
      const fee       = shieldAmt * BigInt(20) / BigInt(10000)

      // 1. Alice shields 1000 USDC
      const commitment1 = ethers.encodeBytes32String('alice-utxo')
      const aliceBefore = await usdc.balanceOf(alice.address)

      await shield.connect(alice).shield(
        usdcAddr, shieldAmt, commitment1,
        proof.a, proof.b, proof.c
      )

      expect(await usdc.balanceOf(alice.address))
        .to.equal(aliceBefore - shieldAmt)
      expect(await shield.leafCount()).to.equal(1)

      // 2. Alice does private transfer to Bob
      const inNullifier    = ethers.encodeBytes32String('alice-null')
      const bobCommitment  = ethers.encodeBytes32String('bob-utxo')
      const aliceChange    = ethers.encodeBytes32String('alice-change')
      const root           = await shield.currentRoot()

      await shield.privateTransfer(
        inNullifier, bobCommitment, aliceChange, root,
        proof.a, proof.b, proof.c
      )

      expect(await shield.leafCount()).to.equal(3)
      expect(await shield.isSpent(inNullifier)).to.equal(true)

      // 3. Bob unshields to his address
      const bobNullifier  = ethers.encodeBytes32String('bob-null')
      const unshieldAmt   = ethers.parseUnits('500', 6)
      const unshieldFee   = unshieldAmt * BigInt(20) / BigInt(10000)
      const bobNet        = unshieldAmt - unshieldFee
      const root2         = await shield.currentRoot()
      const bobBefore     = await usdc.balanceOf(bob.address)
      const tresBefore    = await usdc.balanceOf(treasury.address)

      await shield.unshield(
        usdcAddr, unshieldAmt, bobNullifier, root2,
        bob.address,
        proof.a, proof.b, proof.c
      )

      expect(await usdc.balanceOf(bob.address) - bobBefore)
        .to.equal(bobNet)
      expect(await shield.isSpent(bobNullifier)).to.equal(true)
    })

    it('Multiple users shield and unshield independently', async () => {
      const {
        shield, usdc,
        alice, bob, carol, treasury,
        usdcAddr, proof
      } = await loadFixture(deployAll)

      const amount = ethers.parseUnits('500', 6)

      // All three shield
      await shield.connect(alice).shield(
        usdcAddr, amount,
        ethers.encodeBytes32String('alice'),
        proof.a, proof.b, proof.c
      )
      await shield.connect(bob).shield(
        usdcAddr, amount,
        ethers.encodeBytes32String('bob'),
        proof.a, proof.b, proof.c
      )
      await shield.connect(carol).shield(
        usdcAddr, amount,
        ethers.encodeBytes32String('carol'),
        proof.a, proof.b, proof.c
      )

      expect(await shield.leafCount()).to.equal(3)

      // All three unshield
      const root = await shield.currentRoot()
      for (const [user, name] of [
        [alice, 'alice'], [bob, 'bob'], [carol, 'carol']
      ] as const) {
        const balBefore = await usdc.balanceOf(user.address)
        const nullifier = ethers.encodeBytes32String(`${name}-null`)

        await shield.unshield(
          usdcAddr, amount, nullifier, root,
          user.address,
          proof.a, proof.b, proof.c
        )

        const fee    = amount * BigInt(20) / BigInt(10000)
        const netAmt = amount - fee
        expect(await usdc.balanceOf(user.address) - balBefore)
          .to.equal(netAmt)
      }
    })
  })

  // ── Compliance enforcement ────────────────────────────────

  describe('Compliance Enforcement', () => {

    it('attacker cannot shield without compliance proof', async () => {
      const { shield, attacker, usdcAddr, proof } =
        await loadFixture(deployAll)

      await expect(
        shield.connect(attacker).shield(
          usdcAddr,
          ethers.parseUnits('1000', 6),
          ethers.encodeBytes32String('evil'),
          proof.a, proof.b, proof.c
        )
      ).to.be.revertedWith('Okkult: compliance proof required')
    })

    it('compliance proof expiry blocks shield', async () => {
      const {
        shield, alice, okkultVerifier, usdcAddr, proof
      } = await loadFixture(deployAll)

      // Revoke Alice's proof
      await okkultVerifier.setValidProof(alice.address, false)

      await expect(
        shield.connect(alice).shield(
          usdcAddr,
          ethers.parseUnits('100', 6),
          ethers.encodeBytes32String('c1'),
          proof.a, proof.b, proof.c
        )
      ).to.be.revertedWith('Okkult: compliance proof required')
    })
  })

  // ── Double-spend prevention ───────────────────────────────

  describe('Double-spend Prevention', () => {

    it('same nullifier cannot be used twice in unshield', async () => {
      const { shield, alice, usdcAddr, proof } =
        await loadFixture(deployAll)

      const amount   = ethers.parseUnits('1000', 6)
      const commit   = ethers.encodeBytes32String('c1')
      const nullifier= ethers.encodeBytes32String('n1')

      await shield.connect(alice).shield(
        usdcAddr, amount, commit,
        proof.a, proof.b, proof.c
      )

      const root = await shield.currentRoot()

      await shield.unshield(
        usdcAddr, amount, nullifier, root,
        alice.address, proof.a, proof.b, proof.c
      )

      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, root,
          alice.address, proof.a, proof.b, proof.c
        )
      ).to.be.revertedWith('UTXO already spent')
    })

    it('same nullifier cannot be used in both transfer and unshield', async () => {
      const { shield, alice, usdcAddr, proof } =
        await loadFixture(deployAll)

      const amount  = ethers.parseUnits('1000', 6)
      const commit  = ethers.encodeBytes32String('c1')
      const nullifier = ethers.encodeBytes32String('n1')

      await shield.connect(alice).shield(
        usdcAddr, amount, commit,
        proof.a, proof.b, proof.c
      )

      const root = await shield.currentRoot()

      // Use nullifier in transfer first
      await shield.privateTransfer(
        nullifier,
        ethers.encodeBytes32String('out1'),
        ethers.encodeBytes32String('out2'),
        root, proof.a, proof.b, proof.c
      )

      // Try to use same nullifier in unshield — must fail
      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, root,
          alice.address, proof.a, proof.b, proof.c
        )
      ).to.be.revertedWith('UTXO already spent')
    })
  })

  // ── Fee accounting ────────────────────────────────────────

  describe('Fee Accounting', () => {

    it('total fees collected equals sum of all operations', async () => {
      const {
        shield, usdc,
        alice, bob, carol, treasury,
        usdcAddr, proof
      } = await loadFixture(deployAll)

      const amounts = [
        ethers.parseUnits('100', 6),
        ethers.parseUnits('500', 6),
        ethers.parseUnits('1000', 6),
      ]

      const tresBefore = await usdc.balanceOf(treasury.address)
      let expectedFees = BigInt(0)

      for (let i = 0; i < amounts.length; i++) {
        const user = [alice, bob, carol][i]
        const amt  = amounts[i]
        const fee  = amt * BigInt(20) / BigInt(10000)
        expectedFees += fee

        await shield.connect(user).shield(
          usdcAddr, amt,
          ethers.encodeBytes32String(`c${i}`),
          proof.a, proof.b, proof.c
        )
      }

      const tresAfter = await usdc.balanceOf(treasury.address)
      expect(tresAfter - tresBefore).to.equal(expectedFees)
    })
  })
})
