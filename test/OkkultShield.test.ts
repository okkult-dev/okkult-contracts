import { expect }      from 'chai'
import { ethers }      from 'hardhat'
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers'

describe('OkkultShield', function () {
  this.timeout(60_000)

  // ── Fixture ───────────────────────────────────────────────
  async function deployFixture() {
    const [owner, treasury, user1, user2, attacker] =
      await ethers.getSigners()

    // Mock ERC20 tokens
    const MockERC20 = await ethers.getContractFactory('MockERC20')
    const usdc = await MockERC20.deploy('USD Coin', 'USDC', 6)
    const dai  = await MockERC20.deploy('Dai', 'DAI', 18)

    // Mock verifiers — always return true by default
    const MockVerifier = await ethers.getContractFactory('MockVerifier')
    const shieldVerifier   = await MockVerifier.deploy()
    const unshieldVerifier = await MockVerifier.deploy()
    const transferVerifier = await MockVerifier.deploy()

    // Mock OkkultVerifier
    const MockOkkultVerifier =
      await ethers.getContractFactory('MockOkkultVerifier')
    const okkultVerifier = await MockOkkultVerifier.deploy()

    // Deploy OkkultShield
    const OkkultShield = await ethers.getContractFactory('OkkultShield')
    const shield = await OkkultShield.deploy(
      await okkultVerifier.getAddress(),
      await shieldVerifier.getAddress(),
      await unshieldVerifier.getAddress(),
      await transferVerifier.getAddress(),
      treasury.address
    )

    const shieldAddr = await shield.getAddress()
    const usdcAddr   = await usdc.getAddress()
    const daiAddr    = await dai.getAddress()

    // Fund users
    const mintAmount = ethers.parseUnits('100000', 6)
    await usdc.mint(user1.address, mintAmount)
    await usdc.mint(user2.address, mintAmount)
    await usdc.mint(attacker.address, mintAmount)
    await dai.mint(user1.address, ethers.parseUnits('100000', 18))

    // Approve shield for all users
    await usdc.connect(user1).approve(shieldAddr, ethers.MaxUint256)
    await usdc.connect(user2).approve(shieldAddr, ethers.MaxUint256)
    await usdc.connect(attacker).approve(shieldAddr, ethers.MaxUint256)
    await dai.connect(user1).approve(shieldAddr, ethers.MaxUint256)

    // Give user1 and user2 compliance proof
    await okkultVerifier.setValidProof(user1.address, true)
    await okkultVerifier.setValidProof(user2.address, true)

    // Helper: dummy ZK proof inputs
    const dummyProof = {
      a: ['0', '0'] as [string, string],
      b: [['0', '0'], ['0', '0']] as [[string, string], [string, string]],
      c: ['0', '0'] as [string, string],
    }

    return {
      shield, usdc, dai, okkultVerifier,
      shieldVerifier, unshieldVerifier, transferVerifier,
      owner, treasury, user1, user2, attacker,
      shieldAddr, usdcAddr, daiAddr,
      dummyProof
    }
  }

  // ── Deployment ────────────────────────────────────────────

  describe('Deployment', () => {

    it('sets correct treasury address', async () => {
      const { shield, treasury } = await loadFixture(deployFixture)
      expect(await shield.admin()).to.equal(treasury.address)
    })

    it('initializes UTXO tree with zero leaves', async () => {
      const { shield } = await loadFixture(deployFixture)
      expect(await shield.leafCount()).to.equal(0)
    })

    it('initializes with correct verifier addresses', async () => {
      const {
        shield, shieldVerifier, unshieldVerifier, transferVerifier
      } = await loadFixture(deployFixture)

      expect(await shield.shieldVerifier())
        .to.equal(await shieldVerifier.getAddress())
      expect(await shield.unshieldVerifier())
        .to.equal(await unshieldVerifier.getAddress())
      expect(await shield.transferVerifier())
        .to.equal(await transferVerifier.getAddress())
    })
  })

  // ── shield() ──────────────────────────────────────────────

  describe('shield()', () => {

    it('emits Shielded event with correct params', async () => {
      const { shield, usdc, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await expect(
        shield.connect(user1).shield(
          usdcAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      )
        .to.emit(shield, 'Shielded')
        .withArgs(commitment, 0, usdcAddr, amount * BigInt(20) / BigInt(10000))
    })

    it('transfers tokens from user to shield contract', async () => {
      const { shield, usdc, user1, usdcAddr, shieldAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')
      const balBefore  = await usdc.balanceOf(shieldAddr)

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const balAfter = await usdc.balanceOf(shieldAddr)
      // Shield receives full amount minus fee
      const fee = amount * BigInt(20) / BigInt(10000)
      expect(balAfter - balBefore).to.equal(amount - fee)
    })

    it('sends 0.20% fee to treasury', async () => {
      const { shield, usdc, user1, treasury, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount      = ethers.parseUnits('1000', 6)
      const expectedFee = amount * BigInt(20) / BigInt(10000)
      const commitment  = ethers.encodeBytes32String('commitment1')
      const balBefore   = await usdc.balanceOf(treasury.address)

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const balAfter = await usdc.balanceOf(treasury.address)
      expect(balAfter - balBefore).to.equal(expectedFee)
    })

    it('inserts commitment into UTXO Merkle tree', async () => {
      const { shield, usdc, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')
      const leafBefore = await shield.leafCount()

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      expect(await shield.leafCount())
        .to.equal(leafBefore + BigInt(1))
    })

    it('updates Merkle root after shield', async () => {
      const { shield, usdc, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const rootBefore = await shield.currentRoot()
      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const rootAfter = await shield.currentRoot()
      expect(rootAfter).to.not.equal(rootBefore)
    })

    it('reverts if user has no compliance proof', async () => {
      const { shield, usdc, attacker, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await expect(
        shield.connect(attacker).shield(
          usdcAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Okkult: compliance proof required')
    })

    it('reverts on zero amount', async () => {
      const { shield, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const commitment = ethers.encodeBytes32String('commitment1')

      await expect(
        shield.connect(user1).shield(
          usdcAddr, 0, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Amount must be > 0')
    })

    it('reverts on zero bytes32 commitment', async () => {
      const { shield, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount = ethers.parseUnits('1000', 6)

      await expect(
        shield.connect(user1).shield(
          usdcAddr, amount, ethers.ZeroHash,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Invalid commitment')
    })

    it('reverts if ZK proof is invalid', async () => {
      const {
        shield, user1, usdcAddr, shieldVerifier, dummyProof
      } = await loadFixture(deployFixture)

      // Make verifier reject proofs
      await shieldVerifier.setShouldPass(false)

      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await expect(
        shield.connect(user1).shield(
          usdcAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Invalid shield proof')
    })

    it('handles multiple shields correctly', async () => {
      const { shield, usdc, user1, user2, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount = ethers.parseUnits('500', 6)

      for (let i = 0; i < 5; i++) {
        const commitment = ethers.encodeBytes32String(`commitment${i}`)
        const user = i % 2 === 0 ? user1 : user2

        await shield.connect(user).shield(
          usdcAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      }

      expect(await shield.leafCount()).to.equal(5)
    })

    it('works with different ERC20 tokens', async () => {
      const { shield, dai, user1, daiAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('1000', 18)
      const commitment = ethers.encodeBytes32String('commitment1')

      await expect(
        shield.connect(user1).shield(
          daiAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.emit(shield, 'Shielded')
    })
  })

  // ── unshield() ────────────────────────────────────────────

  describe('unshield()', () => {

    async function shieldFirst(ctx: any) {
      const { shield, usdcAddr, user1, dummyProof } = ctx
      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      return {
        amount,
        commitment,
        root:      await shield.currentRoot(),
        nullifier: ethers.encodeBytes32String('nullifier1'),
      }
    }

    it('emits Unshielded event with correct params', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdcAddr, user2, dummyProof } = ctx
      const { amount, root, nullifier } = await shieldFirst(ctx)

      const fee    = amount * BigInt(20) / BigInt(10000)
      const netAmt = amount - fee

      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, root,
          user2.address,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      )
        .to.emit(shield, 'Unshielded')
        .withArgs(nullifier, user2.address, usdcAddr, netAmt)
    })

    it('transfers net amount to recipient after fee', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdc, usdcAddr, user2, treasury, dummyProof } = ctx
      const { amount, root, nullifier } = await shieldFirst(ctx)

      const fee       = amount * BigInt(20) / BigInt(10000)
      const netAmt    = amount - fee
      const balBefore = await usdc.balanceOf(user2.address)
      const tresBefore= await usdc.balanceOf(treasury.address)

      await shield.unshield(
        usdcAddr, amount, nullifier, root,
        user2.address,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const balAfter  = await usdc.balanceOf(user2.address)
      const tresAfter = await usdc.balanceOf(treasury.address)

      expect(balAfter - balBefore).to.equal(netAmt)
      expect(tresAfter - tresBefore).to.equal(fee)
    })

    it('marks nullifier as spent after unshield', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdcAddr, user2, dummyProof } = ctx
      const { amount, root, nullifier } = await shieldFirst(ctx)

      await shield.unshield(
        usdcAddr, amount, nullifier, root,
        user2.address,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      expect(await shield.isSpent(nullifier)).to.equal(true)
    })

    it('prevents double-spend with same nullifier', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdcAddr, user2, dummyProof } = ctx
      const { amount, root, nullifier } = await shieldFirst(ctx)

      // First unshield succeeds
      await shield.unshield(
        usdcAddr, amount, nullifier, root,
        user2.address,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      // Second unshield with same nullifier must fail
      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, root,
          user2.address,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('UTXO already spent')
    })

    it('reverts on zero address recipient', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdcAddr, dummyProof } = ctx
      const { amount, root } = await shieldFirst(ctx)
      const nullifier2 = ethers.encodeBytes32String('nullifier2')

      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier2, root,
          ethers.ZeroAddress,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Invalid recipient')
    })

    it('reverts if ZK proof is invalid', async () => {
      const ctx = await loadFixture(deployFixture)
      const {
        shield, usdcAddr, user2,
        unshieldVerifier, dummyProof
      } = ctx
      const { amount, root, nullifier } = await shieldFirst(ctx)

      await unshieldVerifier.setShouldPass(false)

      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, root,
          user2.address,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Invalid unshield proof')
    })

    it('reverts on unknown Merkle root', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdcAddr, user2, dummyProof } = ctx
      const { amount, nullifier } = await shieldFirst(ctx)

      const fakeRoot = ethers.encodeBytes32String('fakeroot')

      await expect(
        shield.unshield(
          usdcAddr, amount, nullifier, fakeRoot,
          user2.address,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Unknown root')
    })
  })

  // ── privateTransfer() ─────────────────────────────────────

  describe('privateTransfer()', () => {

    async function shieldFirst(ctx: any) {
      const { shield, usdcAddr, user1, dummyProof } = ctx
      const amount     = ethers.parseUnits('1000', 6)
      const commitment = ethers.encodeBytes32String('commitment1')

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      return {
        amount,
        root:           await shield.currentRoot(),
        inNullifier:    ethers.encodeBytes32String('nullifier1'),
        outCommitment1: ethers.encodeBytes32String('outCommit1'),
        outCommitment2: ethers.encodeBytes32String('outCommit2'),
      }
    }

    it('emits PrivateTransfer event', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      await expect(
        shield.privateTransfer(
          inNullifier, outCommitment1, outCommitment2, root,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      )
        .to.emit(shield, 'PrivateTransfer')
        .withArgs(inNullifier, outCommitment1, outCommitment2)
    })

    it('marks input nullifier as spent', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      await shield.privateTransfer(
        inNullifier, outCommitment1, outCommitment2, root,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      expect(await shield.isSpent(inNullifier)).to.equal(true)
    })

    it('inserts two new output commitments into tree', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      const leafBefore = await shield.leafCount()

      await shield.privateTransfer(
        inNullifier, outCommitment1, outCommitment2, root,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      // Two new leaves inserted
      expect(await shield.leafCount())
        .to.equal(leafBefore + BigInt(2))
    })

    it('does not move any tokens', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, usdc, shieldAddr, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      const balBefore = await usdc.balanceOf(shieldAddr)

      await shield.privateTransfer(
        inNullifier, outCommitment1, outCommitment2, root,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const balAfter = await usdc.balanceOf(shieldAddr)
      expect(balAfter).to.equal(balBefore)
    })

    it('prevents reuse of input nullifier', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      await shield.privateTransfer(
        inNullifier, outCommitment1, outCommitment2, root,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      await expect(
        shield.privateTransfer(
          inNullifier,
          ethers.encodeBytes32String('newout1'),
          ethers.encodeBytes32String('newout2'),
          root,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('UTXO already spent')
    })

    it('reverts if ZK proof is invalid', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, transferVerifier, dummyProof } = ctx
      const {
        root, inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      await transferVerifier.setShouldPass(false)

      await expect(
        shield.privateTransfer(
          inNullifier, outCommitment1, outCommitment2, root,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Invalid transfer proof')
    })

    it('reverts on unknown Merkle root', async () => {
      const ctx = await loadFixture(deployFixture)
      const { shield, dummyProof } = ctx
      const {
        inNullifier, outCommitment1, outCommitment2
      } = await shieldFirst(ctx)

      const fakeRoot = ethers.encodeBytes32String('fakeroot')

      await expect(
        shield.privateTransfer(
          inNullifier, outCommitment1, outCommitment2, fakeRoot,
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Unknown root')
    })
  })

  // ── Security ──────────────────────────────────────────────

  describe('Security', () => {

    it('non-compliant user cannot shield', async () => {
      const { shield, attacker, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      await expect(
        shield.connect(attacker).shield(
          usdcAddr,
          ethers.parseUnits('1000', 6),
          ethers.encodeBytes32String('c1'),
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Okkult: compliance proof required')
    })

    it('treasury always receives correct fee', async () => {
      const { shield, usdc, user1, treasury, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amounts = [
        ethers.parseUnits('100', 6),
        ethers.parseUnits('999', 6),
        ethers.parseUnits('10000', 6),
      ]

      for (let i = 0; i < amounts.length; i++) {
        const amount      = amounts[i]
        const expectedFee = amount * BigInt(20) / BigInt(10000)
        const commitment  = ethers.encodeBytes32String(`c${i}`)
        const balBefore   = await usdc.balanceOf(treasury.address)

        await shield.connect(user1).shield(
          usdcAddr, amount, commitment,
          dummyProof.a, dummyProof.b, dummyProof.c
        )

        const balAfter = await usdc.balanceOf(treasury.address)
        expect(balAfter - balBefore).to.equal(expectedFee)
      }
    })

    it('same commitment can be inserted multiple times (no uniqueness check)', async () => {
      // Note: commitment uniqueness is enforced by ZK circuit, not contract
      // This test documents the expected behavior
      const { shield, usdc, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const amount     = ethers.parseUnits('500', 6)
      const commitment = ethers.encodeBytes32String('same')

      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      // Second shield with same commitment — contract allows,
      // ZK circuit prevents in practice
      await shield.connect(user1).shield(
        usdcAddr, amount, commitment,
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      expect(await shield.leafCount()).to.equal(2)
    })

    it('expired compliance proof blocks shield', async () => {
      const {
        shield, usdc, user1, okkultVerifier, usdcAddr, dummyProof
      } = await loadFixture(deployFixture)

      // Revoke compliance proof
      await okkultVerifier.setValidProof(user1.address, false)

      await expect(
        shield.connect(user1).shield(
          usdcAddr,
          ethers.parseUnits('1000', 6),
          ethers.encodeBytes32String('c1'),
          dummyProof.a, dummyProof.b, dummyProof.c
        )
      ).to.be.revertedWith('Okkult: compliance proof required')
    })
  })

  // ── View functions ────────────────────────────────────────

  describe('View functions', () => {

    it('isSpent returns false for unused nullifier', async () => {
      const { shield } = await loadFixture(deployFixture)
      const nullifier  = ethers.encodeBytes32String('unused')
      expect(await shield.isSpent(nullifier)).to.equal(false)
    })

    it('getRoot returns current Merkle root', async () => {
      const { shield } = await loadFixture(deployFixture)
      const root = await shield.getRoot()
      expect(root).to.not.equal(ethers.ZeroHash)
    })

    it('currentRoot changes after each shield', async () => {
      const { shield, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const root0 = await shield.currentRoot()

      await shield.connect(user1).shield(
        usdcAddr,
        ethers.parseUnits('100', 6),
        ethers.encodeBytes32String('c1'),
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const root1 = await shield.currentRoot()
      expect(root1).to.not.equal(root0)

      await shield.connect(user1).shield(
        usdcAddr,
        ethers.parseUnits('100', 6),
        ethers.encodeBytes32String('c2'),
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      const root2 = await shield.currentRoot()
      expect(root2).to.not.equal(root1)
    })

    it('isKnownRoot returns true for historical roots', async () => {
      const { shield, user1, usdcAddr, dummyProof } =
        await loadFixture(deployFixture)

      const root0 = await shield.currentRoot()

      await shield.connect(user1).shield(
        usdcAddr,
        ethers.parseUnits('100', 6),
        ethers.encodeBytes32String('c1'),
        dummyProof.a, dummyProof.b, dummyProof.c
      )

      // Old root should still be known
      expect(await shield.isKnownRoot(root0)).to.equal(true)
    })
  })
})
