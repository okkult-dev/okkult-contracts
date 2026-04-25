import { expect }      from 'chai'
import { ethers }      from 'hardhat'
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers'

describe('RailgunAdapter', function () {
  this.timeout(60_000)

  async function deployFixture() {
    const [owner, attacker, randomUser] = await ethers.getSigners()

    // Mock ERC20
    const MockERC20 = await ethers.getContractFactory('MockERC20')
    const usdc = await MockERC20.deploy('USDC', 'USDC', 6)

    // Mock Railgun
    const MockRailgun = await ethers.getContractFactory('MockRailgun')
    const railgun = await MockRailgun.deploy()

    // Deploy RailgunAdapter
    const RailgunAdapter = await ethers.getContractFactory('RailgunAdapter')
    const adapter = await RailgunAdapter.deploy(
      owner.address,              // shield address (owner acts as shield)
      await railgun.getAddress()  // railgun address
    )

    const adapterAddr = await adapter.getAddress()
    const usdcAddr    = await usdc.getAddress()

    // Fund adapter and approve
    await usdc.mint(adapterAddr, ethers.parseUnits('100000', 6))
    await usdc.mint(owner.address, ethers.parseUnits('100000', 6))
    await usdc.connect(owner).approve(adapterAddr, ethers.MaxUint256)

    return {
      adapter, railgun, usdc,
      owner, attacker, randomUser,
      adapterAddr, usdcAddr
    }
  }

  describe('Deployment', () => {

    it('sets correct shield address', async () => {
      const { adapter, owner } = await loadFixture(deployFixture)
      expect(await adapter.okkultShield())
        .to.equal(owner.address)
    })

    it('sets correct railgun address', async () => {
      const { adapter, railgun } = await loadFixture(deployFixture)
      expect(await adapter.railgunPool())
        .to.equal(await railgun.getAddress())
    })
  })

  describe('shieldToRailgun()', () => {

    it('forwards tokens to Railgun', async () => {
      const { adapter, railgun, usdc, owner, usdcAddr } =
        await loadFixture(deployFixture)

      const amount    = ethers.parseUnits('1000', 6)
      const railBefore = await usdc.balanceOf(
        await railgun.getAddress()
      )

      await adapter.connect(owner).shieldToRailgun(
        usdcAddr, amount
      )

      const railAfter = await usdc.balanceOf(
        await railgun.getAddress()
      )
      expect(railAfter - railBefore).to.equal(amount)
    })

    it('reverts if caller is not OkkultShield', async () => {
      const { adapter, attacker, usdcAddr } =
        await loadFixture(deployFixture)

      await expect(
        adapter.connect(attacker).shieldToRailgun(
          usdcAddr,
          ethers.parseUnits('1000', 6)
        )
      ).to.be.revertedWith('Only shield')
    })

    it('emits correct event', async () => {
      const { adapter, owner, usdcAddr } =
        await loadFixture(deployFixture)

      const amount = ethers.parseUnits('1000', 6)

      await expect(
        adapter.connect(owner).shieldToRailgun(usdcAddr, amount)
      ).to.emit(adapter, 'ShieldedToRailgun')
        .withArgs(usdcAddr, amount)
    })
  })

  describe('unshieldFromRailgun()', () => {

    it('receives tokens from Railgun and forwards to recipient', async () => {
      const { adapter, usdc, owner, randomUser, usdcAddr } =
        await loadFixture(deployFixture)

      const amount    = ethers.parseUnits('1000', 6)
      const balBefore = await usdc.balanceOf(randomUser.address)

      await adapter.connect(owner).unshieldFromRailgun(
        usdcAddr, amount, randomUser.address
      )

      const balAfter = await usdc.balanceOf(randomUser.address)
      expect(balAfter - balBefore).to.equal(amount)
    })

    it('reverts if caller is not OkkultShield', async () => {
      const { adapter, attacker, randomUser, usdcAddr } =
        await loadFixture(deployFixture)

      await expect(
        adapter.connect(attacker).unshieldFromRailgun(
          usdcAddr,
          ethers.parseUnits('1000', 6),
          randomUser.address
        )
      ).to.be.revertedWith('Only shield')
    })
  })

  describe('Security', () => {

    it('cannot be called by arbitrary address', async () => {
      const { adapter, randomUser, usdcAddr } =
        await loadFixture(deployFixture)

      await expect(
        adapter.connect(randomUser).shieldToRailgun(
          usdcAddr,
          ethers.parseUnits('100', 6)
        )
      ).to.be.revertedWith('Only shield')
    })

    it('zero amount shield is rejected', async () => {
      const { adapter, owner, usdcAddr } =
        await loadFixture(deployFixture)

      await expect(
        adapter.connect(owner).shieldToRailgun(usdcAddr, 0)
      ).to.be.reverted
    })
  })
})
