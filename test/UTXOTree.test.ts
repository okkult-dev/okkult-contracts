import { expect }      from 'chai'
import { ethers }      from 'hardhat'
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers'

describe('UTXOTree', function () {
  this.timeout(60_000)

  async function deployFixture() {
    // UTXOTree is abstract — test via OkkultShield
    // Deploy a TestableUTXOTree that exposes internal functions
    const TestUTXOTree = await ethers.getContractFactory('TestUTXOTree')
    const tree = await TestUTXOTree.deploy()

    return { tree }
  }

  describe('Initialization', () => {

    it('starts with zero leaves', async () => {
      const { tree } = await loadFixture(deployFixture)
      expect(await tree.leafCount()).to.equal(0)
    })

    it('initializes with non-zero root', async () => {
      const { tree } = await loadFixture(deployFixture)
      const root = await tree.currentRoot()
      expect(root).to.not.equal(ethers.ZeroHash)
    })

    it('initial root is known', async () => {
      const { tree } = await loadFixture(deployFixture)
      const root = await tree.currentRoot()
      expect(await tree.isKnownRoot(root)).to.equal(true)
    })
  })

  describe('insert()', () => {

    it('increments leaf count on each insert', async () => {
      const { tree } = await loadFixture(deployFixture)

      for (let i = 1; i <= 5; i++) {
        const leaf = ethers.encodeBytes32String(`leaf${i}`)
        await tree.testInsert(leaf)
        expect(await tree.leafCount()).to.equal(i)
      }
    })

    it('updates root on each insert', async () => {
      const { tree } = await loadFixture(deployFixture)

      const root0 = await tree.currentRoot()
      await tree.testInsert(ethers.encodeBytes32String('leaf1'))
      const root1 = await tree.currentRoot()
      await tree.testInsert(ethers.encodeBytes32String('leaf2'))
      const root2 = await tree.currentRoot()

      expect(root1).to.not.equal(root0)
      expect(root2).to.not.equal(root1)
      expect(root2).to.not.equal(root0)
    })

    it('emits LeafInserted event', async () => {
      const { tree } = await loadFixture(deployFixture)
      const leaf = ethers.encodeBytes32String('leaf1')

      await expect(tree.testInsert(leaf))
        .to.emit(tree, 'LeafInserted')
        .withArgs(leaf, 0, await tree.currentRoot())
    })

    it('stores all historical roots', async () => {
      const { tree } = await loadFixture(deployFixture)

      const roots: string[] = []
      roots.push(await tree.currentRoot())

      for (let i = 0; i < 10; i++) {
        await tree.testInsert(
          ethers.encodeBytes32String(`leaf${i}`)
        )
        roots.push(await tree.currentRoot())
      }

      // All historical roots should be known
      for (const root of roots) {
        expect(await tree.isKnownRoot(root)).to.equal(true)
      }
    })

    it('different leaves produce different roots', async () => {
      const { tree } = await loadFixture(deployFixture)

      // Reset to fresh state by deploying new tree
      const TestUTXOTree = await ethers.getContractFactory('TestUTXOTree')
      const tree2 = await TestUTXOTree.deploy()

      await tree.testInsert(ethers.encodeBytes32String('leafA'))
      await tree2.testInsert(ethers.encodeBytes32String('leafB'))

      expect(await tree.currentRoot())
        .to.not.equal(await tree2.currentRoot())
    })
  })

  describe('isKnownRoot()', () => {

    it('returns false for unknown root', async () => {
      const { tree } = await loadFixture(deployFixture)
      const fakeRoot = ethers.encodeBytes32String('fake')
      expect(await tree.isKnownRoot(fakeRoot)).to.equal(false)
    })

    it('returns true for current root', async () => {
      const { tree } = await loadFixture(deployFixture)
      const root = await tree.currentRoot()
      expect(await tree.isKnownRoot(root)).to.equal(true)
    })

    it('returns true for historical roots', async () => {
      const { tree } = await loadFixture(deployFixture)

      const oldRoot = await tree.currentRoot()
      await tree.testInsert(ethers.encodeBytes32String('leaf1'))
      await tree.testInsert(ethers.encodeBytes32String('leaf2'))

      // Old root still known
      expect(await tree.isKnownRoot(oldRoot)).to.equal(true)
    })
  })
})
