export const CONTRACT_ADDRESSES = {
  ethereum: {

    // ── Okkult Core — Live on Mainnet ─────────────────────
    okkultShield:      '0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A' as `0x${string}`,
    shieldVerifier:    '0x8599c7665f4f8cb6ed2e80fbcb91ca57aefa437c' as `0x${string}`,
    unshieldVerifier:  '0x0bf8136db4c13925724f4f7f436911e2b285d7c9' as `0x${string}`,
    transferVerifier:  '0xe6b364ba301fe4dd3c70b60c36f0edd14324e4e8' as `0x${string}`,

    // ── Railgun Integration — Live on Mainnet ─────────────
    railgunAdapter:    '0xDe8d4FaD0c6b283f6FC997858388F6C995928065' as `0x${string}`,

    // ── Treasury ──────────────────────────────────────────
    treasury:          '0x641ca4b49098e11fe4735c58bafD4bbB781Eba49' as `0x${string}`,

    // ── Pending Deployment ────────────────────────────────
    okkultVerifier:    '' as `0x${string}`,
    complianceTree:    '' as `0x${string}`,
    nullifierRegistry: '' as `0x${string}`,
    okkultVote:        '' as `0x${string}`,
    okkultRelay:       '' as `0x${string}`,
    kultToken:         '' as `0x${string}`,

    // ── External Ecosystem ────────────────────────────────
    chainalysisOracle: '0x40C57923924B5c5c5455c48D93317139ADDaC8fb' as `0x${string}`,
    railgunShield:     '0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9' as `0x${string}`,
    uniswapV3Router:   '0xE592427A0AEce92De3Edee1F18E0157C05861564' as `0x${string}`,
    aavePool:          '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2' as `0x${string}`,

    // ── Supported Tokens ──────────────────────────────────
    usdc: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as `0x${string}`,
    weth: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2' as `0x${string}`,
    dai:  '0x6B175474E89094C44Da98b954EedeAC495271d0F' as `0x${string}`,
    wbtc: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599' as `0x${string}`,
    usdt: '0xdAC17F958D2ee523a2206206994597C13D831ec7' as `0x${string}`,
  }
} as const

export const ENS_NAMES = {
  'shield.okkult.eth':  '0x0377d05573acF3d7e0C2d1E13dCC47537143FC8A',
  'railgun.okkult.eth': '0xDe8d4FaD0c6b283f6FC997858388F6C995928065',
} as const

export const SUPPORTED_TOKENS = [
  { symbol: 'USDC', address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', decimals: 6  },
  { symbol: 'WETH', address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', decimals: 18 },
  { symbol: 'DAI',  address: '0x6B175474E89094C44Da98b954EedeAC495271d0F', decimals: 18 },
  { symbol: 'WBTC', address: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599', decimals: 8  },
  { symbol: 'USDT', address: '0xdAC17F958D2ee523a2206206994597C13D831ec7', decimals: 6  },
] as const
