/* Per-chain configuration. The ONLY place chain-specific values live (ids, token, explorer, contracts).
   Selection: ?chain=rh in the URL, else the chain named in a st:<chain>: link (?to=), else DEFAULT_CHAIN.
   Meta-address prefix is st:<key>: . */
export const DEFAULT_CHAIN = "base";
export const CHAINS = {
  base: {
    key: "base", name: "Base", chainId: 8453, chainHex: "0x2105",
    native: { symbol: "ETH", name: "Ether", decimals: 18 },
    token: { symbol: "USDC", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6, domainName: "USD Coin", domainVersion: "2" },
    explorer: "https://basescan.org", explorerName: "Basescan",
    stealthPay: "0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76",
    rpc: "https://mainnet.base.org",
    api: "/stealth-api",
    privateWithdraw: true,                               // withdraw through NEAR Intents 1Click (web/private-withdraw.js)
    oneClick: { assetId: "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near" },
  },
  rh: {
    key: "rh", name: "Robinhood Chain", chainId: 4663, chainHex: "0x1237",
    native: { symbol: "ETH", name: "Ether", decimals: 18 },
    token: { symbol: "USDG", address: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", decimals: 6, domainName: "Global Dollar", domainVersion: "1" },
    explorer: "https://robinhoodchain.blockscout.com", explorerName: "Blockscout",
    stealthPay: null,                                   // not deployed yet
    rpc: "https://rpc.mainnet.chain.robinhood.com",
    api: "/stealth-api/rh",                              // nginx: /stealth-api/rh/ -> RH indexer :3883 / relayer :3884
    privateWithdraw: true,
    oneClick: { assetId: "nep141:hood-0x5fc5360d0400a0fd4f2af552add042d716f1d168.omft.near" },
  },
};
/** Chain a meta-address was made for (st:<key>:0x...), or null if it has no prefix / unknown prefix. */
export function chainOfMeta(s) {
  const m = String(s).trim().match(/^st:([a-z0-9]+):/);
  return m && CHAINS[m[1]] ? CHAINS[m[1]] : null;
}
export function pickChain(search = (typeof location !== "undefined" ? location.search : "")) {
  const q = new URLSearchParams(search);
  return CHAINS[q.get("chain")] || chainOfMeta(q.get("to") || "") || CHAINS[DEFAULT_CHAIN];
}
/** wallet_addEthereumChain parameters. */
export const addChainParams = c => ({ chainId: c.chainHex, chainName: c.name, nativeCurrency: c.native, rpcUrls: [c.rpc], blockExplorerUrls: [c.explorer] });
