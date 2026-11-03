/* Per-chain configuration. The ONLY place chain-specific values live (ids, token, explorer, contracts).
   Selection: ?chain=rh in the URL, else the chain named in a st:<chain>: link (?to=), else DEFAULT_CHAIN.
   Meta-address prefix is st:<key>: . */
export const DEFAULT_CHAIN = "rh";
export const CHAINS = {
  base: {
    key: "base", name: "Base", chainId: 8453, chainHex: "0x2105",
    native: { symbol: "ETH", name: "Ether", decimals: 18 },
    token: { symbol: "USDC", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6, domainName: "USD Coin", domainVersion: "2" },
    explorer: "https://basescan.org", explorerName: "Basescan",
    stealthPay: "0xC07f54984AbDa1EF76DaB6F602270B76a04E916d",   // v3, Base block 53408013, Sourcify exact match. v2 0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76: its payments are still scanned and withdrawn (neither depends on this address)
    rpc: "https://mainnet.base.org",
    block_ms: 2000,                                      // block time in ms (the measured value of server/chains.json): zec-hop.js treats an RPC tip more than 60 s of blocks behind the indexer head as lagging (audit 1182 L-3)
    rpcs: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],   // read fail-over order (zec-hop.js rpcCall); rpc stays the primary for everything else
    api: "/stealth-api/base",                            // nginx: /stealth-api/base/ -> Base v3 indexer :3893 / relayer :3894 (server/deploy/stealth-base.conf). The prod web copy keeps "/stealth-api" (v2, :3873/:3874)
    privateWithdraw: true,                               // withdraw through NEAR Intents 1Click (web/private-withdraw.js)
    oneClick: { assetId: "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near" },
  },
  rh: {
    key: "rh", name: "Robinhood Chain", chainId: 4663, chainHex: "0x1237",
    native: { symbol: "ETH", name: "Ether", decimals: 18 },
    token: { symbol: "USDG", address: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", decimals: 6, domainName: "Global Dollar", domainVersion: "1" },
    explorer: "https://robinhoodchain.blockscout.com", explorerName: "Blockscout",
    stealthPay: "0x6f488f9036519b9eb0f3db98b76c2c1b02b08ac7",   // v3, deployed 2026-10-29, Sourcify exact match
    rpc: "https://rpc.mainnet.chain.robinhood.com",
    block_ms: 104,                                       // measured (server/chains.json), see base
    rpcs: ["https://rpc.mainnet.chain.robinhood.com"],
    api: "/stealth-api/rh",                              // nginx: /stealth-api/rh/ -> RH indexer :3883 / relayer :3884
    privateWithdraw: true,
    oneClick: { assetId: "nep141:hood-0x5fc5360d0400a0fd4f2af552add042d716f1d168.omft.near" },
    eth: { assetId: "nep141:hood.omft.near" },           // native ETH next to USDG (pay, standard and private withdraw): only where this is set. 1Click: GET /v0/tokens -> nep141:hood.omft.near, 18 decimals
  },
};
/** Zcash leg of the private withdraw (web/zec-hop.js). lightwalletd = gRPC-web proxy; change this ONE value to switch to our own proxy. */
export const zcash = { lightwalletd: "https://zcash-mainnet.chainsafe.dev", network: "main", assetId: "nep141:zec.omft.near", decimals: 8, minIn: 132000n, orchardActivation: 1687104 };
/** Private-withdraw service fee, paid through 1Click `appFees` (basis points of the swap input) on the FIRST leg of a private withdraw only: Private fast = fastBps, Maximum = maxBps (Standard is free; the OUT leg and the ZEC return never carry it).
 *  OFF while appFeeRecipient is empty. appFeeRecipient is the NEAR account that receives the fee (never invented here: empty until the owner names one) - PUT THE ACCOUNT NAME BETWEEN THE QUOTES BELOW. */
export const privateFee = { fastBps: 20, maxBps: 30, appFeeRecipient: "loop_hole.near" };
/** The `appFees` array for a first-leg quote request of a route ("fast" | "max"), or null when the fee is off (the request then stays exactly as it was). An old-shape cfg { appFeeBps, appFeeRecipient } still works without a route. */
export function appFeesOf(cfg = privateFee, route) {
  const bps = !cfg ? 0 : route === "fast" ? cfg.fastBps ?? cfg.appFeeBps : route === "max" ? cfg.maxBps ?? cfg.appFeeBps : route === undefined ? cfg.appFeeBps : 0, to = String((cfg && cfg.appFeeRecipient) || "").trim();
  if (!bps || !to) return null;
  if (!Number.isInteger(bps) || bps < 1 || bps > 1000) throw new Error("bad appFeeBps (1..1000)");
  if (!/^[a-z0-9._-]{2,64}$/.test(to)) throw new Error("bad appFeeRecipient (a NEAR account)");
  return [{ recipient: to, fee: bps }];
}
/** The one short line that names the fee, for a bps value (20 -> "Loophole fee 0.2%"). */
export const feeLine = bps => "Loophole fee " + bps / 100 + "%";
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
export const addChainParams = c => ({ chainId: c.chainHex, chainName: c.name, nativeCurrency: { name: c.native.name, symbol: c.native.symbol, decimals: c.native.decimals }, rpcUrls: [c.rpc], blockExplorerUrls: [c.explorer] });

/** The asset a send moves: "ETH" = the chain's native coin (only where chain.eth is set), anything else = the chain stablecoin. A record saved before ETH existed has no asset field and so means the stablecoin.
 *  -> { key: "TOKEN"|"ETH", symbol, decimals, assetId (1Click), native } */
export function assetOf(chain, asset) {
  if (asset === "ETH") { if (!chain || !chain.eth) throw new Error("ETH is not available on " + ((chain && chain.name) || "this chain")); return { key: "ETH", symbol: chain.native.symbol, decimals: chain.native.decimals, assetId: chain.eth.assetId, native: true }; }
  const t = chain.token || {}; return { key: "TOKEN", symbol: t.symbol, decimals: t.decimals, assetId: chain.oneClick && chain.oneClick.assetId, native: false };
}
/** "ETH" for a saved record / state that moves the native coin, else "TOKEN". */
export const assetKey = rec => rec && rec.asset === "ETH" ? "ETH" : "TOKEN";
/** Exact text of a token amount (BigInt, no float): cut (never rounded up) to `digits` places, trailing zeros trimmed down to `min` places; "<0.000001" for a non-zero amount below the last place. */
export function fmtUnits(v, dec, digits = 6, min = 2) {
  const b = BigInt(v), neg = b < 0n, a = neg ? -b : b, u = 10n ** BigInt(dec), whole = a / u; let frac = (a % u).toString().padStart(dec, "0").slice(0, digits);
  if (a > 0n && whole === 0n && /^0*$/.test(frac)) return "<0." + "0".repeat(Math.max(0, digits - 1)) + "1";
  frac = frac.replace(/0+$/, "").padEnd(min, "0"); return (neg ? "-" : "") + whole + (frac ? "." + frac : "");
}
