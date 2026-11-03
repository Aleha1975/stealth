# Fee benchmark, privacy and private-payment services (2026-11-03)

Read-only desk research. "Claim" = vendor or third-party statement, not verified on-chain. "not found" = no source located.

## 1. Table

| Service | Model | Fee | Where taken | Source |
|---|---|---|---|---|
| Railgun | Shielded pool (EVM) | 0.25% shield + 0.25% unshield (0.5% round trip); plus broadcaster gas fee at the broadcaster's advertised rate | On deposit and on withdraw, by contract (to DAO treasury); broadcaster fee paid in a note inside the tx | https://docs.railgun.org/wiki/learn/privacy-system/community-broadcasters.md ; https://blockworks.com/analytics/railgun |
| Tornado Cash (historical) | Fixed-denomination mixer | Relayer fee 0.3% (governance can change; small pools 0.1 ETH / 100 DAI no fee); deposit fee: none found | On withdraw; relayer fee is paid by relayer's staked TORN to protocol, relayer charges user own fee plus gas | https://git.hackliberty.org/TornadoCash/docs/commit/1d28f757b95a1985fd69d44317bdecf1e7c2c91e (docs mirror; secondary) |
| Privacy Pools (0xbow) | Pool with association sets | Vetting fee 0.5% on ETH, USDC, BOLD (0% on most other assets); relayer fee set by each relayer, cap 10% (5% DAI, USD1); self-relay = no relayer fee | Vetting on deposit (kept by Entrypoint owner); relayer fee on withdraw | https://l2beat.com/privacy/projects/privacy-pools |
| Umbra | Stealth address payments (EVM) | ETH "toll" per payment currently 0 ETH (owner can raise, no cap); token withdrawals via relayer, fee taken in the withdrawn token, amount not found; ETH withdrawals pay gas only. Solana fee: not found | On send (toll), on withdraw (relayer) | https://l2beat.com/privacy/projects/umbra |
| Fluidkey | Stealth-address smart accounts | Plans/fees: not found (pricing page 404; no figure in sources) | not found | https://www.fluidkey.com/pricing (404) |
| Zashi / Zodl (Zcash wallets) | Shielded ZEC wallet; swaps via NEAR Intents | No wallet-specific swap fee percent found. Reported: Zashi swaps settle through NEAR Intents; Zashi earned ~$0.76M of cumulative fees (claim, third-party blog) | Inside the swap quote (solver spread + app fee) | https://grenade.tw/blog/zec-near/ |
| NEAR Intents 1Click API | Swap API used by wallets | appFees: array of {recipient, fee in bps}, e.g. 100 = 1%; no limit or default stated on the API page. Optional "insured" flag +2 bps. Third-party (claim): protocol fee 0.0001%, extra 0.1-0.25% depending on key/site (figures conflict, 20-25 bps vs 10 bps) | Deducted from amountIn, paid to recipient account inside Intents | https://docs.near-intents.org/api-reference/oneclick/request-a-swap-quote ; https://phemex.com/academy/near-intents-explained-swap-fees ; https://coinpost.jp/crypto/near/intents/ |
| SwapKit | Aggregator (THORChain, Chainflip, Maya, NEAR Intents) | Own fee 0.15% up to $500k, 0.12% to $1M, 0.10% above; stablecoin-to-stablecoin 0.01%. Integrator affiliate fee 0-1000 bps on top (example 50 bps = $50 on $10,000) | Per swap, paid automatically to integrator address | https://swapkit.dev/pricing/ |
| THORChain affiliates | DEX | Total affiliate fees capped at 1000 bps (10%); tx rejected above; fee skipped if too small to cover outbound fee | Per swap, in memo | https://dev.thorchain.org/affiliate-guide/affiliate-fee-guide.html (via search summary) |
| Houdini Swap | Aggregator with "private" route | No official fee figure found. Third-party: fees 0.2-0.5% of volume (claim); private route ~1-2% slippage, 10-40 min (claim); vendor says no additional fee (claim) | Inside partner-exchange rate | https://paragraph.xyz/@metaera/houdini-swap-lock ; https://houdiniswap.medium.com/about |
| FixedFloat | Custodial swap | 1% (fixed rate) or 0.5% (float rate) plus network fee | In the rate | https://ff.io/faq |
| ChangeNOW | Custodial swap | 0.5-4% depending on rate type (third-party, not confirmed); partner commission from 0.4% | In the rate | https://www.businessofapps.com/affiliate/changenow/ |
| SimpleSwap | Custodial swap | "from 0.2%", varies with pair/liquidity (SimpleSwap's own comparison, claim) | In the rate | https://www.publish0x.com/simpleswap-blog/simpleswap-vs-changenow-2026-which-crypto-swap-service-fits-xgngzzk |
| Wasabi (coinjoin) | Bitcoin coinjoin | Coordinator fee removed in 2.2.0.0; client pays mining fee only; min coinjoin 5,000 sats | Mining fee | https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html |
| Trocador (Monero aggregator) | Aggregator | No own fee (claim); spread of partner exchanges ~1-3% (unreliable blog estimate) | In the rate | https://arnoldnakamura.codeberg.page/trocador-guide/ |
| Gelato Relay | Gas sponsorship | 10% of relayed gas cost (third-party, Astar docs; Gelato page unreachable, certificate expired) | On top of gas, billed via 1Balance | https://docs.astar.network/docs/build/zkEVM/integrations/account-abstraction/relayers/gelato-relay |
| Pimlico paymaster | ERC-4337 | 10% surcharge on sponsored gas, mainnet (third-party review; not confirmed in official docs) | On top of gas | https://stablecoininsider.org/best-paymaster-providers-gas-in-usdc/ |

## 2. Comparison for $10 / $100 / $1000 (USD)

Round-trip cost = fee to get funds in, move, and out. Our payment fee (0.05 fixed) is included only on our rows.

| Option | $10 | $100 | $1000 |
|---|---|---|---|
| Ours: payment only (0.05) | 0.05 (0.5%) | 0.05 (0.05%) | 0.05 (0.005%) |
| Ours: Standard withdraw (0 + payment 0.05) | 0.05 | 0.05 | 0.05 |
| Ours: Private fast now (0.1-1% spread + 0.05) | 0.06-0.15 | 0.15-1.05 | 1.05-10.05 |
| Ours: Private fast with planned 0.30% | 0.09-0.18 | 0.45-1.35 | 4.05-13.05 |
| Ours: Maximum (~7-12% at $9-20; assuming cost is mostly fixed ~$0.7-1.2, an estimate) | 0.70-1.20 | 0.7-1.2 (est.) | 0.7-1.2 (est.) |
| Railgun (0.25% + 0.25%, excl. broadcaster gas) | 0.05 | 0.50 | 5.00 |
| Privacy Pools USDC (0.5% vetting, excl. relayer fee; relayer cap 10%) | 0.05 + relayer | 0.50 + relayer | 5.00 + relayer |
| Tornado (0.3% relayer, historical) | 0.03 | 0.30 | 3.00 |
| FixedFloat float / fixed (0.5% / 1% + network) | 0.05 / 0.10 | 0.50 / 1.00 | 5 / 10 |
| SwapKit 0.15% (+ optional affiliate) | 0.015 | 0.15 | 1.50 |

Reading:
1. Payment and Standard (0.05 fixed) are cheaper than Railgun, Privacy Pools and Tornado at $100 and $1000, and equal to Railgun's % fee at $10.
2. Private fast without our fee is about the same as SwapKit (0.15%) at the low end of our spread range and similar to Railgun/FixedFloat at the high end.
3. Adding 0.30% puts Private fast at roughly Tornado's 0.3% relayer fee on top of the spread; total stays at or below FixedFloat float (0.5%) except at the upper spread range.
4. Maximum is the dearest at $10 (about 7-12%), because costs are fixed; at $100+ it is cheaper in % than any percentage-fee service (if the fixed-cost assumption holds; not measured by this research).
5. No comparable product found that charges a flat fee as small as 0.05; competitors charge by percentage.
6. Gas-sponsorship vendors take 10% of gas (claim); our 0.05 vs ~$0.01 gas is a 5x markup on gas but a small absolute sum.

## 3. Pricing options

A. Keep payment at 0.05 fixed; Standard stays 0; Private fast/Maximum add 0.30% via 1Click appFees (30 bps). Reason: 0.30% equals Tornado's relayer fee and is below Railgun's 0.5% round trip, FixedFloat float 0.5%, Privacy Pools 0.5% vetting. Simple, covers the "hides the link" value.

B. Option A plus a small Standard fee of 0.10% with minimum 0.05 (the fee leg already exists). Reason: Railgun, Privacy Pools charge 0.5% for similar direct privacy; 0.10% at $1000 = $1, still well below them. Risk: Standard is the cheap on-ramp; fee may push users to competitors at $10 (minimum 0.05 doubles cost there).

C. Tiered: payment 0.05; Standard 0; Private fast 0.20%; Maximum 0.50% with a floor of 0.25 USD. Reason: Maximum is already expensive at small sizes and users there are price-sensitive, whereas at $1000+ the fixed costs dilute (below 1%) and 0.5% is comparable to FixedFloat float. Appfee limits: our code allows 1..1000 bps; SwapKit and THORChain cap affiliates at 1000 bps, so our range matches, and 20-50 bps is the realistic span (the only cited examples: 50 bps in SwapKit, 100 bps in NEAR docs).

## 4. Not found

- Fluidkey plans and fees (pricing page 404).
- Umbra relayer fee amount, and any Umbra Solana fee.
- Zashi/Zodl swap fee percentage; NEAR Intents official protocol fee and typical appFees values integrators set (the API page gives no default or limit; third-party fee numbers conflict).
- Railgun broadcaster fee level (market-set, no figure).
- Houdini Swap official private-route fee.
- Official Gelato fee page (certificate error) and official Pimlico/Biconomy surcharge; ERC-4337 paymaster levels come from third parties only.
- Aztec/other privacy L2 fees; Tornado Nova fees; Maya affiliate fee specifics; Wasabi-style coordinator fees outside Wasabi (Wasabi's is removed).
- ChangeNOW and SimpleSwap official fee pages; Trocador official statement.
- Current actual Tornado relayer quotes (mirror docs may be outdated).
