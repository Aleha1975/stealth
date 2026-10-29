# Audit scope: private withdraw via a Zcash hop

Branch `zec-hop`. Stealth USDG -> NEAR Intents -> ZEC (t-addr of a throw-away wallet) -> shield -> random 2-10 min -> Orchard -> NEAR Intents -> recipient.

## In scope (lines)
| file | lines | role |
|---|---|---|
| web/zec-hop.js | 230 | state machine, key derivation, IndexedDB persistence, WebZjs calls |
| web/app.js (private section, ~70 of 374) | | UI glue: preview, start, resume banner |
| web/private-withdraw.js (`requestQuote` okDeposit param, `signTransferAuth`) | 194 | 1Click helpers, EIP-3009 signing (existing) |
| web/chains.js (`zcash`) | 41 | lightwalletd URL, ZEC asset id, limits |
| web/index.html (CSP meta) | | connect-src, worker-src, script-src |
| ops/build_webzjs.sh, web/vendor/webzjs/SHA256SUMS | 66 | reproducible wallet build, hashes |
| ops/nginx-stealth-zec.conf | 24 | COOP/COEP test path |
| web/vendor/bip39-english.txt (+ pinned sha256 in zec-hop.js and vendor/SHA256SUMS) | 2048 | word list |
Out of scope: WebZjs/librustzcash (pinned ChainSafe/WebZjs a50df944c32243cb8da9f86e7d52cb65ac926439, only its build and the 2 import patches), server relayer, existing stealth crypto.

## Trust assumptions
- lightwalletd proxy (`zcash.lightwalletd`): sees the hop wallet's viewing activity (IP, block ranges, tx broadcast) but cannot spend. A malicious proxy can lie about balances or censor; it cannot redirect funds.
- NEAR Intents 1Click: custodial for the duration of each swap. `requestQuote` refuses a quote whose amount, recipient, refund address or assets differ from the request. Its public /status reveals the recipient of each deposit address, so unlinkability comes only from the shielded pool in between.
- Our relayer: submits the stealth key's signed EIP-3009 transfer to the 1Click deposit address; it can censor or delay, not change recipient or amount (signed). It sees stealth address + deposit address.
- Browser: the stealth key and hop mnemonic live in page memory. Any XSS reads them (strict CSP is the control; see open point on `unsafe-eval`).

## Threat model
Observer correlating deposit and payout (amount/time): mitigated by shielding, random delay, fee-shaped amount change; not by volume (small anonymity set). Malicious/compromised lightwalletd, 1Click or relayer (above). Lost tab/storage mid-hop. Double payment on resume. Address reuse linking withdrawals. Quote tampering. Dust/too-small amounts stranding funds.

## Invariants (each has a test in server/test_zec_hop.mjs)
1. Funds are recoverable from `stealthPriv`: mnemonic = BIP39(keccak256(tag || stealthPriv)); counter n>0 only for a later hop from the same address. Frozen golden vector.
2. No address reuse: one mnemonic per withdrawal; account i holds attempt i, account i+1's t-address is attempt i's refund address; all distinct.
3. The signed authorization is persisted BEFORE it is sent; a resume re-sends the same nonce, never signs a second one while the stealth balance shows it was spent.
4. The raw ZEC transaction and wallet bytes are persisted BEFORE broadcast; broadcast and 1Click state are checked before acting on resume.
5. Refund paths: in-leg refund -> stealth address (state FAILED_IN); out-leg refund -> fresh t-address, shielded again, up to 3 attempts; otherwise FAILED with the hop wallet balances shown.
6. Too-small amounts are rejected before anything is sent. Dry mode can never sign, relay or advance past WAIT_T.
7. No secret (mnemonic, key) is written to the stored state.

## Not verified without funds
Real ZEC deposit address format from a non-dry ZEC-origin quote; `pczt_shield` + `pczt_sign` + `pczt_prove` on real UTXOs; Orchard->transparent send fee; txid byte order accepted by `/v0/deposit/submit`; real refund behaviour.

## eval in the wallet glue (resolved)
WebZjs' thread library calls js_sys::eval with exactly two strings: "self" and a script_path() snippet that reads the glue module URL from a stack trace. ops/build_webzjs.sh (third patch) answers both without eval (`self`, `import.meta.url`) and throws on anything else, so the page keeps script-src 'self' 'wasm-unsafe-eval' without 'unsafe-eval'. module_workers_polyfill.min.js (imported by wasm_thread) contains `new Function` for browsers without module workers; under this CSP it cannot run there.
Stored state: the IndexedDB record holds the wallet bytes (viewing keys and notes, not the seed: spending calls take the mnemonic each time) and the signed EIP-3009 authorization of the in-leg.

## v2 changes (branch `shielded-v2`, answer to ODA job 1088)
All tests are in `server/test_zec_hop.mjs` (section "v2", names start with the finding id). Run `node server/test_zec_hop.mjs` and `node server/test_zec_return.mjs`.

| finding | fix | tests |
|---|---|---|
| H-1 amount linkability (out = in - constant) | Split payout. After shielding, `planParts` splits the shielded balance into k parts (`splitAmounts`: random weights, each >= max(PART_FLOOR 150000, 1Click minimum) zatoshi, all different, none a multiple of 0.0001 ZEC), each with its own random time (`planDelays`), own 1Click quote and deposit, and its own fresh hop t-address as refund address (accounts allocated from `st.nextAcct`; never reused). Modes in `ctx.mode`: `fast` = 1..2 parts, last send 5..20 min; `private` = 2..4 parts, last send 1..6 h. A refunded part is shielded again from its refund account and retried (PART_TRIES = 2). State `v:2` keeps `parts[]`, `partIdx`; a state saved by the old code (no `parts`) runs the old single out-leg path unchanged. `remainingMs`, `progressText`, `hop-card.js` and the app preview show "payout i of k" and the per-mode ETA. | `H1 split ...`, `H1 plan ...`, `H1 modes ...`, `H1 private end-to-end ...`, `H1 parts ...`, `H1 refund address of every part ...`, `H1 a refunded part ...`, `H1 resume of an old single-out-leg state ...`, `H1 old state: out-leg refund ...`, `H1 ETA ...`, `H1 labels ...`, `H1 card ...` |
| M-1 second in-leg authorization on resume | The authorization is saved before it is sent and re-sent unchanged while `validBefore` is in the future. After a revert it is kept (it is public). A new one (new nonce) is signed only if `validBefore` has passed AND `ctx.authUsed(stealth, nonce)` (USDG `authorizationState`, `makeAuthUsed`) answers false; then a fresh quote is taken first. Answer true: the deposit exists, we only wait for 1Click. No answer / no checker: Halt, nothing signed. | `M1 the authorization is saved ... BEFORE`, `M1 expired ... IS used`, `M1 expired + unused`, `M1 expired but the chain check fails`, `M1 not expired`, `M1 a reverted deposit keeps ...`, `M1 authUsed = ...` |
| M-2 "unknown"/"mempool" broadcast errors counted as success | Only a clean return from `send_authorized_transactions` is success. Any error: `ctx.txKnown(txid)` (`makeTxKnown` -> `zec-return.txKnown`, lightwalletd `GetTransaction`): known = sent; not known = rethrow (the retry loop rebroadcasts, 4 tries, then error shown); cannot tell = Halt, the txid is not recorded as sent. | `M2 an error mentioning ...`, `M2 error but the txid IS known`, `M2 ambiguous error + ...` (x2), `M2 a real rejection ...`, `M2 zec-return.txKnown ...` |
| M-3 quotes / authorizations / raw txs never expire | Quote: `deadlineMs` from 1Click (required, validated). Authorization: `validBefore` (see M-1). Zcash transaction: `expiry` = tip + 40 blocks (ZIP-203 default) recorded at creation. SEND_OUT: a stale quote or an expired transaction is dropped only if the txid is provably not on the network (`txKnown` false) and 1Click has not seen the deposit; then wait for the expiry height and re-quote. Known: follow it. Unknown: Halt. | `M3 every stored artefact has a deadline ...`, `M3 expired out-quote ...`, `M3 transaction past its expiry height ...`, `M3 expired but the network already has ...`, `M3 expired and the network cannot say ...`, `M3 in-quote expired ...` |
| M-4 hop counter only in IndexedDB | `startHop` takes `n = max(local + 1, ctx.countPriorHops(stealth))`. The default (`makeCountPriorHops`) counts the token's `AuthorizationUsed` logs of the stealth address, so any device with the same chain view gets the same n. IndexedDB is a cache. If the chain cannot be read the hop is not started. | `M4 counter = chain count ...`, `M4 IndexedDB is only a cache ...`, `M4 chain unreadable ...`, `M4 a bogus count ...`, `M4 makeCountPriorHops ...` |
| M-5 client hands 1Click the cross-leg link | Requests share only protocol constants (`CONSTANT_FIELDS`); no referral/appFees/user/session field; refundTo and recipient differ per leg and per part; deadline has +-10 min random jitter; all 1Click calls are sent with `credentials: "omit"`, `referrerPolicy: "no-referrer"`; out-leg calls use `ctx.fetchFnOut` (inject a different network path, e.g. a proxy) when given. | `M5 the two requests share only ...`, `M5 out-leg calls go through ...`, `M5 every 1Click call ...`, `M5 all quote requests ...` |
| M-6 quotes not validated economically | `quoteInfoOf`: amountIn equals the request, amountOut > 0, 0 < minAmountOut <= amountOut and within 3% slippage (`SLIP_CAP_BPS`), deadline present and 5 min..2 h away, deposit address format (0x..40 hex for the stablecoin leg, t1.. for the ZEC leg) and not one of our own addresses. `projectedLoss`: at each out quote, value paid so far + this quote's rate on the ZEC still to send, against the amount that left the stealth address; above `ctx.maxLoss` (default 3%) the hop halts before sending anything. | `M6 a sane quote passes ...`, `M6 refused: ...` (x6), `M6 projected loss math`, `M6 round-trip loss above the cap ...`, `M6 the cap is configurable`, `M6 in-leg quote with a 50% slippage floor ...`, `M6 out-leg quote expiring in 30 s ...` |

### Remaining known limits after v2
- Same recipient address for all parts and one browser: an observer who groups the parts of one withdrawal (same recipient, same hour) sees in - fees again. Split payout only breaks the one-payout-equals-deposit match; k = 1 (fast mode may pick it) keeps the old fee-shaped match.
- 1Click still sees both legs from one client unless the integrator supplies `ctx.fetchFnOut` on another network path: same IP, user agent and TLS fingerprint link the quote requests; the deposit/payout timing and the shielded pool are the only break. Amounts are only roughly matchable (fees + ZEC price move), not exactly.
- The rate-based loss cap cannot price ZEC independently of 1Click: a quote that is wrong in both legs by the same factor is not caught. A ZEC price move during a long private-mode delay can push the projected loss over the cap; the hop then halts with the ZEC still shielded (resume later, or raise `maxLoss`).
- Private mode needs the tab open for 1-6 h (it is resumable, but a part is only sent while a tab runs it). Parts are sent in order; a slow payout delays the next one.
- `makeCountPriorHops` counts every EIP-3009 use of the address (also public withdraws), so n may skip values; it needs `eth_getLogs` from block 0 on the wallet's RPC (some providers refuse: the hop then does not start). Recovery on a fresh device must try n = 0..count.
- Zcash expiry height is assumed to be tip + 40 (the wallet default); WebZjs's real value, `GetTransaction` behaviour for unknown txids and the shielding path are not verified without funds (WebZjs currently cannot shield on mainnet after NU6.3; another effort upgrades it). All v2 tests use mocks.
- `authUsed` / `countPriorHops` run through the connected wallet's RPC in the app (CSP forbids direct RPC); a wallet on another chain makes them fail closed.
- The server/relayer was not changed; "already used" from the relayer is still how a repeated send of the same authorization is recognised.
