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
