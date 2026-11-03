# StealthPay v3: accepted residuals (deployed contracts, unchanged)

Contracts: Robinhood Chain `0x6f488f9036519b9eb0f3db98b76c2c1b02b08ac7`, Base `0xC07f54984AbDa1EF76DaB6F602270B76a04E916d`. The deployed bytecode matches `src/StealthPay.sol` including the metadata hash, so the source is NOT edited for wording: a changed comment changes the hash. This file and `server/deploy/README_ops.txt` carry the wider text instead. The NatSpec header of the contract keeps the original wording; where it differs, this file is the current statement.

## Griefing through `used[stealth]` (audit 1161 M-1) -- broader than the NatSpec says
- The NatSpec describes one case: a watcher pays `payToken(X)` one unit first. The real scope: `_fresh()` is shared by `payToken`, `payWithAuthorization` and `payETH`, and checks nothing about amount, token or fee. Any of the three can block a pending call of any of the three on the same stealth address. The cheapest is `payETH{value: 1}(X, ...)` (1 wei, no token, no approval).
- No sequencer cooperation is needed when the attacker already sees the request: a relayer, or anyone the signed request is shown to, sees `stealthAddress` in plain text before it is submitted.
- Cost to the payer: `payToken` / `payETH`: gas, then retry with a new one-time address. `payWithAuthorization`: the EIP-3009 signature is bound by `paymentNonce()` to that exact address, so a blocked address kills the signature for good; a new signature from the payer is the only recovery. No funds are lost in any case (the authorization moves nothing until the contract accepts it).
- Mitigation, off chain (no contract change):
  - relayer `/relay/pay` reads `used(stealth)` on the contract before it spends gas and answers `stealth address already used: ...` (honest refusal, charged to the network, not the signer);
  - the web client reads `used(stealth)` right before it asks the wallet for a signature or a transaction, and on a `NotFresh` / that refusal derives a new one-time address and asks again (gasless: up to two new addresses, short "please sign again" message; own gas: once, after the user agrees).
  - A window remains between the check and inclusion; the attack is then a lost signature (gasless) or a reverted transaction's gas (own gas), never lost funds.

## `feeRecipient == stealthAddress` (audit 1161 L-1)
The contract does not reject it; both legs reach the address and the `Paid` event announces only the net part. Neither our client nor our relayer ever sets it: the relayer refuses it (`bad destination`) and the client refuses to sign it. The indexer's `paid` column is the sum of every token `Transfer` to the stealth address in the receipt, so it reports the real amount (tested).

## Informational (no change)
- I-1 a contract under construction passes the `code.length == 0` check against itself: only its own funds move, no third party is affected; documented residual.
- I-2 ETH force-fed by `selfdestruct` stays in the contract: no sweep function exists; only the sender's own ETH.
- I-3 the comment "transient lock" in the source means a plain storage-slot lock. Wording is in the contract source and is left as is (bytecode match).
- I-4 the build uses `evm_version = cancun`; confirmed supported on Robinhood Chain by the live deployment and by the identical bytecode. Check again before deploying the same build to a new chain.
- I-5 `ephemeralPubKey` is checked for length and prefix only, not for curve membership; it is used off chain only. Our client always derives a valid point.
- I-6 the C2 guarantee (payWithAuthorization cannot be redirected) depends on the token implementing EIP-3009 as specified (R3, accepted).

## Hop counter start block b0 trusts the indexer (audit 1180 M-2, accepted)
The hop-wallet counter scan (`makeCountPriorHops`, web/zec-hop.js) starts 100 blocks before b0, the earliest announcement block of the stealth address in what the client's scan received (history pages and tail from our indexer, `foldRow` in web/chain-read.js; an unknown block makes b0 null = the safe full start). b0 therefore comes from the same component that finds the payments, and an address cannot authorize anything before its owner learned of it only as far as that view is complete.
- The local IndexedDB hop records are always merged: `startHop` uses `max(local record n + 1, chain count)`, so hops made on this device are never lost to a late b0.
- Residual: an indexer gap or outage, announcements before the indexer's start block, a lying indexer, or the same key used on another device/client before this indexer saw the address can give a b0 later than the first real use, and the count is then below the truth (a hop-wallet counter can be reused). No new network dependency was added to close it.
- The local records store only a creation TIME (`startedAt`, see `newState`), not a block, so b0 is not compared with them; mapping a time to a block would need another trusted source.

## The one pre-1181 Base hop wallet equals an rh hop wallet (audit 1182 L-2, accepted)
Before audit 1181 M-1 a hop on any chain used the legacy derivation, so the legacy hop wallet `k` of a stealth key is the same Zcash wallet on Base and on rh. Since 1181 only rh uses it; every other chain derives its own wallet (`HOP_TAG:<chain>:<n>`). The only non-rh hop that ever used the legacy derivation is ONE completed Base test hop of a test wallet (nothing to recover, no real Base users), so the Base lost-funds scan and the adopt path no longer have a legacy branch: a non-rh chain reads and writes chain-keyed records and wallets only, and rh `findHop` / `startHop` ignore a legacy-key record whose `st.chain` is not `rh` (1182 L-1).
- Residual: on rh, wallet `k` of that single test stealth address is the wallet the Base test hop used. A new rh hop of that address that picks `n = k` would reuse the mnemonic of the old Base hop (links the two hops; the old hop is finished and empty). Nothing else is affected, and no other address has such a hop.
- Not closed in code on purpose: a Base-side check in the rh startup would bring back the cross-chain legacy logic that audit 1182 L-1 traced the risk to.
