/* Hidden Zcash hop for the private withdraw: stealth USDG -> (NEAR Intents) -> ZEC t-addr of a throw-away wallet -> shield -> random delay -> Orchard -> (NEAR Intents) -> recipient.
   One resumable state machine per withdrawal, persisted in IndexedDB together with the wallet bytes. Pure helpers first, IO below.
   Keys: the hop wallet's BIP39 mnemonic = f(stealthPriv, n) (see entropyFor), so every coin is recoverable from keys the user already has.
   Accounts 0..MAX_OUT of that wallet: account i holds the funds of out-attempt i, account i+1's t-address is that attempt's refund address (no address is used twice).
   Nothing here touches the DOM. Injected: fetchFn, sleep, store, loadZjs (WebZjs), words, waitReceipt, balance, rand, onProgress. */
import { keccak, unhex, hex } from "./stealth-crypto.js";
import * as PW from "./private-withdraw.js";
import { postRelay } from "./relay-post.js";
import { zcash as ZC } from "./chains.js";

export const STEPS = ["QUOTE_IN", "DEPOSIT_IN", "WAIT_T", "SHIELD", "DELAY", "QUOTE_OUT", "SEND_OUT"];
export const DONE_STEPS = new Set(["DONE", "FAILED_IN", "FAILED"]);
export const HOP_TAG = "stealth-zec-hop/v1", MAX_OUT = 3, PART_TRIES = 2, PENDING = "PENDING_DEPOSIT", ETA_MIN = 35, T_CONFS = 10;   // T_CONFS: WebZjs spends transparent coins received from others only after 10 confirmations (ZIP-315)
export const STEP_MIN = { QUOTE_IN: 0.5, DEPOSIT_IN: 4, WAIT_T: 12, SHIELD: 3, DELAY: 6, QUOTE_OUT: 0.5, SEND_OUT: 8 };   // typical minutes per step (sum 34)
/** Payout modes (audit H-1): the shielded balance is paid out in k parts of random size, each with its own random delay, quote and deposit.
 *  fast = 1..2 parts, 5..20 min in total; private = 2..4 parts spread over 1..6 h. totalMin/totalMax: minutes from "shielded" to the LAST part's send time. */
export const MODES = { fast: { kMin: 1, kMax: 2, totalMin: 5, totalMax: 20 }, private: { kMin: 2, kMax: 4, totalMin: 60, totalMax: 360 } };
export const modeOf = m => MODES[m] || MODES.fast;
export const accountsFor = mode => 1 + modeOf(mode).kMax * PART_TRIES;            // account 0 holds the shielded funds, every part attempt gets a fresh refund account
const MIN = 60_000, BASE_MIN = Object.values(STEP_MIN).reduce((a, b) => a + b, 0) - STEP_MIN.DELAY - STEP_MIN.QUOTE_OUT - STEP_MIN.SEND_OUT;
/** [low, high] minutes for the whole private transfer of a mode (steps before the delay + the delay + sequential sends). */
export const etaRangeMin = mode => { const m = modeOf(mode), send = STEP_MIN.QUOTE_OUT + STEP_MIN.SEND_OUT; return [Math.round(BASE_MIN + m.totalMin + send), Math.round(BASE_MIN + m.totalMax + send * m.kMax)]; };
export const etaLabel = mode => { const [a, b] = etaRangeMin(mode), h = x => (x / 60).toFixed(1).replace(/\.0$/, ""); return b < 120 ? a + "–" + b + " min" : a < 120 ? a + " min–" + h(b) + " h" : h(a) + "–" + h(b) + " h"; };
/** Time left for an unfinished hop, in ms: rest of the current step (min 1 min) + typical time of the later steps. DELAY uses its exact end; with payout parts the parts are simulated one after the other
 *  (each waits for its own time, then needs a quote and a send). Never below 1 min while unfinished, 0 once finished. */
export function remainingMs(st, now = Date.now()) {
  const i = STEPS.indexOf(st.step); if (i < 0) return 0;
  const sm = k => STEP_MIN[k] * MIN, send = sm("QUOTE_OUT") + sm("SEND_OUT"), di = STEPS.indexOf("DELAY"), parts = Array.isArray(st.parts) ? st.parts : null;
  const cur = st.step === "DELAY" && st.delayUntil ? Math.max(0, st.delayUntil - now) : Math.max(MIN, sm(st.step) - (now - (st.stepAt || now)));
  if (!parts) {
    const m = st.mode ? modeOf(st.mode) : null, dl = m ? (m.totalMin + m.totalMax) / 2 * MIN + ((m.kMin + m.kMax) / 2 - 1) * send : sm("DELAY");   // plan not made yet: typical delay of the mode
    return Math.max(MIN, cur + STEPS.slice(i + 1).reduce((a, k) => a + (k === "DELAY" ? dl : sm(k)), 0));
  }
  let t = now, j = st.partIdx || 0;
  if (i < di) { t += cur + STEPS.slice(i + 1, di).reduce((a, k) => a + sm(k), 0) + sm("DELAY") + send; j++; }      // a refunded part is shielded again, waits a short delay and is sent
  else if (st.step === "DELAY") { t = Math.max(t, (parts[j] || {}).at || t) + send; j++; }
  else { t += cur + (st.step === "QUOTE_OUT" ? sm("SEND_OUT") : 0); j++; }
  for (; j < parts.length; j++) t = Math.max(t, parts[j].at || t) + send;
  return Math.max(MIN, t - now);
}
export const WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
export const SHIELD_FEE = 15000n, DRY_T = "t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ";   // DRY_T: any valid t-address, used only in dry (preview) quotes
const RESERVE = 20000n, MIN_SHIELD = 20000n;       // zatoshi: kept back for the out fee (ZIP-317 ~15000) / dust threshold / shield fee
export class Halt extends Error {}                                      // stop and show: no automatic retry, the user can resume
const enc = s => new TextEncoder().encode(s), isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), isT = a => /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(a || "");
const sha256 = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const sleepMs = ms => new Promise(r => setTimeout(r, ms));

// ---------------------------------------------------------------- pure helpers
/** 32 bytes = keccak256(tag || stealthPriv). n > 0 (a second hop from the same address, e.g. after a partial withdraw) uses tag + ":" + n, so no mnemonic is ever reused. */
export const entropyFor = (priv, n = 0) => keccak(Uint8Array.from([...enc(HOP_TAG + (n ? ":" + n : "")), ...unhex(priv)])).slice(0, 32);
/** BIP39 (English) 24 words from 32 bytes of entropy: 256 bits + first 8 bits of sha256 = 264 bits = 24 x 11. */
export async function mnemonicFromEntropy(ent, words) {
  if (ent.length !== 32 || words.length !== 2048) throw new Error("need 32 bytes and the 2048-word list");
  let bits = ""; for (const b of [...ent, (await sha256(ent))[0]]) bits += b.toString(2).padStart(8, "0");
  return Array.from({ length: 24 }, (_, i) => words[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]).join(" ");
}
export const mnemonicFor = async (priv, words, n = 0) => mnemonicFromEntropy(entropyFor(priv, n), words);
/** BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, no passphrase): only needed to sign the shield PCZT. */
export async function mnemonicSeed(m) {
  const k = await crypto.subtle.importKey("raw", enc(m.normalize("NFKD")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt: enc("mnemonic"), iterations: 2048 }, k, 512));
}
export async function loadWords(fetchFn = fetch, url = new URL("./vendor/bip39-english.txt", import.meta.url)) {
  const t = await (await fetchFn(url)).text();
  if (hex(await sha256(enc(t))).slice(2) !== WORDLIST_SHA256) throw new Error("the BIP39 word list does not match its pinned hash");
  return t.trim().split("\n");
}
/** M-5: nothing is shared between the two legs but protocol constants. No referral / appFees / user id fields exist here; refundTo and recipient differ per leg and per part;
 *  the quote deadline is 1 h +- 10 min of random jitter so it is no fingerprint either. The remaining links are listed in audit/zec-hop-scope.md. */
const reqOf = ({ originAsset, destAsset, amount, recipient, refundTo, dry, now = Date.now(), rand = Math.random }) => {
  if (!(amount > 0n)) throw new Error("bad amount");
  return { dry: !!dry, swapType: "EXACT_INPUT", slippageTolerance: 100, originAsset, depositType: "ORIGIN_CHAIN", destinationAsset: destAsset, amount: amount.toString(), refundTo,
    refundType: "ORIGIN_CHAIN", recipient, recipientType: "DESTINATION_CHAIN", deadline: new Date(now + 3600_000 + Math.floor((rand() - 0.5) * 1200_000)).toISOString(), confidentiality: "public" };
};
/** Fields (name=value) that two quote requests have in common; only protocol constants may show up (M-5 test). */
export const sharedFields = (a, b) => Object.keys(a).filter(k => k in b && JSON.stringify(a[k]) === JSON.stringify(b[k])).map(k => k + "=" + JSON.stringify(a[k]));
export const CONSTANT_FIELDS = new Set(["dry", "swapType", "slippageTolerance", "depositType", "refundType", "recipientType", "confidentiality"]);
/** In-leg: chain stablecoin -> ZEC paid to the hop's t-address; refund goes back to the stealth address. */
export function reqIn({ chain, amount, tAddr, stealth, dry, now, rand }) {
  if (!chain.oneClick || !isT(tAddr) || !isAddr(stealth)) throw new Error("bad address");
  return reqOf({ originAsset: chain.oneClick.assetId, destAsset: ZC.assetId, amount, recipient: tAddr, refundTo: stealth, dry, now, rand });
}
/** Out-leg: ZEC -> stablecoin on `dest` to the final recipient; a ZEC-origin refund must be a Zcash t-address (a fresh one of the hop wallet). */
export function reqOut({ dest, amount, recipient, refundT, dry, now, rand }) {
  if (!dest.oneClick || !isAddr(recipient) || !isT(refundT)) throw new Error("bad address");
  return reqOf({ originAsset: ZC.assetId, destAsset: dest.oneClick.assetId, amount, recipient, refundTo: refundT, dry, now, rand });
}
export const outAmount = (orchard, reserve = RESERVE) => (orchard - reserve >= ZC.minIn ? orchard - reserve : 0n);
export const okSize = zatsOut => zatsOut >= ZC.minIn + SHIELD_FEE + RESERVE + 25000n;     // the ZEC we will get must survive the shield fee, the out reserve and still reach the 1Click minimum
export const delayMs = (rand = Math.random) => Math.floor((2 + 8 * rand()) * 60_000);       // 2..10 min
/** Conservative (too early) Zcash height for a unix time: assumes 60 s blocks (real ~75 s) and 500 blocks of slack. */
export const birthdayFromTime = (tSec, tip, nowSec = Date.now() / 1000) => Math.max(ZC.orchardActivation, tip - Math.ceil(Math.max(0, nowSec - tSec) / 60) - 500);
export const newState = ({ stealth, chain, dest, recipient, amount, dry, n = 0, mode = "fast", now = Date.now() }) => ({ v: 2, n, stealth: stealth.toLowerCase(), chain: chain.key, dest: dest.key, recipient, amount: amount.toString(),
  dry: !!dry, step: "QUOTE_IN", attempt: 0, reserve: RESERVE.toString(), startedAt: now, err: null, mode: MODES[mode] ? mode : "fast", nAccts: accountsFor(mode), nextAcct: 1 });
export const afterIn = status => (status === "SUCCESS" ? { step: "WAIT_T" } : { step: "FAILED_IN", result: status });
/** Legacy (v1 state, one out-leg). */
export const afterOut = (st, status) => status === "SUCCESS" ? { step: "DONE" }
  : status === "REFUNDED" && st.attempt + 1 < MAX_OUT ? { step: "WAIT_T", attempt: st.attempt + 1, tSeenHeight: null, tSeenAt: null, outQuote: null, outRaw: null, outTx: null }   // ZEC came back to account attempt+1's t-address: shield and send again
  : { step: "FAILED", result: status };
/** After the payout part st.partIdx ended with `status`: next part, DONE, shield the refund again (it came back to the part's refund account) or FAILED. */
export function afterPart(st, status) {
  const i = st.partIdx || 0, p = st.parts[i];
  if (status === "SUCCESS") return i + 1 < st.parts.length ? { step: "DELAY", partIdx: i + 1, delayUntil: st.parts[i + 1].at } : { step: "DONE" };
  if (status === "REFUNDED" && (p.tries || 0) + 1 < PART_TRIES && p.refundAcct != null) return { step: "WAIT_T", attempt: p.refundAcct, tSeenHeight: null, tSeenAt: null };
  return { step: "FAILED", result: status };
}
export const partsLabel = st => Array.isArray(st.parts) && st.parts.length > 1 ? "payout " + ((st.partIdx || 0) + 1) + " of " + st.parts.length : "";
export const etaText = st => st.mode ? etaLabel(st.mode) : ETA_MIN + " min";
export const progressText = st => DONE_STEPS.has(st.step) ? (st.step === "DONE" ? "Private transfer done" : "Private transfer stopped")
  : "Private transfer: step " + (STEPS.indexOf(st.step) + 1) + "/" + STEPS.length + (partsLabel(st) ? " (" + partsLabel(st) + ")" : "") + " · keep this tab open · ~" + etaText(st);
export function recoveryText(st) {
  if (st.step === "DONE") return "Done.";
  if (st.step === "FAILED_IN") return "The first swap ended as " + st.result + ". The money is back on the stealth address (minus the refund fee).";
  if (st.step === "FAILED") { const n = Array.isArray(st.parts) ? st.parts.filter(p => p.status === "SUCCESS").length : 0;
    return "The last swap ended as " + st.result + (st.outQuote ? " (deposit address " + st.outQuote.depositAddress + ")" : "") + (n ? ". " + n + " of " + st.parts.length + " payouts were already made" : "") + ". Any ZEC left is in the hop wallet, which you can rebuild from this payment's key."; }
  return (st.err ? st.err + ". " : "") + "Nothing is lost: press Resume to continue from step " + (STEPS.indexOf(st.step) + 1) + "/" + STEPS.length + ".";
}
export async function retry(fn, { tries = 4, base = 2000, sleep = sleepMs } = {}) {
  for (let i = 1; ; i++) try { return await fn(); } catch (e) { if (e instanceof Halt || i >= tries) throw e; await sleep(base * 3 ** (i - 1)); }
}

// ---------------------------------------------------------------- split payout (H-1)
export const PART_FLOOR = 150000n, ROUND = 10000n;            // zatoshi: a part is never below this (nor below the 1Click minimum), and never a multiple of ROUND (0.0001 ZEC)
const pickInt = (rand, n) => Math.min(n - 1, Math.floor(rand() * n));
/** total (BigInt zatoshi) -> k random amounts, each >= floor, sum == total, all different, none a round number (k = 1 keeps the total). */
export function splitAmounts(total, k, floor, rand = Math.random) {
  if (!(k >= 1) || total < floor * BigInt(k)) throw new Error("amount too small to split");
  if (k === 1) return [total];
  const w = Array.from({ length: k }, () => 0.5 + rand()), sw = w.reduce((a, b) => a + b, 0), spare = total - floor * BigInt(k);
  const a = w.map(x => floor + BigInt(Math.floor(Number(spare) * x / sw)));
  a[pickInt(rand, k)] += total - a.reduce((x, y) => x + y, 0n);                           // rounding remainder
  const badAt = (x, i) => x % ROUND === 0n || a.some((y, j) => j !== i && y === x), bad = () => a.some(badAt);
  for (let it = 0; bad() && it < 200; it++) {
    const i = a.findIndex(badAt), j = (i + 1 + pickInt(rand, k - 1)) % k, d = BigInt(1 + pickInt(rand, 97));
    if (a[j] - d >= floor) { a[i] += d; a[j] -= d; } else if (a[i] - d >= floor) { a[i] -= d; a[j] += d; }
  }
  if (bad()) throw new Error("could not make the parts irregular");
  return a;
}
/** k ascending send times (ms after the shield finished): the last one is a random total in the mode's range, the others split it by random weights. */
export function planDelays(mode, k, rand = Math.random) {
  const m = modeOf(mode), T = (m.totalMin + rand() * (m.totalMax - m.totalMin)) * MIN, w = Array.from({ length: k }, () => 0.6 + 0.8 * rand()), sw = w.reduce((a, b) => a + b, 0);
  let c = 0; return w.map((x, i) => { c += x; return i === k - 1 ? Math.round(T) : Math.round(T * c / sw); });
}
/** The payout plan from the shielded balance `orchard`: k from the mode, every part pays its own fee reserve; k shrinks if the balance is too small for k parts. */
export function planParts({ orchard, reserve = RESERVE, mode = "fast", rand = Math.random, now = Date.now(), acct = 0 }) {
  const m = modeOf(mode), floor = PART_FLOOR > ZC.minIn ? PART_FLOOR : ZC.minIn; let k = m.kMin + pickInt(rand, m.kMax - m.kMin + 1);
  let amounts, dist;
  for (;; k--) {                                                                           // k shrinks until the balance can carry k parts of at least `floor` each
    dist = orchard - reserve * BigInt(k);
    if (dist >= floor * BigInt(k)) { try { amounts = splitAmounts(dist, k, floor, rand); break; } catch (e) { if (k === 1) throw e; } }
    if (k === 1) throw new Halt("only " + orchard + " zatoshi are shielded, below the 1Click minimum; they stay in the hop wallet");
  }
  if (k === 1 && amounts[0] % ROUND === 0n && amounts[0] - ROUND >= floor) amounts = [amounts[0] - BigInt(1 + pickInt(rand, 9999))];   // leave a few zatoshi behind: no round amount
  const off = planDelays(mode, k, rand);
  return amounts.map((a, i) => ({ amount: a.toString(), at: now + off[i], acct, tries: 0, reserve: reserve.toString(), quote: null, raw: null, tx: null, expiry: null, refundAcct: null, status: null }));
}

// ---------------------------------------------------------------- quote validation (M-6)
export const MAX_LOSS = 0.03, SLIP_CAP_BPS = 300, QUOTE_MIN_LEFT_MS = 5 * MIN, QUOTE_MAX_LEFT_MS = 2 * 3600_000, TX_EXPIRY_DELTA = 40;   // TX_EXPIRY_DELTA: blocks a Zcash wallet transaction stays valid (ZIP-203 default)
/** Checks a 1Click quote against the request and economic sanity; returns the fields we keep. Throws Halt (never retried) with nothing sent. */
export function quoteInfoOf(j, req, { now = Date.now(), minLeft = QUOTE_MIN_LEFT_MS, maxLeft = QUOTE_MAX_LEFT_MS, slipBps = SLIP_CAP_BPS } = {}) {
  const q = j && j.quote; if (!q) throw new Halt("NEAR Intents returned no quote");
  const big = (v, n) => { if (!/^[0-9]+$/.test(String(v))) throw new Halt("the quote's " + n + " is not a number"); return BigInt(v); };
  const aIn = big(q.amountIn, "amountIn"), aOut = big(q.amountOut, "amountOut"), mOut = big(q.minAmountOut == null ? q.amountOut : q.minAmountOut, "minAmountOut");
  if (aIn !== BigInt(req.amount)) throw new Halt("the quote changed the amount; refusing");
  if (aOut <= 0n || mOut <= 0n || mOut > aOut) throw new Halt("the quote's amounts are inconsistent (out " + aOut + ", min " + mOut + ")");
  if (mOut * 10000n < aOut * BigInt(10000 - slipBps)) throw new Halt("the quote allows more than " + slipBps / 100 + "% slippage; refusing");
  const dl = Math.min(...[(j.quoteRequest || {}).deadline, q.deadline].map(Date.parse).filter(Number.isFinite)), left = dl - now;   // the earlier of our request deadline and 1Click's (which can be days away)
  if (!Number.isFinite(dl)) throw new Halt("the quote has no deadline");
  if (left < minLeft) throw new Halt("the quote expires too soon (" + Math.round(left / 1000) + " s)"); if (left > maxLeft) throw new Halt("the quote's deadline is unreasonably far away");
  const dep = q.depositAddress || null;
  if (!req.dry) {
    const fromZec = req.originAsset === ZC.assetId, okAddr = fromZec ? isT(dep) : isAddr(dep);
    if (!okAddr) throw new Halt("the quote has no valid deposit address");
    if (String(dep).toLowerCase() === String(req.refundTo).toLowerCase() || String(dep).toLowerCase() === String(req.recipient).toLowerCase()) throw new Halt("the quote's deposit address equals our own address; refusing");
  }
  return { depositAddress: dep, amountIn: q.amountIn, amountOut: q.amountOut, minOut: mOut.toString(), deadlineMs: dl };
}
/** Projected loss (0..1, negative = gain) of the whole transfer: value paid out so far + this quote's rate on the ZEC still to be sent, against the amount that left the stealth address. */
export function projectedLoss({ amountIn, inDec, outDec, paidOut, rate, zatsLeft }) {
  const out = (Number(paidOut) + rate * Number(zatsLeft)) / 10 ** outDec, inn = Number(amountIn) / 10 ** inDec; return 1 - out / inn;
}

// ---------------------------------------------------------------- chain reads (M-1, M-4) and lightwalletd (M-2); all injectable in ctx
// Public RPCs (and wallets in front of them) answer 429 / "client error" under load: retry with backoff before giving up.
export let RPC_RETRY = { tries: 4, base: 1500 };
const rpcCall = (fetchFn, url, method, params) => retry(async () => {
  const r = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json().catch(() => ({})); if (!r.ok || j.error || j.result === undefined) throw new Error("rpc " + method + " failed: " + ((j.error && j.error.message) || r.status)); return j.result;
}, RPC_RETRY);
export const setRpcRetry = o => { RPC_RETRY = o; };
const pad32 = h => String(h).replace(/^0x/, "").toLowerCase().padStart(64, "0");
export const AUTH_STATE_SELECTOR = "0xe94a0102";                      // authorizationState(address,bytes32) of EIP-3009
export const AUTH_USED_TOPIC = hex(keccak(enc("AuthorizationUsed(address,bytes32)")));
/** ctx.authUsed(authorizer, nonce) -> bool: has this EIP-3009 nonce been consumed on chain (USDG authorizationState view call)? */
export const makeAuthUsed = (chain, fetchFn = fetch) => async (authorizer, nonce) => {
  const r = await rpcCall(fetchFn, chain.rpc, "eth_call", [{ to: chain.token.address, data: AUTH_STATE_SELECTOR + pad32(authorizer) + pad32(nonce) }, "latest"]);
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(r)) throw new Error("unexpected authorizationState answer"); return BigInt(r) !== 0n;
};
/** ctx.countPriorHops(stealth) -> number of AuthorizationUsed events of this stealth address on the token (every private withdraw spends exactly one). Counts every EIP-3009 use of the address, so it
 *  can only over-count (e.g. after a public withdraw), which skips a counter value but never reuses one. Same answer on every device. */
// RPCs cap eth_getLogs at 10M blocks per call; a stealth address cannot authorize anything before the pay contract existed, so scan from there in windows.
export const LOG_SPAN = 2_000_000, PAY_FROM_BLOCK = { rh: 100_761_230 };
export const makeCountPriorHops = (chain, fetchFn = fetch) => async stealth => {
  const tip = Number(await rpcCall(fetchFn, chain.rpc, "eth_blockNumber", [])); if (!Number.isFinite(tip)) throw new Error("unexpected block number");
  let n = 0;
  for (let a = PAY_FROM_BLOCK[chain.key] || 0; a <= tip; a += LOG_SPAN) {
    const r = await rpcCall(fetchFn, chain.rpc, "eth_getLogs", [{ address: chain.token.address, fromBlock: "0x" + a.toString(16), toBlock: "0x" + Math.min(tip, a + LOG_SPAN - 1).toString(16), topics: [AUTH_USED_TOPIC, "0x" + pad32(stealth)] }]);
    if (!Array.isArray(r)) throw new Error("unexpected logs answer"); n += r.length;
  }
  return n;
};
/** ctx.txKnown(txid) -> true / false (lightwalletd GetTransaction through the gRPC-web proxy, like zec-return.js); throws when it cannot tell. */
/** UTXOs of a t-address straight from lightwalletd (one cheap call, no wallet sync): [{ value, height }]. Times out after 20 s so a hung proxy cannot freeze the wait loop. */
export const makeGetUtxos = (fetchFn = fetch, base = ZC.lightwalletd) => async addr => withTimeout((async () => (await import("./zec-return.js")).getUtxos(base, addr, fetchFn))(), 20000, "lightwalletd UTXO query");
export const withTimeout = (p, ms, what) => { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(what + " timed out after " + Math.round(ms / 1000) + " s")), ms); })]).finally(() => clearTimeout(t)); };
export const makeTxKnown = (fetchFn = fetch, base = ZC.lightwalletd) => async txid => (await import("./zec-return.js")).txKnown(base, txid, fetchFn);

// ---------------------------------------------------------------- storage: key = "<stealth>#<n>", value = { st, db } (db = wallet bytes)
export function idbStore(name = "stealth-zec-hop") {
  // 1088 L-4: every way a request can end settles the promise (abort, blocked, version change); a failed open is not cached; storage is asked to be persistent (no silent eviction)
  let dbp; const open = () => dbp ||= new Promise((res, rej) => { const r = indexedDB.open(name, 1); r.onupgradeneeded = () => r.result.createObjectStore("hops"); r.onsuccess = () => { r.result.onversionchange = () => { r.result.close(); dbp = null; }; res(r.result); }; r.onerror = () => rej(r.error); r.onblocked = () => rej(new Error("storage is blocked by another tab")); try { navigator.storage && navigator.storage.persist && navigator.storage.persist(); } catch {} }).catch(e => { dbp = null; throw e; });
  const run = (mode, f) => open().then(db => new Promise((res, rej) => { const t = db.transaction("hops", mode), q = f(t.objectStore("hops")); t.oncomplete = () => res(q.result); t.onerror = () => rej(t.error); t.onabort = () => rej(t.error || new Error("storage write aborted")); }));
  return { get: k => run("readonly", s => s.get(k)), put: (k, v) => run("readwrite", s => s.put(v, k)), keys: () => run("readonly", s => s.getAllKeys()) };
}
export const memStore = () => { const m = new Map(); return { get: async k => m.get(k) && structuredClone(m.get(k)), put: async (k, v) => void m.set(k, structuredClone(v)), keys: async () => [...m.keys()] }; };
/** Latest hop record of a stealth address, or null. */
export async function findHop(store, stealth) {
  const p = stealth.toLowerCase() + "#", ks = (await store.keys()).filter(k => k.startsWith(p)).sort((a, b) => Number(a.slice(p.length)) - Number(b.slice(p.length)));
  return ks.length ? { key: ks[ks.length - 1], rec: await store.get(ks[ks.length - 1]) } : null;
}
export async function startHop(ctx) {
  const old = await findHop(ctx.store, ctx.stealth);
  if (old && !["DONE", "FAILED_IN"].includes(old.rec.st.step)) throw new Error("an earlier private transfer from this address is unfinished: resume it first");
  const local = old ? old.rec.st.n + 1 : 0;                                   // the IndexedDB counter is only a cache (M-4): the chain's count wins when it is higher; if it cannot be read we do not start
  let chainN = 0; if (ctx.countPriorHops) { try { chainN = await ctx.countPriorHops(ctx.stealth); } catch (e) { throw new Error("could not read this address's earlier hops from the chain (" + e.message + "); nothing was started"); }
    if (!Number.isInteger(chainN) || chainN < 0) throw new Error("bad hop count from the chain"); }
  const n = Math.max(local, chainN), st = newState({ ...ctx, n });
  await ctx.store.put(ctx.stealth.toLowerCase() + "#" + n, { st, db: null });
  return runHop(ctx);
}
const WEBZJS_SHA256 = { "webzjs_wallet.js": "a907bca3e7acbe1757e41e2c4d7f7d3ffa65a654cacdcabfb151c921c8b6264f", "webzjs_wallet_bg.wasm": "128604dfaed593b69ba63fd77602bcdeb9652fc152b345981937ae07d7b77f7c" };   // keep in step with web/vendor/webzjs/SHA256SUMS
export async function loadZjs(base = new URL("./vendor/webzjs/", import.meta.url)) {
  if (!self.crossOriginIsolated) throw new Error("this page is not cross-origin isolated (COOP/COEP), so the Zcash wallet cannot run here");
  // The wasm below receives the seed phrase: refuse to run any bytes other than the audited build (hashes = web/vendor/webzjs/SHA256SUMS; ops/build_webzjs.sh refreshes them).
  const hex = async b => [...new Uint8Array(await crypto.subtle.digest("SHA-256", b))].map(x => x.toString(16).padStart(2, "0")).join("");
  const get = async f => { const r = await fetch(new URL(f, base), { cache: "no-store", credentials: "omit" }); if (!r.ok) throw new Error("cannot load " + f); return r.arrayBuffer(); };
  const [glue, wasm] = await Promise.all([get("webzjs_wallet.js"), get("webzjs_wallet_bg.wasm")]);
  if (await hex(glue) !== WEBZJS_SHA256["webzjs_wallet.js"] || await hex(wasm) !== WEBZJS_SHA256["webzjs_wallet_bg.wasm"]) throw new Error("the Zcash wallet files do not match the audited build; refusing to load them");
  const m = await import(new URL("webzjs_wallet.js", base)); await m.default({ module_or_path: wasm }); await m.initThreadPool(Math.min(4, navigator.hardwareConcurrency || 2)); return m;
}
let zjsP; export const sharedZjs = () => zjsP ||= loadZjs().catch(e => { zjsP = null; throw e; });

// ---------------------------------------------------------------- the machine
/** ctx: { store, stealth, priv, chain, dest, recipient, amount, dry, mode("fast"|"private"), stopAt, api, words, loadZjs, fetchFn, fetchFnOut, sleep, rand, base, maxLoss,
 *          waitReceipt(hash)->{ok}, balance()->BigInt, randomNonce(), authUsed(authorizer,nonce)->bool, txKnown(txid)->bool, countPriorHops(stealth)->n, onProgress(st,msg) }
 *  Returns the state. st.err set = halted (resume = call runHop again); DONE_STEPS = finished. */
export async function runHop(ctx) {
  const { store, sleep = sleepMs, base = PW.ONECLICK } = ctx, found = await findHop(store, ctx.stealth);
  if (!found) throw new Error("no private transfer to resume"); const { key, rec } = found, st = rec.st;
  const rawFetch = ctx.fetchFn || fetch, iso = f => (u, init = {}) => f(u, { ...init, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" });   // M-5: no cookies / referrer to 1Click
  const fIn = iso(rawFetch), fOut = iso(ctx.fetchFnOut || rawFetch), fetchFn = rawFetch;                  // fOut may be a different network path (proxy) than fIn
  const mn = await mnemonicFor(ctx.priv, ctx.words, st.n || 0), say = m => ctx.onProgress && ctx.onProgress(st, m), save = () => store.put(key, rec);
  const go = async (step, patch = {}) => { Object.assign(st, patch, { step }, st.step === step && st.stepAt ? {} : { stepAt: Date.now() }); await save(); };
  if (!st.stepAt) st.stepAt = Date.now();                        // state saved by older code: count from now
  const partsOn = () => Array.isArray(st.parts);
  const legacy = { get quote() { return st.outQuote; }, set quote(v) { st.outQuote = v; }, get raw() { return st.outRaw; }, set raw(v) { st.outRaw = v; }, get tx() { return st.outTx; }, set tx(v) { st.outTx = v; },
    get expiry() { return st.outExpiry; }, set expiry(v) { st.outExpiry = v; }, get acct() { return st.attempt; }, set acct(_) {}, get amount() { return null; }, get reserve() { return st.reserve; }, set reserve(v) { st.reserve = v; }, get tries() { return st.attempt; }, set tries(_) {} };
  const P = () => partsOn() ? st.parts[st.partIdx || 0] : legacy;     // the payout part in work; an old (v1) state has one out-leg kept in the old fields
  let W = null, Z = null;
  const wallet = async () => {                                   // restore from the saved bytes, or create the accounts at the stored birthday (re-creating gives the same addresses)
    if (W) return W; Z = ctx.Zjs || (ctx.Zjs = await ctx.loadZjs());
    W = new Z.WebWallet(ZC.network, ZC.lightwalletd, 1, 1, rec.db || null);
    if (!rec.db) {
      if (st.birthday == null) { st.birthday = Number(await retry(() => W.get_latest_block())) - 10; await save(); }
      st.accts = []; for (let i = 0; i < (st.nAccts || MAX_OUT + 1); i++) st.accts.push(await W.create_account("hop" + i, mn, i, st.birthday));
      rec.db = await W.db_to_bytes(); await save();
    }
    return W;
  };
  const saveWallet = async () => { rec.db = await W.db_to_bytes(); await save(); };
  // Sync with a live status line. MEASURED against mainnet (Chrome, WebZjs Ironwood build): the first sync() of a wallet that has never synced takes 5-15 s (~0.1 s per block + 2 s subtree roots),
  // but EVERY later sync() of a wallet that already scanned takes 145-156 s with 1 account and ~340 s with 4 (a fresh WebWallet restored from saved bytes behaves the same). So: the wallet is synced as rarely
  // as possible (waits use the lightwalletd UTXO query), and a slow sync is shown honestly. WebZjs has no progress callback and blocks get_wallet_summary while syncing, so the percent is an estimate.
  const beatMs = ctx.beatMs || 5000, syncMax = ctx.syncMaxMs || 15 * 60_000;
  const syncW = async () => {
    const w = await wallet(); let blocks = null;
    try { const s0 = await withTimeout(w.get_wallet_summary(), 15000, "wallet summary"); if (s0 && s0.chain_tip_height > 0 && s0.fully_scanned_height > 0) blocks = s0.chain_tip_height - s0.fully_scanned_height; if (blocks <= 0) blocks = null; } catch {}
    const again = !!st.syncedOnce, t0 = Date.now(), n = (st.accts || []).length || 1;
    const est = again ? 100_000 + 60_000 * n : 4000 + (blocks == null ? 100 : blocks) * 120;
    const line = () => { const e = Date.now() - t0; return "Syncing Zcash wallet " + Math.min(95, Math.floor(100 * e / est)) + "%" + (again ? " (a repeat refresh takes ~" + Math.round(est / 60_000) + " min)" : blocks != null ? " (" + blocks + " blocks)" : "") + " · " + Math.round(e / 1000) + " s"; };
    say(line()); const iv = setInterval(() => say(line()), beatMs);
    try { await withTimeout(w.sync(), syncMax, "Zcash wallet sync"); st.syncedOnce = true; } catch (e) { if (/timed out/.test(e.message)) { W = null; say("Problem: " + e.message + " · retrying"); } throw e; } finally { clearInterval(iv); }   // W = null: the next call restores a fresh wallet from the last saved bytes
  };
  const bal = async i => {                                       // sync, then the balances of account i
    await retry(() => syncW()); const w = await wallet();
    const e = ((await w.get_wallet_summary()).account_balances.find(x => x[0] === st.accts[i]) || [0, {}])[1];
    return { t: BigInt(e.unshielded_balance || 0), o: BigInt(e.orchard_balance || 0) + BigInt(e.ironwood_balance || 0), p: BigInt(e.pending_change || 0) + BigInt(e.pending_spendable || 0) };
  };
  const taddr = async i => (await wallet()).get_current_address_transparent(st.accts[i]);
  const tip = async () => { const w = await wallet(); return Number(await retry(() => withTimeout(w.get_latest_block(), 20000, "Zcash tip query"))); };
  const utxoOf = async a => { if (!ctx.getUtxos) return undefined; try { const u = (await ctx.getUtxos(a)).filter(x => x.height > 0); return { sum: u.reduce((s, x) => s + BigInt(x.value), 0n), height: u.reduce((m, x) => Math.max(m, x.height), 0) }; } catch { return undefined; } };   // undefined = cannot tell
  const allocAcct = async () => { const a = st.nextAcct || MAX_OUT + 1; if (a >= st.accts.length) throw new Halt("no fresh hop account left for a refund address; nothing was sent"); st.nextAcct = a + 1; await save(); return a; };
  const until = async (what, ms, fn, every = 10000) => { const t0 = Date.now(); for (;;) { if (await fn()) return; if (Date.now() - t0 > ms) throw new Halt(what + " is taking too long"); say("Waiting for " + what + "… " + Math.round((Date.now() - t0) / 1000) + " s"); await sleep(every); } };
  const status = async (a, f) => { const r = await f(base + "/v0/status?depositAddress=" + encodeURIComponent(a), { cache: "no-store" }).catch(() => null); return r && r.ok ? (await r.json().catch(() => ({}))).status || PENDING : PENDING; };
  const poll = async (a, label, ms, f) => { try { return await PW.pollStatus({ base, depositAddress: a, fetchFn: f, sleep, intervalMs: 4000, timeoutMs: ms, onUpdate: s => say(label + ": " + s.status) }); } catch (e) { throw new Halt(e.message); } };
  const txidOf = raw => hex(unhex(raw).slice(0, 32).reverse()).slice(2);
  const known = async raw => { try { return ctx.txKnown ? await ctx.txKnown(txidOf(raw)) : undefined; } catch { return undefined; } };      // true / false / undefined = cannot tell
  const relay = async () => {
    if (st.dry) throw new Error("dry run never calls the relayer");
    const { r, d } = await postRelay(fetchFn, ctx.api + "/relay", st.auth, { sleep: ctx.sleep, onBusy: m => ctx.onProgress && ctx.onProgress(m), check: ctx.authUsed ? () => ctx.authUsed(st.auth.from, st.auth.nonce) : null });   // 1098 L-3: a 502/504 is settled on chain before any retry
    if (d.used) return null;                                     // the relayer did get it: the authorization is used on chain
    if (r.ok && d.hash) return d.hash;
    if (/already used/.test(d.error || "")) return null;         // this very authorization was sent before: the transfer exists
    throw new Error(d.error || "relayer error");
  };
  const H = {
    async QUOTE_IN() {
      if (!st.inQuote) {
        const tIn = await taddr(0), req = reqIn({ chain: ctx.chain, amount: BigInt(st.amount), tAddr: tIn, stealth: st.stealth, dry: st.dry, rand: ctx.rand });
        const info = quoteInfoOf(await PW.requestQuote({ base, fetchFn: fIn, req }), req);
        if (!okSize(BigInt(info.amountOut))) throw new Halt("too small for the Zcash route: it would deliver only " + info.amountOut + " zatoshi; nothing was sent");
        st.tIn = tIn; st.inQuote = info; await save();
      }
      await go("DEPOSIT_IN");
    },
    async DEPOSIT_IN() {
      if (st.dry) return go("WAIT_T");                           // dry hops never sign or relay
      const q = st.inQuote;
      if (!st.relayed) {
        if ((await status(q.depositAddress, fIn)) === PENDING) { // not seen by 1Click yet
          if (!st.auth && Date.now() > q.deadlineMs - 120_000) return go("QUOTE_IN", { inQuote: null });      // quote nearly expired and nothing signed: start over
          const spent = st.auth && !st.txIn && ctx.balance && (await ctx.balance()) < BigInt(q.amountIn);       // authorization used but the answer got lost
          let skip = !!spent;
          if (skip && ctx.authUsed) { try { if ((await ctx.authUsed(st.stealth, st.auth.nonce)) === false) skip = false; } catch {} }   // 1088 L-3: a low or missing balance reading alone is no proof; the chain must say the nonce was used (else the SAME authorization is sent again, which is safe)
          if (!skip && st.auth && !st.txIn && st.auth.validBefore * 1000 <= Date.now()) {
            // M-1: the saved authorization has expired. It may still have been settled. A new one (new nonce) is allowed ONLY if the chain says this nonce was never used.
            let used; try { used = ctx.authUsed ? await ctx.authUsed(st.stealth, st.auth.nonce) : undefined; } catch (e) { throw new Halt("could not check the earlier authorization on chain (" + e.message + "); nothing new was signed"); }
            if (used === true) skip = true;                      // settled: the deposit exists, only wait for 1Click
            else if (used === false) return go("QUOTE_IN", { auth: null, inQuote: null });    // expired and unused: a fresh quote, then a fresh authorization
            else throw new Halt("cannot tell whether the earlier authorization was used; nothing new was signed");
          }
          if (!skip) {
            if (!st.auth) {
              st.auth = PW.signTransferAuth({ chain: ctx.chain, priv: ctx.priv, from: st.stealth, to: q.depositAddress, value: BigInt(q.amountIn), validBefore: Math.min(Math.floor(Date.now() / 1000) + 3600, Math.floor(q.deadlineMs / 1000) - 30), nonce: ctx.randomNonce() });     // 1088 M-3: never valid past the quote
              await save();                                      // recorded BEFORE it can leave the device
            }
            if (!st.txIn) { say("Sending through the relayer…"); st.txIn = await relay(); await save(); }
            if (st.txIn) {
              if (!(await ctx.waitReceipt(st.txIn)).ok) { st.txIn = null; await save(); throw new Halt("the deposit transfer reverted; nothing moved"); }   // the SAME authorization stays saved: it is public now and may still be valid
              await PW.submitDeposit({ base, txHash: st.txIn, depositAddress: q.depositAddress, fetchFn: fIn }).catch(() => {});
            }
          }
        }
        st.relayed = true; await save();
      }
      const fin = await poll(q.depositAddress, "Swap to ZEC", 40 * 60_000, fIn); await go(afterIn(fin.status).step, afterIn(fin.status));
    },
    async WAIT_T() {
      const need = st.attempt ? MIN_SHIELD : BigInt(st.inQuote.minOut) * 9n / 10n, ta = ctx.getUtxos ? await taddr(st.attempt) : null;
      let last = null, utxo = null, k = 0;
      // 1) arrival: the cheap lightwalletd UTXO query decides (1 s) and gives the exact block; the slow wallet sync is only a second opinion (first pass, then every 6th)
      await until("ZEC to arrive", 45 * 60_000, async () => {
        utxo = ta ? await utxoOf(ta) : undefined; if (utxo && utxo.sum >= need) return true;
        if (utxo === undefined || k++ % 6 === 0) { last = await bal(st.attempt); return last.t >= need || last.o >= ZC.minIn; }
        return false;
      });
      if (!(last && last.o >= ZC.minIn && last.t < MIN_SHIELD)) {   // coins on the t-address: they become spendable only after T_CONFS confirmations
        if (st.tSeenHeight == null) { st.tSeenHeight = utxo && utxo.height ? utxo.height - 1 : await tip(); st.tSeenAt = Date.now(); await save(); }   // the block of the deposit when known (it counts as confirmation 1), else the tip when first seen
        const t0 = Date.now();
        for (;;) {
          const n = Math.max(0, Math.min(T_CONFS, (await tip()) - st.tSeenHeight)); if (n >= T_CONFS) break;
          if (Date.now() - t0 > 45 * 60_000) throw new Halt("Zcash confirmations are taking too long");
          say("Waiting for Zcash confirmations (" + n + "/" + T_CONFS + ") · ~" + Math.max(1, Math.round((T_CONFS - n) * 1.25)) + " min");
          await sleep(beatMs * 2);
        }
      }
      await go("SHIELD");
    },
    async SHIELD() {
      const i = st.attempt, t0 = Date.now();
      for (;;) {
        const b = await bal(i); if (b.t < MIN_SHIELD) break;     // nothing left to shield (already sent: a resume skips this)
        try {
          say("Shielding: preparing the transaction…"); const w = await wallet(), seed = await mnemonicSeed(mn);
          let p = await w.pczt_shield(st.accts[i]);
          p = await Z.pczt_sign(ZC.network, p, new Z.UnifiedSpendingKey(ZC.network, seed, i), new Z.SeedFingerprint(seed));
          const tp = Date.now(), iv = setInterval(() => say("Shielding: building the zero-knowledge proof · " + Math.round((Date.now() - tp) / 1000) + " s"), beatMs); say("Shielding: building the zero-knowledge proof…");
          let pr; try { pr = await withTimeout(w.pczt_prove(p, null), 10 * 60_000, "Shield proof"); } finally { clearInterval(iv); }
          say("Shielding: sending to the Zcash network…"); await w.pczt_send(pr); await saveWallet(); break;
        } catch (e) {
          if (!/InsufficientFunds/.test(String((e && e.message) || e))) throw e;          // coins not spendable yet (confirmations): wait and try again
          if (Date.now() - t0 > 30 * 60_000) throw new Halt("The ZEC has arrived but is not spendable yet. Press Continue in a few minutes.");
          say("Waiting for the ZEC to become spendable in the wallet… " + Math.round((Date.now() - t0) / 1000) + " s"); await sleep(10000);
        }
      }
      const tShield = ctx.getUtxos ? await taddr(i) : null;
      await until("the shielded balance (1 confirmation)", 40 * 60_000, async () => {
        if (tShield) { const u = await utxoOf(tShield); if (u && u.sum >= MIN_SHIELD) return false; }           // the shield is not mined yet (the t-coins are still there): no need for a slow wallet sync
        const x = await bal(i); await saveWallet(); return x.o >= ZC.minIn && x.p === 0n && x.t < MIN_SHIELD;
      }, 10000);
      if (partsOn()) { const p = P(); p.acct = i; p.refundAcct = null; p.at = Date.now() + delayMs(ctx.rand); await go("DELAY", { delayUntil: p.at }); }      // a refunded part is shielded again: short own delay, then sent from this account
      else if (st.mode) {                                        // H-1: split the shielded balance into random parts, each with its own random time
        const parts = planParts({ orchard: (await bal(i)).o, reserve: BigInt(st.reserve), mode: st.mode, rand: ctx.rand, now: Date.now(), acct: i });
        await go("DELAY", { parts, partIdx: 0, delayUntil: parts[0].at });
      } else await go("DELAY", { delayUntil: Date.now() + delayMs(ctx.rand) });         // state of the old code: one out-leg
    },
    async DELAY() {
      const at = () => partsOn() ? P().at : st.delayUntil, lbl = partsLabel(st);
      if (partsOn()) st.delayUntil = P().at;
      while (Date.now() < at()) { const left = at() - Date.now(); say((lbl ? lbl + ": waiting " : "Waiting ") + Math.ceil(left / 1000) + " s to break the timing link…"); await sleep(Math.min(left > 120_000 ? 10000 : 5000, left)); }
      await go("QUOTE_OUT");
    },
    async QUOTE_OUT() {
      const p = P();
      if (p.quote && (p.raw || Date.now() < p.quote.deadlineMs - 120_000)) return go("SEND_OUT");
      if (st.waitExpiry) { await until("the earlier unsent Zcash transaction to expire", 70 * 60_000, async () => (await tip()) > st.waitExpiry); st.waitExpiry = null; await save(); }
      const reserve = BigInt(p.reserve || st.reserve);
      if (partsOn()) await until("the shielded change to confirm", 40 * 60_000, async () => { const x = await bal(p.acct); return x.p === 0n && x.o >= (p.tries ? ZC.minIn : BigInt(p.amount)) + reserve; }, 10000);
      const b = await bal(p.acct), amount = partsOn() && !p.tries ? BigInt(p.amount) : outAmount(b.o, reserve);
      if (!amount || amount < ZC.minIn) throw new Halt("only " + b.o + " zatoshi are shielded, below the 1Click minimum; they stay in the hop wallet");
      if (partsOn() && p.refundAcct == null) { p.refundAcct = await allocAcct(); await save(); }            // a fresh hop t-address per part and attempt: the refund address is never reused
      const refundT = await taddr(partsOn() ? p.refundAcct : st.attempt + 1), req = reqOut({ dest: ctx.dest, amount, recipient: st.recipient, refundT, rand: ctx.rand });
      const info = quoteInfoOf(await PW.requestQuote({ base, fetchFn: fOut, okDeposit: isT, req }), req);
      const paid = (partsOn() ? st.parts : []).filter(x => x.status === "SUCCESS").reduce((a, x) => a + Number(x.quote.amountOut), 0);
      const left = (partsOn() ? st.parts.filter((x, i) => i > (st.partIdx || 0)).reduce((a, x) => a + BigInt(x.amount), 0n) : 0n) + amount;
      const loss = projectedLoss({ amountIn: st.amount, inDec: ctx.chain.token.decimals, outDec: ctx.dest.token.decimals, paidOut: paid, rate: Number(info.amountOut) / Number(amount), zatsLeft: left }), cap = ctx.maxLoss == null ? MAX_LOSS : ctx.maxLoss;
      if (loss > cap) throw new Halt("the quote would lose " + (loss * 100).toFixed(1) + "% of the amount in total, above the " + (cap * 100).toFixed(1) + "% limit; nothing was sent, the ZEC stays shielded. Resume later or raise the limit");
      p.quote = info; p.tx = null; p.raw = null; p.expiry = null; await go("SEND_OUT");
    },
    async SEND_OUT() {
      const p = P(), oq = p.quote;
      if (!p.tx && (await status(oq.depositAddress, fOut)) === PENDING) {        // 1Click has not seen the ZEC yet
        const w = await wallet(), stale = Date.now() > oq.deadlineMs - 60_000;
        let send = true;
        if (p.raw && (stale || (p.expiry && (await tip()) > p.expiry))) {         // M-3: the quote or the signed transaction has expired. Only start over if the transaction is provably not out.
          const kn = await known(p.raw);
          if (kn === true) send = false;                                           // it went out after all: carry on with it
          else if (kn === false) { st.waitExpiry = p.expiry || null; p.raw = null; p.expiry = null; p.quote = null; return go("QUOTE_OUT"); }
          else throw new Halt("cannot tell whether the earlier ZEC transaction went out; not creating another");
        } else if (!p.raw && stale) { p.quote = null; return go("QUOTE_OUT"); }
        if (send) {
          if (!p.raw) {
            let proposal; try { proposal = await w.propose_transfer(st.accts[p.acct], oq.depositAddress, BigInt(oq.amountIn)); }
            catch (e) {
              const r = BigInt(p.reserve || st.reserve);
              if (!/insufficient|fee|funds/i.test(String((e && e.message) || e))) throw e;                              // 1088 L-2: only a fee shortfall doubles the reserve; sync / network errors just retry
              if (r >= RESERVE * 8n) throw new Halt("the Zcash fee does not fit even with a reserve of " + r + " zatoshi (" + e.message + ")");   // ... and never without bound
              p.reserve = (r * 2n).toString(); p.quote = null;
              if (partsOn()) { p.amount = (BigInt(p.amount) - r).toString(); if (BigInt(p.amount) < ZC.minIn) throw new Halt("the Zcash fee does not fit into this payout part (" + e.message + ")"); }
              await go("QUOTE_OUT"); throw new Halt("the Zcash fee did not fit; resume to try with a bigger reserve (" + e.message + ")");
            }
            p.raw = hex(await w.create_proposed_transactions(proposal, mn, p.acct)).slice(2); p.expiry = (await tip()) + TX_EXPIRY_DELTA; await saveWallet();      // txid(s) recorded and the wallet saved BEFORE broadcasting
          }
          try { await w.send_authorized_transactions(unhex(p.raw)); }
          catch (e) {                                                              // M-2: only a clean return counts as sent. Any error: ask the network whether the txid is known.
            const kn = await known(p.raw);
            if (kn === true) { /* already in the mempool / chain: fine */ }
            else if (kn === false) throw e;                                        // not known: a real failure, the retry rebroadcasts
            else throw new Halt("the broadcast failed and the network could not say whether the transaction is known (" + String((e && e.message) || e) + ")");
          }
        }
        p.tx = txidOf(p.raw); await save();
        await PW.submitDeposit({ base, txHash: p.tx, depositAddress: oq.depositAddress, fetchFn: fOut }).catch(() => {});
      }
      const fin = await poll(oq.depositAddress, (partsLabel(st) ? partsLabel(st).replace(/^./, c => c.toUpperCase()) + ": swap" : "Swap") + " from ZEC", 90 * 60_000, fOut);
      const t = (((fin.swapDetails || {}).destinationChainTxHashes) || [])[0], pay = t && t.hash ? { hash: String(t.hash), url: String(t.explorerUrl || "") } : null;
      if (!partsOn()) { const a = afterOut(st, fin.status); if (a.step === "DONE") { if (pay) a.payoutTx = pay; a.doneAt = Date.now(); } return go(a.step, a); }
      p.status = fin.status; if (pay) p.payoutTx = pay;
      const a = afterPart(st, fin.status);
      if (fin.status === "REFUNDED" && a.step === "WAIT_T") { p.tries = (p.tries || 0) + 1; p.quote = null; p.raw = null; p.tx = null; p.expiry = null; }
      if (a.step === "DONE") {
        const ok = st.parts.filter(x => x.status === "SUCCESS");
        a.doneAt = Date.now(); a.payoutTxs = ok.map(x => x.payoutTx).filter(Boolean); if (a.payoutTxs[0]) a.payoutTx = a.payoutTxs[0];
        a.outTotal = ok.reduce((s, x) => s + BigInt(x.quote.amountOut), 0n).toString();
      }
      await go(a.step, a);
    },
  };
  for (st.err = null, st.halted = false; !DONE_STEPS.has(st.step) && st.step !== ctx.stopAt;) {
    if (st.dry && !["QUOTE_IN", "DEPOSIT_IN"].includes(st.step)) { st.err = "dry run stops here"; break; }
    try { await retry(() => H[st.step](), { sleep }); } catch (e) { st.err = e.message || String(e); st.halted = e instanceof Halt; break; }   // halted = a deliberate stop (checks); otherwise a transient failure the app may retry
  }
  await save(); say(st.err || progressText(st));
  return st;
}

/** 1088 L-6: a finished transfer must not keep the stealth -> hop address -> recipient link (nor the wallet / viewing key) in plaintext. Leaves only what findHop / startHop need.
 *  Called by the app once the result has been shown (not inside runHop: the caller and tests still read the full state). */
export async function scrubFinished(store, stealth) {
  const f = await findHop(store, stealth); if (!f || !["DONE", "FAILED_IN"].includes(f.rec.st.step)) return false;
  const st = f.rec.st; await store.put(f.key, { st: { v: st.v, n: st.n, stealth: st.stealth, chain: st.chain, dest: st.dest, step: st.step, result: st.result, doneAt: st.doneAt, amount: st.amount, hidden: st.hidden, scrubbed: true }, db: null }); return true;
}

/** Funds left in the hop wallet: per account t-address and balances. Works from the saved wallet, or from the keys alone (fallback birthday from the payment's block time). */
export async function hopSummary(ctx, rec = null) {
  const Zj = ctx.Zjs || await ctx.loadZjs(), mn = await mnemonicFor(ctx.priv, ctx.words, rec ? rec.st.n || 0 : ctx.n || 0), w = new Zj.WebWallet(ZC.network, ZC.lightwalletd, 1, 1, rec && rec.db || null);
  let ids = rec && rec.st.accts;
  if (!ids) { const bd = rec && rec.st.birthday != null ? rec.st.birthday : birthdayFromTime(ctx.blockTimeSec, Number(await w.get_latest_block())); ids = []; for (let i = 0; i < (rec && rec.st.nAccts || MAX_OUT + 1); i++) ids.push(await w.create_account("hop" + i, mn, i, bd)); }
  await w.sync(); const s = await w.get_wallet_summary();
  return Promise.all(ids.map(async (id, i) => { const e = (s.account_balances.find(x => x[0] === id) || [0, {}])[1]; return { account: i, t: await w.get_current_address_transparent(id), transparent: BigInt(e.unshielded_balance || 0), orchard: BigInt(e.orchard_balance || 0) + BigInt(e.ironwood_balance || 0) }; }));
}
