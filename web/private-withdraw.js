/* Private withdraw from a stealth address through NEAR Intents 1Click (https://docs.near-intents.org).
   The stealth key signs an EIP-3009 transferWithAuthorization to the quote's deposit address; OUR relayer submits it (no gas for the user);
   1Click then pays the destination on the destination chain. The refund address of every quote is the stealth address itself, never a main wallet.
   This file has no DOM access: every function takes what it needs (fetch, sleep, rng) so it runs in the browser and in Node tests.
   Honest limits: the deposit and the payout are both public on-chain; with confidentiality "public" they can be matched by amount and time.
   confidentiality "basic" needs a User-Session token (sessionSignIn below) and is OFF in the app until SESSION_SIGNIN is switched on. */
import { keccak, signDigest, unhex, hex } from "./stealth-crypto.js";
import { postRelay } from "./relay-post.js";
import { timeoutSignal } from "./chain-read.js";
import { privateFee, appFeesOf } from "./chains.js";

export const ONECLICK = "https://1click.chaindefuser.com";
export const NEAR_RPCS = ["https://rpc.mainnet.near.org", "https://free.rpc.fastnear.com"];   // read-only: current_salt of intents.near
export const INTENTS_CONTRACT = "intents.near";
export const SESSION_SIGNIN = false;          // the app only calls authenticate() when this is true (nothing is sent to /v0/auth/* today)
export const MIN_PART = 1_000_000n;           // smallest split part (1 token, 6 decimals); 1Click refuses tiny swaps ("at least 150000")
export const TERMINAL = new Set(["SUCCESS", "REFUNDED", "FAILED"]);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), isHash = h => /^0x[0-9a-fA-F]{64}$/.test(h || "");

// ---------------------------------------------------------------- base58 + ERC-191 session sign-in
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58(bytes) {
  let n = 0n; for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = "1" + s; else break; }
  return s;
}
/** secp256k1:<base58(r||s||v)>, v normalised to 0/1 (the verifier rejects 27/28). Same as the SDK's transformERC191Signature. */
export function encodeSecpSignature(sigHex) {
  const b = unhex(sigHex); if (b.length !== 65) throw new Error("expected a 65-byte signature");
  let v = b[64]; if (v >= 27) v -= 27; if (v !== 0 && v !== 1) throw new Error("bad recovery byte");
  b[64] = v; return "secp256k1:" + base58(b);
}
/** EIP-191 personal_sign hash of a UTF-8 string. */
export function personalHash(msg) {
  const m = new TextEncoder().encode(msg), pre = new TextEncoder().encode("\x19Ethereum Signed Message:\n" + m.length);
  const all = new Uint8Array(pre.length + m.length); all.set(pre, 0); all.set(m, pre.length); return keccak(all);
}
const b64 = u8 => { let s = ""; for (const x of u8) s += String.fromCharCode(x); return btoa(s); };
/** Versioned nonce (32 bytes, base64) exactly as @defuse-protocol/intents-sdk VersionedNonceBuilder.encodeNonce:
 *  magic 56 28 f6 c6 | version 0 | salt(4) | deadline ns u64 LE | 15 bytes, the first 8 = start time in ns (i64 LE), then 7 random. */
export function encodeNonce(salt4, deadlineMs, rand15) {
  if (salt4.length !== 4 || rand15.length !== 15) throw new Error("bad nonce parts");
  const out = new Uint8Array(32);
  out.set([0x56, 0x28, 0xf6, 0xc6, 0], 0); out.set(salt4, 5);
  new DataView(out.buffer).setBigUint64(9, BigInt(deadlineMs) * 1000000n, true); out.set(rand15, 17);
  return b64(out);
}
export function versionedNonce(salt4, deadlineMs, startMs, rand7) {
  if (rand7.length !== 7) throw new Error("bad nonce parts");
  const r = new Uint8Array(15); new DataView(r.buffer).setBigInt64(0, BigInt(startMs) * 1000000n, true); r.set(rand7, 8);
  return encodeNonce(salt4, deadlineMs, r);
}
/** The empty-intent payload string, key order as the official signer (IntentSignerViem.signIntent). `intents: []` moves no tokens: it only proves ownership. */
export function sessionPayload({ address, saltHex, now = Date.now(), ttlMs = 5 * 60_000, rand7 = crypto.getRandomValues(new Uint8Array(7)), nonce }) {
  if (!isAddr(address)) throw new Error("bad signer address");
  const deadlineMs = now + ttlMs;
  return JSON.stringify({ signer_id: address.toLowerCase(), verifying_contract: INTENTS_CONTRACT, deadline: new Date(deadlineMs).toISOString(),
    nonce: nonce || versionedNonce(unhex("0x" + saltHex), deadlineMs, now, rand7), intents: [] });
}
/** MultiPayload {standard, payload, signature} signed IN THE PAGE by the stealth private key (no wallet prompt). */
export function signSession({ priv, address, saltHex, now, rand7, nonce }) {
  const payload = sessionPayload({ address, saltHex, now, rand7, nonce });
  const s = signDigest(personalHash(payload), unhex(priv));
  const sig = "0x" + s.r.slice(2) + s.s.slice(2) + (s.v - 27).toString(16).padStart(2, "0");
  return { standard: "erc191", payload, signature: encodeSecpSignature(sig) };
}
/** Current salt of intents.near (4 bytes hex) from a public NEAR RPC. */
export async function fetchSalt({ rpcs = NEAR_RPCS, fetchFn = fetch } = {}) {
  let last;
  for (const url of rpcs) {
    try {
      const r = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query",
        params: { request_type: "call_function", finality: "optimistic", account_id: INTENTS_CONTRACT, method_name: "current_salt", args_base64: "e30=" } }) });
      const j = await r.json(); const s = JSON.parse(String.fromCharCode(...j.result.result));
      if (/^[0-9a-f]{8}$/.test(s)) return s;
    } catch (e) { last = e; }
  }
  throw new Error("could not read the intents salt" + (last ? ": " + last.message : ""));
}
/** POST /v0/auth/authenticate with the signed empty intent -> accessToken. Only called when SESSION_SIGNIN is on. */
export async function sessionSignIn({ base = ONECLICK, priv, address, fetchFn = fetch, saltHex }) {
  const salt = saltHex || await fetchSalt({ fetchFn });
  const signedData = signSession({ priv, address, saltHex: salt });
  const r = await fetchFn(base + "/v0/auth/authenticate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signedData }) });
  const j = await r.json().catch(() => ({})); if (!r.ok || !j.accessToken) throw new Error("session sign-in failed: " + (j.message || r.status));
  return j.accessToken;
}

// ---------------------------------------------------------------- 1Click quote / deposit / status
/** Quote request. originAsset = the chain's own token, refundTo = the stealth address (never the user's main wallet). */
export function buildQuoteRequest({ from, to, amount, recipient, refundTo, dry, confidentiality = "public", now = Date.now(), deadlineMs = 3600_000, fees = privateFee }) {
  if (!from.oneClick || !to.oneClick) throw new Error("private withdraw is not available on " + (from.oneClick ? to.name : from.name));
  if (!isAddr(recipient) || !isAddr(refundTo)) throw new Error("bad address");
  if (!(amount > 0n)) throw new Error("bad amount");
  const r = { dry: !!dry, swapType: "EXACT_INPUT", slippageTolerance: 100, originAsset: from.oneClick.assetId, depositType: "ORIGIN_CHAIN",
    destinationAsset: to.oneClick.assetId, amount: amount.toString(), refundTo, refundType: "ORIGIN_CHAIN", recipient, recipientType: "DESTINATION_CHAIN",
    deadline: new Date(now + deadlineMs).toISOString(), confidentiality }, af = appFeesOf(fees);
  if (af) r.appFees = af;      // service fee (chains.js privateFee, off by default); this one quote is the whole route, i.e. its first leg
  return r;
}
async function call(fetchFn, url, init) {
  const r = await fetchFn(url, { ...init, signal: init.signal || timeoutSignal(30000) }); const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.message || ("NEAR Intents error " + r.status));
  return j;
}
/** Requests a quote and refuses anything that differs from what we asked (amount, recipient, refund address, assets). */
export async function requestQuote({ base = ONECLICK, req, token, fetchFn = fetch, okDeposit = isAddr }) {
  const headers = { "content-type": "application/json" }; if (token) headers.authorization = "Bearer " + token;
  const j = await call(fetchFn, base + "/v0/quote", { method: "POST", headers, body: JSON.stringify(req) });
  const q = j.quote, e = j.quoteRequest || {};
  if (!q || !q.amountIn || !q.amountOut) throw new Error("NEAR Intents returned no quote");
  if (q.amountIn !== req.amount) throw new Error("the quote changed the amount; refusing");
  if (String(e.recipient).toLowerCase() !== req.recipient.toLowerCase() || String(e.refundTo).toLowerCase() !== req.refundTo.toLowerCase()
    || e.originAsset !== req.originAsset || e.destinationAsset !== req.destinationAsset) throw new Error("the quote does not match the request; refusing");
  if (!req.dry && !okDeposit(q.depositAddress)) throw new Error("the quote has no usable deposit address");
  // audit 1086 L-2: beyond the format, the deposit address must not be one of our own / the token or the zero address (a hijacked quote would point the signature at those)
  if (!req.dry) { const d = String(q.depositAddress).toLowerCase(); if ([req.refundTo, req.recipient, "0x0000000000000000000000000000000000000000"].some(a => String(a || "").toLowerCase() === d)) throw new Error("the quote's deposit address is not acceptable; refusing"); }
  return j;
}
/** Human numbers from a quote. Both stablecoins here have 6 decimals (token.decimals of the destination chain is used for the output). */
export function summarizeQuote(j, inDec = 6, outDec = 6) {
  const q = j.quote, i = BigInt(q.amountIn), o = BigInt(q.amountOut);
  const f = (v, d) => (Number(v) / 10 ** d).toFixed(4).replace(/0{1,2}$/, "");
  const fee = i - o;      // nominal: both sides are $1 stablecoins
  return { amountIn: i, amountOut: o, inText: f(i, inDec), outText: f(o, outDec), feeText: (Number(fee) / 10 ** inDec).toFixed(4), feePct: Number(i) ? (Number(fee) / Number(i) * 100).toFixed(2) : "0",
    etaSec: q.timeEstimate, minOutText: q.minAmountOut ? f(BigInt(q.minAmountOut), outDec) : null };
}
export async function submitDeposit({ base = ONECLICK, txHash, depositAddress, fetchFn = fetch }) {
  return call(fetchFn, base + "/v0/deposit/submit", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ txHash, depositAddress }) });
}
/** Polls GET /v0/status until SUCCESS / REFUNDED / FAILED. onUpdate(statusJson) on every change. Transient errors are retried. */
export async function pollStatus({ base = ONECLICK, depositAddress, fetchFn = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), intervalMs = 3000, timeoutMs = 20 * 60_000, onUpdate = () => {} }) {
  const t0 = Date.now(); let last = null, errs = 0;
  while (Date.now() - t0 < timeoutMs) {
    try {
      const j = await call(fetchFn, base + "/v0/status?depositAddress=" + encodeURIComponent(depositAddress), { cache: "no-store" });
      errs = 0; if (j.status !== last) { last = j.status; onUpdate(j); }
      if (TERMINAL.has(j.status)) return j;
    } catch (e) { if (++errs > 10) throw e; }
    await sleep(intervalMs);
  }
  throw new Error("still not finished after " + Math.round(timeoutMs / 60000) + " min; check the status later with deposit address " + depositAddress);
}

// ---------------------------------------------------------------- privacy helpers
/** Random split of `total` into up to `parts` pieces, each >= minPart, unequal (weights 0.5..1.5) and in random order. */
export function randomSplit(total, parts, rng = Math.random, minPart = MIN_PART) {
  let n = Math.max(1, Math.min(parts, Number(total / minPart)));
  if (n === 1) return [total];
  const w = Array.from({ length: n }, () => 0.5 + rng()), sw = w.reduce((a, b) => a + b, 0), spare = total - minPart * BigInt(n);
  const out = w.map(x => minPart + BigInt(Math.floor(Number(spare) * x / sw)));
  out[0] += total - out.reduce((a, b) => a + b, 0n);          // rounding remainder
  return out;
}
export const randomDelayMs = (maxMin, rng = Math.random) => Math.max(0, Math.floor(rng() * Number(maxMin || 0) * 60_000));

// ---------------------------------------------------------------- EIP-3009 from the stealth key
const enc = s => new TextEncoder().encode(s);
const w32 = v => (typeof v === "bigint" ? v.toString(16) : String(v).replace(/^0x/, "")).padStart(64, "0");
const TYPEHASH = hex(keccak(enc("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")));
const DOMAIN_TYPEHASH = hex(keccak(enc("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")));
export const domainSeparator = chain => hex(keccak(unhex(DOMAIN_TYPEHASH + hex(keccak(enc(chain.token.domainName))).slice(2) + hex(keccak(enc(chain.token.domainVersion))).slice(2)
  + w32(BigInt(chain.chainId)) + w32(chain.token.address.toLowerCase().replace(/^0x/, ""))))).toLowerCase();
export function signTransferAuth({ chain, priv, from, to, value, validBefore, nonce }) {
  const struct = TYPEHASH + w32(from.toLowerCase().replace(/^0x/, "")) + w32(to.toLowerCase().replace(/^0x/, "")) + w32(value) + w32(0n) + w32(BigInt(validBefore)) + nonce.slice(2);
  const digest = keccak(unhex("0x1901" + domainSeparator(chain).slice(2) + hex(keccak(unhex(struct))).slice(2)));
  const sig = signDigest(digest, unhex(priv));
  return { from, to, value: value.toString(), validAfter: "0", validBefore: String(validBefore), nonce, v: sig.v, r: sig.r, s: sig.s };
}

/** The relayer's answer, read the same way by the standard route (app.js) and the fast route (1121 L-2, 1125 F-3).
 *  -> { kind: "used" }  the authorization is already used on chain (lost answer, then the retry): follow the transaction, do not give up;
 *     { kind: "error", message, definite, config }  config = a 400 that names a setting of the relayer (shown as it is, with CONFIG_NOTE; the guard stays);  definite = a JSON 400 that carries the relayer's explicit `definite: true` (refused by offline validation, before any broadcast; 1130 M-1): only then may the
 *       double-send guard be cleared. Every other error (a 400 "still being confirmed" / "in progress", 403, 429, 5xx) may follow an earlier broadcast of the same authorization and counts as in progress;
 *     { kind: "ok" }. */
const CONFIG_REFUSAL = /below the minimum|fees are not enabled|fee below the minimum|fee authorization required/i;      // 1135 L-2: the relayer's own settings refused the request (server/relayer.mjs early(..., false)); matched by its words, no new flag
export const CONFIG_NOTE = " This is a setting of the relayer, not a problem with your request, and nothing is known to have been sent. The safety lock stays on until this authorization expires (up to about an hour).";
export function relayOutcome(r, d) {
  const usedErr = !!d.error && /authorization already used/i.test(String(d.error));
  if (d.used || usedErr) return { kind: "used" };
  if (!r.ok || d.error) return { kind: "error", message: d.error || "relayer error", definite: !!d.error && r.status === 400 && d.definite === true, config: !!d.error && r.status === 400 && d.definite !== true && CONFIG_REFUSAL.test(String(d.error)) };
  return { kind: "ok" };
}
/** One part: optional delay -> real quote -> stealth key signs the transfer to the deposit address -> relayer -> receipt -> submit -> poll.
 *  ctx: { from(chain), to(chain), priv, stealth, recipient, api, token, base, fetchFn, sleep, waitReceipt(hash)->{ok}, onProgress(msg), randomNonce(), maxWorse(0..1), refAmountOut }
 *  Returns { status, depositAddress, txHash, quote, final }. Throws before anything is signed if the quote is worse than the preview. */
export async function runPart(ctx, amount, delayMs) {
  const say = ctx.onProgress || (() => {}), fetchFn = ctx.fetchFn || fetch, sleep = ctx.sleep || (ms => new Promise(r => setTimeout(r, ms)));
  if (delayMs > 0) {
    const end = Date.now() + delayMs;
    while (Date.now() < end) { say("Waiting " + Math.ceil((end - Date.now()) / 1000) + " s before requesting the quote (keep this tab open)…"); await sleep(Math.min(1000, end - Date.now())); }
  }
  const conf = ctx.token ? "basic" : "public";
  say("Requesting a " + conf + " quote…");
  const req = buildQuoteRequest({ from: ctx.from, to: ctx.to, amount, recipient: ctx.recipient, refundTo: ctx.stealth, dry: false, confidentiality: conf });
  const j = await requestQuote({ base: ctx.base, req, token: ctx.token, fetchFn }); const q = j.quote;
  if (ctx.minRatio != null) {      // rate shown in the preview vs the real quote: abort BEFORE signing if it got worse
    const ratio = Number(BigInt(q.amountOut)) / Number(BigInt(q.amountIn));
    if (ratio < ctx.minRatio) throw new Error("the final quote is worse than the preview (" + (ratio * 100).toFixed(2) + "% vs " + (ctx.minRatio * 100).toFixed(2) + "%); nothing was sent");
  }
  say("Quote: send " + (Number(q.amountIn) / 1e6).toFixed(4) + ", receive " + (Number(q.amountOut) / 1e6).toFixed(4) + ", ~" + q.timeEstimate + " s. Signing the transfer…");
  const validBefore = Math.floor(Date.now() / 1000) + 3600;
  const auth = signTransferAuth({ chain: ctx.from, priv: ctx.priv, from: ctx.stealth, to: q.depositAddress, value: amount, validBefore, nonce: ctx.randomNonce() });
  say("Sending through the relayer (no gas for you)…");
  if (ctx.onSigned) ctx.onSigned({ auth, depositAddress: q.depositAddress, amount, validBefore });      // from here on the outcome of this transfer may be unknown to us: the caller arms its double-send guard
  const { r, d } = await postRelay(fetchFn, ctx.api + "/relay", auth, { onBusy: m => say(m), check: ctx.authUsed ? () => ctx.authUsed(ctx.stealth, auth.nonce) : null });
  const o = relayOutcome(r, d);
  if (o.kind === "error") { const e = new Error(o.message); if (o.definite) { e.refused = true; if (ctx.onRefused) ctx.onRefused(); } if (o.config) e.config = true; throw e; }      // refused: nothing left the stealth address
  if (o.kind === "used") {      // an earlier attempt of this same request went through: find its transaction by the authorization nonce, like the standard route
    d.hash = ctx.findTx ? await ctx.findTx(auth).catch(() => null) : null;
    if (!isHash(d.hash)) throw new Error("The relayer received the deposit transfer (its authorization is used on chain) but its transaction hash could not be found. Check the explorer; deposit address " + q.depositAddress + ".");
  }
  if (!isHash(d.hash)) throw new Error("the relayer answered without a valid transaction hash; check the explorer; deposit address " + q.depositAddress);
  say("Deposit sent (tx " + d.hash.slice(0, 12) + "…), waiting for the block…");
  const rc = await ctx.waitReceipt(d.hash); if (!rc.ok) throw new Error(rc.unexpected ? "the deposit transaction is mined but does not contain the expected transfer (tx " + d.hash.slice(0, 12) + "…). Check the explorer; deposit address " + q.depositAddress + "." : "the deposit transfer reverted (tx " + d.hash.slice(0, 12) + "…)");
  if (ctx.onDeposited) ctx.onDeposited({ depositAddress: q.depositAddress, txHash: rc.hash || d.hash });
  await submitDeposit({ base: ctx.base, txHash: d.hash, depositAddress: q.depositAddress, fetchFn }).catch(e => say("Could not notify NEAR Intents (" + e.message + "); it will still detect the deposit."));
  say("NEAR Intents is swapping (deposit address " + q.depositAddress + ")…");
  const fin = await pollStatus({ base: ctx.base, depositAddress: q.depositAddress, fetchFn, sleep, intervalMs: ctx.pollMs || 3000, onUpdate: s => say("Status: " + s.status + " (deposit address " + q.depositAddress.slice(0, 10) + "…)") });
  return { status: fin.status, depositAddress: q.depositAddress, txHash: d.hash, quote: q, final: fin };
}

// ---------------------------------------------------------------- route "private, fast": NEAR Intents only, no Zcash
/** 1-2 parts of random size, each with its own random delay (0..delayMaxMin) before its quote; parts go one after the other. The link is broken by the swap, not by cryptography.
 *  splitMin: below this the amount is not split (1Click fees and its minimum make tiny parts pointless). */
export const FAST = { kMin: 1, kMax: 2, delayMaxMin: 3, splitMin: 5_000_000n };
/** typical minutes of one part: quote, gasless deposit + block, 1Click swap (a real dry quote said timeEstimate 29-37 s; the rest is polling and the block) */
export const FAST_STEP_MIN = { QUOTE: 0.25, DEPOSIT: 0.75, SWAP: 1.5 };
/** the standard (direct, gasless) withdraw: relayer + one block, in seconds */
export const STANDARD_SEC = [10, 30];
const partMin = Object.values(FAST_STEP_MIN).reduce((a, b) => a + b, 0);
export const fastEtaRangeMin = () => [Math.round(partMin), Math.round(FAST.kMax * (FAST.delayMaxMin + partMin))];
export const fastEtaLabel = () => { const [a, b] = fastEtaRangeMin(); return a + "–" + b + " min"; };
export const standardEtaLabel = () => STANDARD_SEC[0] + "–" + STANDARD_SEC[1] + " s";
/** Plan of a fast withdraw: { parts: [{ amount (decimal string), delayMs, state:"PLANNED", depositAddress:null, txHash:null }] } */
export function fastPlan(total, rng = Math.random) {
  const k = total >= FAST.splitMin ? FAST.kMin + Math.min(FAST.kMax - FAST.kMin, Math.floor(rng() * (FAST.kMax - FAST.kMin + 1))) : 1;
  return randomSplit(total, k, rng).map(a => ({ amount: a.toString(), delayMs: randomDelayMs(FAST.delayMaxMin, rng), state: "PLANNED", depositAddress: null, txHash: null }));
}
export const FAST_OPEN = new Set(["PLANNED", "SIGNED", "DEPOSITED"]);
/** Runs (or, with `resume`, only follows) the parts of `rec` one after the other. `save(rec)` is called at every transition, so a closed tab loses nothing that was sent:
 *  DEPOSITED parts are followed to their end on resume (1Click swaps whether or not the tab is open); a PLANNED part that was never signed becomes NOT_SENT (its money never left the stealth address);
 *  a SIGNED part whose deposit we did not see confirmed becomes UNKNOWN (check the explorer and the deposit address).
 *  ctx = what runPart needs + { onProgress, onSigned, onDeposited }. Returns rec. Throws after saving when a part fails before the money left. */
export async function runFast(ctx, rec, save = () => {}, { resume = false } = {}) {
  const say = ctx.onProgress || (() => {}), n = rec.parts.length;
  for (let i = 0; i < n; i++) {
    const p = rec.parts[i], tag = n > 1 ? "Part " + (i + 1) + " of " + n + ": " : "";
    if (p.state === "SIGNED" && resume) { p.state = "UNKNOWN"; save(rec); continue; }
    if (p.state === "PLANNED" && resume) { p.state = "NOT_SENT"; save(rec); continue; }
    if (p.state === "DEPOSITED") {
      // 1130 M-2: a poll that gives up (10 errors in a row, or no terminal status within its bound) PARKS the part in STUCK (not in FAST_OPEN, depositAddress kept for the note): it must not block later fast withdraws forever
      try { const fin = await pollStatus({ base: ctx.base, depositAddress: p.depositAddress, fetchFn: ctx.fetchFn, sleep: ctx.sleep, intervalMs: ctx.pollMs || 3000, timeoutMs: ctx.pollTimeoutMs, onUpdate: s => say(tag + "Status: " + s.status) }); p.state = fin.status; }
      catch (e) { p.state = "STUCK"; p.stuckWhy = String((e && e.message) || e).slice(0, 160); }
      save(rec); continue;
    }
    if (p.state !== "PLANNED") continue;
    const c = { ...ctx, onProgress: m => say(tag + m),
      onSigned: info => { p.state = "SIGNED"; p.depositAddress = info.depositAddress; save(rec); if (ctx.onSigned) ctx.onSigned({ ...info, index: i }); },
      onDeposited: info => { p.state = "DEPOSITED"; p.depositAddress = info.depositAddress; p.txHash = info.txHash; save(rec); if (ctx.onDeposited) ctx.onDeposited({ ...info, index: i }); } };
    try { const r = await runPart(c, BigInt(p.amount), p.delayMs); p.state = r.status; p.final = r.status; save(rec); }
    catch (e) { if (p.state === "PLANNED" || (p.state === "SIGNED" && e.refused)) p.state = "NOT_SENT"; else if (p.state === "DEPOSITED") { p.state = "STUCK"; p.stuckWhy = String((e && e.message) || e).slice(0, 160); }      // DEPOSITED + a throw = the 1Click poll gave up (1130 M-2)
       for (const q of rec.parts) if (q.state === "PLANNED") q.state = "NOT_SENT"; save(rec); throw e; }      // the parts after a failed one are not started
  }
  return rec;
}
/** What happened, as lines for the screen. amountFmt(BigInt) formats a token amount. */
export function fastSummary(rec, amountFmt = v => v.toString(), sym = "") {
  const out = [], n = rec.parts.length, lbl = i => (n > 1 ? "Part " + (i + 1) + " of " + n + " (" : "(") + amountFmt(BigInt(rec.parts[i].amount)) + " " + sym + ")";
  rec.parts.forEach((p, i) => {
    const m = { SUCCESS: "was sent to the recipient.", REFUNDED: "was refunded by NEAR Intents: the money is back on the stealth address.", FAILED: "failed: check the status of deposit address " + p.depositAddress + ".",
      NOT_SENT: "was not sent: the money is still on the stealth address.", UNKNOWN: "was signed, but the deposit was not seen confirmed. Check the explorer and deposit address " + p.depositAddress + " before sending again.",
      STUCK: "was handed to NEAR Intents but no final status was seen. Check the status of deposit address " + p.depositAddress + " (the money may still arrive, be refunded to the stealth address, or need NEAR Intents support).",
      DEPOSITED: "is with NEAR Intents (deposit address " + p.depositAddress + ") and still swapping.", SIGNED: "was signed and handed to the relayer; the result is not known yet.", PLANNED: "has not started yet." }[p.state] || p.state;
    out.push(lbl(i) + " " + m);
  });
  return out;
}
/** 1125 F-1: a stored record that still has an open part (a new withdraw from the same address must not replace it) */
export const fastOpenRec = rec => !!rec && Array.isArray(rec.parts) && rec.parts.some(p => FAST_OPEN.has(p.state));
export const fastDone = rec => rec.parts.every(p => !FAST_OPEN.has(p.state));

/** 1130 M-2: the explicit "abandon this record" action. Every open part gets the state that tells the truth about it and closes it: DEPOSITED -> STUCK (deposit address kept for the note),
 *  SIGNED -> UNKNOWN (the transfer may still land), PLANNED -> NOT_SENT. The caller keeps the notes and the double-send guard (UNKNOWN). Returns rec. */
export function abandonRec(rec, save = () => {}) {
  for (const p of rec.parts) { if (p.state === "DEPOSITED") p.state = "STUCK"; else if (p.state === "SIGNED") p.state = "UNKNOWN"; else if (p.state === "PLANNED") p.state = "NOT_SENT"; }
  save(rec); return rec;
}
