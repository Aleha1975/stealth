/* Private withdraw from a stealth address through NEAR Intents 1Click (https://docs.near-intents.org).
   The stealth key signs an EIP-3009 transferWithAuthorization to the quote's deposit address; OUR relayer submits it (no gas for the user);
   1Click then pays the destination on the destination chain. The refund address of every quote is the stealth address itself, never a main wallet.
   This file has no DOM access: every function takes what it needs (fetch, sleep, rng) so it runs in the browser and in Node tests.
   Honest limits: the deposit and the payout are both public on-chain; with confidentiality "public" they can be matched by amount and time.
   confidentiality "basic" needs a User-Session token (sessionSignIn below) and is OFF in the app until SESSION_SIGNIN is switched on. */
import { keccak, signDigest, unhex, hex } from "./stealth-crypto.js";
import { postRelay } from "./relay-post.js";

export const ONECLICK = "https://1click.chaindefuser.com";
export const NEAR_RPCS = ["https://rpc.mainnet.near.org", "https://free.rpc.fastnear.com"];   // read-only: current_salt of intents.near
export const INTENTS_CONTRACT = "intents.near";
export const SESSION_SIGNIN = false;          // the app only calls authenticate() when this is true (nothing is sent to /v0/auth/* today)
export const MIN_PART = 1_000_000n;           // smallest split part (1 token, 6 decimals); 1Click refuses tiny swaps ("at least 150000")
export const TERMINAL = new Set(["SUCCESS", "REFUNDED", "FAILED"]);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || "");

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
export function buildQuoteRequest({ from, to, amount, recipient, refundTo, dry, confidentiality = "public", now = Date.now(), deadlineMs = 3600_000 }) {
  if (!from.oneClick || !to.oneClick) throw new Error("private withdraw is not available on " + (from.oneClick ? to.name : from.name));
  if (!isAddr(recipient) || !isAddr(refundTo)) throw new Error("bad address");
  if (!(amount > 0n)) throw new Error("bad amount");
  return { dry: !!dry, swapType: "EXACT_INPUT", slippageTolerance: 100, originAsset: from.oneClick.assetId, depositType: "ORIGIN_CHAIN",
    destinationAsset: to.oneClick.assetId, amount: amount.toString(), refundTo, refundType: "ORIGIN_CHAIN", recipient, recipientType: "DESTINATION_CHAIN",
    deadline: new Date(now + deadlineMs).toISOString(), confidentiality };
}
async function call(fetchFn, url, init) {
  const r = await fetchFn(url, init); const j = await r.json().catch(() => ({}));
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
  const { r, d } = await postRelay(fetchFn, ctx.api + "/relay", auth, { onBusy: m => say(m), check: ctx.authUsed ? () => ctx.authUsed(ctx.stealth, auth.nonce) : null });
  if (d.used) throw new Error("The relayer received the deposit transfer (its authorization is used on chain) but its transaction hash was lost. Check the explorer; deposit address " + q.depositAddress + ".");
  if (!r.ok || d.error) throw new Error(d.error || "relayer error");
  say("Deposit sent (tx " + d.hash.slice(0, 12) + "…), waiting for the block…");
  const rc = await ctx.waitReceipt(d.hash); if (!rc.ok) throw new Error("the deposit transfer reverted (tx " + d.hash.slice(0, 12) + "…)");
  await submitDeposit({ base: ctx.base, txHash: d.hash, depositAddress: q.depositAddress, fetchFn }).catch(e => say("Could not notify NEAR Intents (" + e.message + "); it will still detect the deposit."));
  say("NEAR Intents is swapping (deposit address " + q.depositAddress + ")…");
  const fin = await pollStatus({ base: ctx.base, depositAddress: q.depositAddress, fetchFn, sleep, intervalMs: ctx.pollMs || 3000, onUpdate: s => say("Status: " + s.status + " (deposit address " + q.depositAddress.slice(0, 10) + "…)") });
  return { status: fin.status, depositAddress: q.depositAddress, txHash: d.hash, quote: q, final: fin };
}
