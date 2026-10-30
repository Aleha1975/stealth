/* Reads straight from the chain's JSON-RPC (audit 1098 M-2, L-4): balances, authorization state, receipts and the events that prove a payment.
   Nothing here talks to our indexer/API, so the operator never learns which stealth addresses belong together, and a hostile API cannot
   invent a "Done". `rpc(method, params)` -> result (throws on an RPC error); `batch([[method, params], ...])` -> results (same order). No DOM. */
import { keccak_256 } from "./vendor/noble.js";

const enc = s => new TextEncoder().encode(s);
const hexOf = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
export const topic = sig => "0x" + hexOf(keccak_256(enc(sig)));
export const TRANSFER_TOPIC = topic("Transfer(address,address,uint256)");
export const PAID_TOPIC = topic("Paid(address,address,uint256)");           // StealthPay: Paid(stealthAddress indexed, token indexed, amount)
export const AUTH_USED_TOPIC = topic("AuthorizationUsed(address,bytes32)");   // EIP-3009: AuthorizationUsed(authorizer indexed, nonce indexed)
export const FETCH_TIMEOUT_MS = 15000;
export const timeoutSignal = (ms = FETCH_TIMEOUT_MS) => typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(ms) : undefined;     // 1101 L-5: no chain/API fetch may hang forever
export const ETH_TOKEN = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";      // the sentinel StealthPay uses for native payments (metadata selector 0xeeeeeeee)
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), isHash = h => /^0x[0-9a-fA-F]{64}$/.test(h || "");
const pad = a => a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const word = x => /^0x[0-9a-fA-F]{1,64}$/.test(x) ? BigInt(x) : (() => { throw new Error("unexpected RPC answer"); })();
const topicAddr = t => typeof t === "string" && /^0x0{24}[0-9a-fA-F]{40}$/.test(t) ? "0x" + t.slice(26).toLowerCase() : null;

/** Balances of many addresses: { token units, native } per lowercase address, read from the chain (one batch if the RPC allows it). */
export async function getBalances(batch, token, addrs) {
  const calls = []; for (const a of addrs) { if (!isAddr(a)) throw new Error("bad address"); calls.push(["eth_call", [{ to: token, data: "0x70a08231" + pad(a) }, "latest"]], ["eth_getBalance", [a, "latest"]]); }
  const res = calls.length ? await batch(calls) : [];
  if (!Array.isArray(res) || res.length !== calls.length) throw new Error("unexpected RPC batch answer");
  const out = new Map();
  addrs.forEach((a, i) => out.set(a.toLowerCase(), { usdc: word(res[2 * i]), eth: word(res[2 * i + 1]) }));
  return out;
}
/** JSON-RPC batch over fetch with strict validation; any irregularity throws so the caller can fall back to single calls. */
export async function fetchBatch(fetchFn, url, calls) {
  const body = calls.map(([method, params], i) => ({ jsonrpc: "2.0", id: i + 1, method, params }));
  const r = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: timeoutSignal() });
  if (!r.ok) throw new Error("rpc " + r.status);
  const j = await r.json(); if (!Array.isArray(j) || j.length !== calls.length) throw new Error("unexpected RPC batch answer");
  const out = new Array(calls.length);
  for (const x of j) { if (!x || !Number.isInteger(x.id) || x.id < 1 || x.id > calls.length || out[x.id - 1] !== undefined || x.error || x.result === undefined || x.result === null) throw new Error("bad RPC batch entry"); out[x.id - 1] = x.result; }
  return out;
}
const AUTH_STATE = "0xe94a0102";          // authorizationState(address,bytes32)
/** Is this EIP-3009 authorization (authorizer, nonce) used (or cancelled) on the token? */
export async function authorizationUsed(rpc, token, authorizer, nonce) {
  if (!isAddr(authorizer) || !isHash(nonce)) throw new Error("bad authorization");
  return word(await rpc("eth_call", [{ to: token, data: AUTH_STATE + pad(authorizer) + nonce.slice(2).toLowerCase() }, "latest"])) !== 0n;
}
/** The receipt of `hash`, validated against the hash we asked for; null while not mined. */
export async function fetchReceipt(rpc, hash) {
  if (!isHash(hash)) throw new Error("bad transaction hash");
  const r = await rpc("eth_getTransactionReceipt", [hash]);
  if (r === null || r === undefined) return null;
  if (!r || String(r.transactionHash || "").toLowerCase() !== hash.toLowerCase() || !Array.isArray(r.logs) || (r.status !== "0x1" && r.status !== "0x0")) throw new Error("unexpected receipt from the RPC");
  return { hash: hash.toLowerCase(), ok: r.status === "0x1", logs: r.logs, from: String(r.from || "").toLowerCase(), block: r.blockNumber };
}
/** A successful ERC-20 Transfer(token, from?, to, value) is in the receipt. Leave `from` null to accept any sender. */
export const hasTransfer = (rc, { token, from = null, to, value = null }) => !!rc && rc.ok && rc.logs.some(l => l && String(l.address).toLowerCase() === token.toLowerCase() && Array.isArray(l.topics) && l.topics.length === 3 &&
  String(l.topics[0]).toLowerCase() === TRANSFER_TOPIC && (from === null || topicAddr(l.topics[1]) === from.toLowerCase()) && topicAddr(l.topics[2]) === to.toLowerCase() && (value === null || (/^0x[0-9a-fA-F]{1,64}$/.test(l.data) && BigInt(l.data) === BigInt(value))));
/** The token emitted AuthorizationUsed(authorizer, nonce) in this receipt: binds a receipt to ONE signed request, so an earlier identical transfer cannot stand in for it (1101 L-1). */
export const hasAuthUsed = (rc, { token, authorizer, nonce }) => !!rc && rc.ok && rc.logs.some(l => l && String(l.address).toLowerCase() === token.toLowerCase() && Array.isArray(l.topics) && l.topics.length === 3 &&
  String(l.topics[0]).toLowerCase() === AUTH_USED_TOPIC && topicAddr(l.topics[1]) === authorizer.toLowerCase() && String(l.topics[2]).toLowerCase() === String(nonce).toLowerCase());
/** StealthPay's Paid(stealth, token, amount) for this stealth address (token = the ERC-20, or ETH_TOKEN for native; amount optional). */
export const hasPaid = (rc, { stealthPay, stealth, token = null, amount = null }) => !!rc && rc.ok && rc.logs.some(l => l && String(l.address).toLowerCase() === stealthPay.toLowerCase() && Array.isArray(l.topics) && l.topics.length === 3 &&
  String(l.topics[0]).toLowerCase() === PAID_TOPIC && topicAddr(l.topics[1]) === stealth.toLowerCase() && (token === null || topicAddr(l.topics[2]) === token.toLowerCase()) && (amount === null || (/^0x[0-9a-fA-F]{1,64}$/.test(l.data) && BigInt(l.data) === BigInt(amount))));
/** Recent logs (last `span` blocks) of one address and topic list: how a request whose answer was lost is matched to its transaction. */
export async function recentLogs(rpc, { address, topics, span = 5000 }) {
  const tip = Number(word(await rpc("eth_blockNumber", [])));
  const r = await rpc("eth_getLogs", [{ address, topics, fromBlock: "0x" + Math.max(0, tip - span).toString(16), toBlock: "0x" + tip.toString(16) }]);
  if (!Array.isArray(r)) throw new Error("unexpected logs answer"); return r.filter(l => l && isHash(l.transactionHash));
}
/** Wait for the final receipt of `hash` on the chain. `expect(receipt)` must be true for a success, otherwise a mined transaction does not count as the thing we wanted.
 *  A replacement hash offered by the API (`follow()` -> hash) is polled only if the chain says it came from the same sender with the same nonce as the original transaction.
 *  -> { ok, hash } ; throws on timeout. */
export async function waitFinal(rpc, hash, { expect = null, follow = null, sleep = ms => new Promise(r => setTimeout(r, ms)), tries = 60, everyMs = 2000 } = {}) {
  let orig = null; const first = hash, polled = [hash];             // 1101 L-4: the original stays polled after a replacement is followed (it may still be the one that mines)
  const tx = async h => { const t = await rpc("eth_getTransactionByHash", [h]); return t && String(t.hash || "").toLowerCase() === h.toLowerCase() ? { from: String(t.from).toLowerCase(), nonce: String(t.nonce) } : null; };
  for (let i = 0; i < tries; i++) {
    for (const h of polled) {
      const rc = await fetchReceipt(rpc, h);
      if (rc) { if (!rc.ok) return { ok: false, hash: rc.hash }; if (expect && !expect(rc)) return { ok: false, hash: rc.hash, unexpected: true }; return { ok: true, hash: rc.hash, receipt: rc }; }
    }
    if (!orig) orig = await tx(first).catch(() => null);
    if (follow && i % 3 === 2 && orig) {
      const nh = await follow().catch(() => null);
      if (isHash(nh) && !polled.some(h => h.toLowerCase() === nh.toLowerCase())) { const t = await tx(nh).catch(() => null); if (t && t.from === orig.from && t.nonce === orig.nonce) polled.push(nh); }   // 1098 L-4: same sender AND nonce, checked on chain
    }
    await sleep(everyMs);
  }
  throw new Error("not mined yet: " + first);
}
