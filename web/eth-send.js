/* A plain ETH transfer signed by a stealth key and sent from the page (no relayer, no EIP-3009: native ETH has no authorization). No DOM, no network of its own: every function takes `rpc(method, params) -> result` (throws on an RPC error, with e.rpc = true when the node answered with an error).
   Legacy (type 0, EIP-155) transaction: accepted by every EVM node, one rule for the fee. The nonce is read at "latest", never "pending", so a transaction that is stuck or whose answer was lost is REPLACED by the next one instead of being followed by a second payment:
   one nonce can be mined once, so a re-sent or re-signed transfer can never pay twice. The signed bytes are saved by the caller BEFORE the first broadcast and only ever re-sent as they are. */
import { keccak, signDigest, unhex, hex } from "./stealth-crypto.js";

const cat = list => { const o = new Uint8Array(list.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of list) { o.set(x, i); i += x.length; } return o; };
/** minimal big-endian bytes of a non-negative integer (0 -> empty, as RLP wants it) */
export const be = n => { n = BigInt(n); if (n < 0n) throw new Error("negative number"); const h = n.toString(16); return n === 0n ? new Uint8Array(0) : unhex("0x" + (h.length % 2 ? "0" : "") + h); };
const lenPrefix = (len, off) => len < 56 ? Uint8Array.of(off + len) : (b => cat([Uint8Array.of(off + 55 + b.length), b]))(be(len));
/** RLP of a byte string (Uint8Array) or a list of them (nested arrays) */
export function rlp(x) {
  if (x instanceof Uint8Array) return x.length === 1 && x[0] < 0x80 ? x : cat([lenPrefix(x.length, 0x80), x]);
  const body = cat(x.map(rlp)); return cat([lenPrefix(body.length, 0xc0), body]);
}
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), ZERO = "0x0000000000000000000000000000000000000000";
const big = (x, what) => { if (!/^0x[0-9a-fA-F]{1,64}$/.test(String(x))) throw new Error("unexpected " + what + " from the RPC"); return BigInt(x); };
const hx = n => "0x" + BigInt(n).toString(16);

/** Signs a legacy transaction with the stealth key. -> { raw (0x…), hash, nonce, to, value, gasLimit, gasPrice } (all numbers as decimal strings, so a record can be saved as JSON) */
export function signLegacyTx({ priv, chainId, nonce, gasPrice, gasLimit, to, value }) {
  if (!isAddr(to) || to.toLowerCase() === ZERO) throw new Error("bad destination address");
  const f = [be(nonce), be(gasPrice), be(gasLimit), unhex(to), be(value), new Uint8Array(0)];
  const s = signDigest(keccak(rlp([...f, be(chainId), be(0), be(0)])), unhex(priv)), v = BigInt(s.v - 27) + 35n + 2n * BigInt(chainId);
  const raw = rlp([...f, be(v), be(BigInt(s.r)), be(BigInt(s.s))]);
  return { raw: hex(raw), hash: hex(keccak(raw)), nonce: String(nonce), to: to.toLowerCase(), value: String(value), gasLimit: String(gasLimit), gasPrice: String(gasPrice) };
}

/** Why these two margins (nothing here is measured; they only decide how much ETH is kept back, and a transfer that needs less simply leaves the rest on the address):
 *  GAS_LIMIT_PCT: gas limit = the node's estimate + 25 %. On an Arbitrum Orbit chain the estimate also prices the data posted to the parent chain, which moves between the estimate and the block.
 *  PRICE_X: max gas price = 2 x the node's current price (the EIP-1559 base fee can rise 12.5 % per block, 2x covers about six blocks of it). Unused gas is refunded, so a margin costs nothing when it is not needed. */
export const GAS_LIMIT_PCT = 125n, PRICE_X = 2n;
/** Gas limit, price and the worst-case fee of sending `value` wei from `from` to `to`. */
export async function planFee(rpc, { from, to, value }) {
  const [est, gp] = await Promise.all([rpc("eth_estimateGas", [{ from, to, value: hx(value) }]), rpc("eth_gasPrice", [])]);
  const gasLimit = big(est, "gas estimate") * GAS_LIMIT_PCT / 100n, gasPrice = big(gp, "gas price") * PRICE_X;
  if (gasLimit <= 0n || gasPrice <= 0n) throw new Error("the RPC gave no usable gas figures");
  return { gasLimit, gasPrice, fee: gasLimit * gasPrice };
}
/** What can be sent from `balance` when the user asks for "all": the balance minus the worst-case fee (estimated against `to`, with 1 wei as the value). null when the balance does not even cover the fee. */
export async function sendableAll(rpc, { from, to, balance }) {
  const p = await planFee(rpc, { from, to, value: 1n }); return balance > p.fee ? { value: balance - p.fee, fee: p.fee } : null;
}
/** Reads the nonce, plans the fee against the REAL destination, checks the balance covers value + fee, signs. Sends nothing. Throws before signing when the balance is short. */
export async function prepareSend(rpc, { priv, chainId, from, to, value }) {
  if (!(BigInt(value) > 0n)) throw new Error("bad amount");
  const [bal, cnt, p] = await Promise.all([rpc("eth_getBalance", [from, "latest"]), rpc("eth_getTransactionCount", [from, "latest"]), planFee(rpc, { from, to, value })]);
  if (big(bal, "balance") < BigInt(value) + p.fee) throw Object.assign(new Error("not enough ETH on this address for the amount plus the network fee (about " + p.fee + " wei). Nothing was sent. Send a little less."), { short: true });
  return signLegacyTx({ priv, chainId, nonce: big(cnt, "nonce"), gasPrice: p.gasPrice, gasLimit: p.gasLimit, to, value });
}
const KNOWN = /already known|known transaction|already imported|AlreadyKnown|already in (the )?(mempool|pool)/i;
/** eth_sendRawTransaction of the SAME saved bytes. "already known" counts as sent. Any other RPC error rethrown with e.rpc = true (the node refused it: nothing was accepted); a network failure has no e.rpc (outcome unknown). */
export async function sendRaw(rpc, tx) {
  try { const h = await rpc("eth_sendRawTransaction", [tx.raw]); if (h && String(h).toLowerCase() !== tx.hash.toLowerCase()) throw Object.assign(new Error("the node returned another transaction hash than the one signed"), { rpc: true, mismatch: true }); }
  catch (e) { if (KNOWN.test(String((e && e.message) || e))) return; throw e; }
}
/** Where a saved transfer stands: "mined" (receipt, success) | "failed" (mined, reverted: nothing moved) | "pending" (the node knows it) | "dead" (its nonce was used by another transaction: it can never be mined) | "unsent" (unknown to the node, nonce still free: safe to send the same bytes again).
 *  "dead" is only believed after a second look `sleep` later (a lagging node can count a nonce before it serves the receipt). */
export async function txStatus(rpc, { from, hash, nonce }, { sleep = ms => new Promise(r => setTimeout(r, ms)), recheckMs = 3000 } = {}) {
  const look = async () => {
    const rc = await rpc("eth_getTransactionReceipt", [hash]);
    if (rc && String(rc.transactionHash || "").toLowerCase() === hash.toLowerCase()) return rc.status === "0x1" ? "mined" : rc.status === "0x0" ? "failed" : "pending";
    const t = await rpc("eth_getTransactionByHash", [hash]); if (t && String(t.hash || "").toLowerCase() === hash.toLowerCase()) return "pending";
    return big(await rpc("eth_getTransactionCount", [from, "latest"]), "nonce") > BigInt(nonce) ? "dead" : "unsent";
  };
  const a = await look(); if (a !== "dead") return a;
  await sleep(recheckMs); const b = await look(); return b;
}
/** Is this RPC error a definite refusal (the node answered and did not accept the transaction)? */
export const refused = e => !!(e && e.rpc === true && !KNOWN.test(String(e.message || "")));
