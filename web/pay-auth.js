/* One-signature payment: pure helpers shared by the browser (app.js) and the Node e2e test (server/test_pay_e2e.mjs),
   so both sign/hash exactly the same bytes. No DOM, no wallet access here.
   paymentNonce mirrors StealthPay.paymentNonce (abi.encode of 9 words; bytes1 is left-aligned). */
import { keccak, hex, unhex } from "./stealth-crypto.js";
const te = new TextEncoder();
// audit 1086 I-3: validate instead of silently producing a wrong nonce (negative, non-integer, over-long or non-hex input throws)
const w = v => { const b = typeof v === "bigint" ? v : BigInt(v); if (b < 0n || b >= 1n << 256n) throw new Error("number out of range"); return b.toString(16).padStart(64, "0"); };
const a32 = a => { if (!/^0x[0-9a-fA-F]{40}$/.test(String(a))) throw new Error("bad address"); return a.toLowerCase().replace(/^0x/, "").padStart(64, "0"); };
const k = b => hex(keccak(b)).slice(2);
export const PAYMENT_NONCE_TAG = "StealthPay.payWithAuthorization";
/** keccak256(abi.encode(keccak256(tag), chainid, stealthPay, token, stealth, keccak256(eph), viewTag, fee, feeRecipient)) -> 0x… */
export function paymentNonce({ chainId, stealthPay, token, stealth, eph, viewTag, fee, feeRecipient }) {
  if (!/^0x[0-9a-fA-F]{2}$/.test(String(viewTag))) throw new Error("bad view tag");
  if (!/^0x[0-9a-fA-F]+$/.test(String(eph)) || eph.length % 2) throw new Error("bad ephemeral key");
  const enc = "0x" + k(te.encode(PAYMENT_NONCE_TAG)) + w(chainId) + a32(stealthPay) + a32(token) + a32(stealth) + k(unhex(eph)) +
    viewTag.replace(/^0x/, "").padEnd(64, "0") + w(fee) + a32(feeRecipient);
  return "0x" + k(unhex(enc));
}
export const RECEIVE_TYPES = {
  EIP712Domain: [{ name: "name", type: "string" }, { name: "version", type: "string" }, { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }],
  ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }],
};
/** Typed data (JSON string) for eth_signTypedData_v4: payer authorises `amount` of the token to StealthPay, bound to the payment nonce. */
export function receiveTypedData({ token, chainId, from, stealthPay, amount, validAfter, validBefore, nonce }) {
  return JSON.stringify({ types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization",
    domain: { name: token.domainName, version: token.domainVersion, chainId: String(chainId), verifyingContract: token.address },
    message: { from, to: stealthPay, value: String(amount), validAfter: String(validAfter), validBefore: String(validBefore), nonce } });
}
/** The EIP-712 digest of the same typed data (for Node-side signing in tests and cross-checks). */
export function receiveDigest(p) {
  const td = JSON.parse(receiveTypedData(p)), d = td.domain, m = td.message;
  const dom = k(te.encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")) + k(te.encode(d.name)) + k(te.encode(d.version)) + w(d.chainId) + a32(d.verifyingContract);
  const th = k(te.encode("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));
  const st = th + a32(m.from) + a32(m.to) + w(m.value) + w(m.validAfter) + w(m.validBefore) + m.nonce.slice(2);
  return keccak(unhex("0x1901" + k(unhex("0x" + dom)) + k(unhex("0x" + st))));
}
/** Split a 65-byte wallet signature into {v,r,s}. */
export function splitSig(sig) {
  const h = sig.replace(/^0x/, ""); if (h.length !== 130) throw new Error("unexpected signature length");
  let v = parseInt(h.slice(128), 16); if (v < 27) v += 27;
  return { r: "0x" + h.slice(0, 64), s: "0x" + h.slice(64, 128), v };
}
/** The two linked amount fields ("you pay" / "receiver gets"). `src` is the field the user typed in ("amount" = you pay, "amount-get" = receiver gets).
 *  Exact decimal parsing (no floats). Typing in "you pay" means exactly that much leaves the wallet: send = typed, get = typed - fee (the fee is
 *  taken OUT of it by StealthPay.payWithAuthorization). Typing in "receiver gets" means send = typed + fee. Returns {send,get,fee} in token units, or null. */
export function payAmounts({ src, text, decimals, fee, bps = 0 }) {
  const m = /^(\d*)(?:\.(\d*))?$/.exec(String(text || "").trim().replace(",", "."));
  if (!m || (!m[1] && !m[2])) return null;
  const raw = BigInt((m[1] || "0") + (m[2] || "").slice(0, decimals).padEnd(decimals, "0"));
  if (raw <= 0n) return null;
  if (!bps) return src === "amount-get" ? { send: raw + fee, get: raw, fee } : { send: raw, get: raw - fee, fee };   // fixed fee (the relayer's default): exactly as before
  if (src !== "amount-get") { const f = payFeeFor(raw, fee, bps); return { send: raw, get: raw - f, fee: f }; }
  let send = raw + fee; for (let i = 0; i < 40; i++) { const next = raw + payFeeFor(send, fee, bps); if (next === send) break; send = next; }   // fee depends on what leaves the wallet: fixed point (monotone, converges at once)
  return { send, get: raw, fee: send - raw };
}
/** The relayer's pay fee for a payment of `amount` token units: the flat fee it offers (/relay/stats pay_fee, also its minimum) or `bps` basis points of the amount (rounded UP), whichever is larger.
 *  Same formula as payFeeFor in server/relay-util.mjs (a test keeps the two equal). bps 0 = the flat fee only. */
export const payFeeFor = (amount, flat, bps = 0) => { const p = (BigInt(amount) * BigInt(bps) + 9999n) / 10000n; return p > BigInt(flat) ? p : BigInt(flat); };
/** Client-side cap on the relayer's fee (audit 1086 L-1): the fee and its recipient come from our relayer API, so a compromised API must not be able to take (almost) the whole
 *  payment. Refused when the fee is above `maxAbs` token units (default 1.00 with 6 decimals) or above half of what leaves the wallet. */
export const feeWithinCap = (fee, raw, maxAbs = 1_000_000n, pctCapBps = 0) => fee >= 0n && (fee <= maxAbs || fee * 10000n <= raw * BigInt(pctCapBps)) && fee * 2n <= raw;   // pctCapBps: a percentage fee announced by the relayer may exceed maxAbs, but never this share of the payment (0 = no such allowance)
