/* One-signature payment: pure helpers shared by the browser (app.js) and the Node e2e test (server/test_pay_e2e.mjs),
   so both sign/hash exactly the same bytes. No DOM, no wallet access here.
   paymentNonce mirrors StealthPay.paymentNonce (abi.encode of 9 words; bytes1 is left-aligned). */
import { keccak, hex, unhex } from "./stealth-crypto.js";
const te = new TextEncoder();
const w = v => (typeof v === "bigint" ? v : BigInt(v)).toString(16).padStart(64, "0");
const a32 = a => a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const k = b => hex(keccak(b)).slice(2);
export const PAYMENT_NONCE_TAG = "StealthPay.payWithAuthorization";
/** keccak256(abi.encode(keccak256(tag), chainid, stealthPay, token, stealth, keccak256(eph), viewTag, fee, feeRecipient)) -> 0x… */
export function paymentNonce({ chainId, stealthPay, token, stealth, eph, viewTag, fee, feeRecipient }) {
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
