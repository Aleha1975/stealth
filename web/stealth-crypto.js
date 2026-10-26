/* Stealth: ERC-5564 scheme 1 (secp256k1 + view tag) in the browser. Keys never leave the device.
   Math, as in EIP-5564: S = p_eph · P_view (33-byte compressed point); s_h = keccak256(S); view tag = s_h[0];
   P_stealth = P_spend + s_h·G; address = keccak256(uncompressed P_stealth without 0x04)[12:].
   Receiver: S' = p_view · P_eph; same hash; p_stealth = (p_spend + s_h) mod n. Verified against a Python
   reference (coincurve) with fixed vectors in selftest.html. */
import * as secp from "https://esm.sh/@noble/secp256k1@2.2.3";
import { keccak_256 } from "https://esm.sh/@noble/hashes@1.7.1/sha3";
import { hmac } from "https://esm.sh/@noble/hashes@1.7.1/hmac";
import { sha256 } from "https://esm.sh/@noble/hashes@1.7.1/sha256";

// noble v2 needs these hooks for signing / randomness in some builds
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));

const N = secp.CURVE.n;
export const hex = b => "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
export const unhex = h => { h = h.startsWith("0x") ? h.slice(2) : h; if (h.length % 2) h = "0" + h; return Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16)); };
const toBig = b => BigInt(hex(b));
const toBytes32 = n => unhex(n.toString(16).padStart(64, "0"));
const mod = (a, m) => ((a % m) + m) % m;

export function addressOf(pubCompressed) {
  const P = secp.ProjectivePoint.fromHex(pubCompressed);
  const un = P.toRawBytes(false);              // 65 bytes, 0x04 || X || Y
  return toChecksum(hex(keccak_256(un.slice(1)).slice(12)));
}
export function toChecksum(addr) {
  const a = addr.toLowerCase().replace(/^0x/, "");
  const h = hex(keccak_256(new TextEncoder().encode(a))).slice(2);
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}
function hashedShared(privBytes, pubCompressed) {
  const S = secp.getSharedSecret(privBytes, pubCompressed, true);   // 33-byte compressed point
  return keccak_256(S);
}

/** Receiver: keys from one wallet signature (deterministic). spend = keccak(sig || "spend"), view = keccak(sig || "view"), reduced mod n. */
export function keysFromSignature(sigHex) {
  const sig = unhex(sigHex);
  const tag = s => new TextEncoder().encode(s);
  const d = (t) => toBytes32(mod(toBig(keccak_256(secp.etc.concatBytes(sig, tag(t)))), N) || 1n);
  const spendPriv = d("deepyield-stealth/spend/v1"), viewPriv = d("deepyield-stealth/view/v1");
  return { spendPriv, viewPriv, spendPub: secp.getPublicKey(spendPriv, true), viewPub: secp.getPublicKey(viewPriv, true) };
}
/** Meta-address: st:base:0x<P_spend><P_view> (66 bytes). */
export const metaAddress = (keys, chain = "base") => "st:" + chain + ":" + hex(secp.etc.concatBytes(keys.spendPub, keys.viewPub));
export function parseMeta(s) {
  const m = String(s).trim().match(/^(?:st:[a-z0-9]+:)?(0x[0-9a-fA-F]{132})$/);
  if (!m) throw new Error("not a stealth meta-address");
  const b = unhex(m[1]);
  return { spendPub: b.slice(0, 33), viewPub: b.slice(33, 66) };
}

/** Sender: one-time address for this payment. Returns {stealth, ephPub (33 bytes hex), viewTag (0x..)}. */
export function deriveForPayment(metaOrParsed, ephPriv = secp.utils.randomPrivateKey()) {
  const { spendPub, viewPub } = typeof metaOrParsed === "string" ? parseMeta(metaOrParsed) : metaOrParsed;
  const sh = hashedShared(ephPriv, viewPub);
  const P = secp.ProjectivePoint.fromHex(spendPub).add(secp.ProjectivePoint.fromPrivateKey(sh));
  return { stealth: addressOf(P.toRawBytes(true)), ephPub: hex(secp.getPublicKey(ephPriv, true)), viewTag: "0x" + sh[0].toString(16).padStart(2, "0") };
}

/** Receiver: does this announcement pay me? Returns {stealth, stealthPriv} or null. Cheap view-tag check first. */
export function checkAnnouncement(keys, ephPubHex, viewTagHex) {
  const ephPub = unhex(ephPubHex);
  if (ephPub.length !== 33) return null;
  let sh;
  try { sh = hashedShared(keys.viewPriv, ephPub); } catch { return null; }
  if (viewTagHex && (sh[0] !== parseInt(viewTagHex, 16))) return null;
  const P = secp.ProjectivePoint.fromHex(keys.spendPub).add(secp.ProjectivePoint.fromPrivateKey(sh));
  const stealth = addressOf(P.toRawBytes(true));
  const priv = toBytes32(mod(toBig(keys.spendPriv) + toBig(sh), N));
  return { stealth, stealthPriv: hex(priv) };
}

/** ERC-5564 metadata for a token payment: viewTag | 0xa9059cbb | token | amount (57 bytes). Decode helper. */
export function decodeMetadata(metaHex) {
  const b = unhex(metaHex);
  if (b.length < 1) return null;
  const out = { viewTag: "0x" + b[0].toString(16).padStart(2, "0") };
  if (b.length >= 57) {
    out.selector = hex(b.slice(1, 5)); out.token = toChecksum(hex(b.slice(5, 25))); out.amount = toBig(b.slice(25, 57));
    if (out.selector === "0xeeeeeeee") out.token = "ETH";
  }
  return out;
}
export const secpUtils = secp;
export const keccak = keccak_256;
/** Sign a 32-byte digest with a raw private key (for EIP-3009 authorizations from a stealth address). */
export function signDigest(digestBytes, privBytes) {
  const sig = secp.sign(digestBytes, privBytes, { lowS: true });
  return { r: "0x" + sig.r.toString(16).padStart(64, "0"), s: "0x" + sig.s.toString(16).padStart(64, "0"), v: 27 + sig.recovery };
}
export const randomBytes32 = () => hex(secp.utils.randomPrivateKey());
