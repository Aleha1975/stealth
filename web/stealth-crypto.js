/* Stealth: ERC-5564 scheme 1 (secp256k1 + view tag) in the browser. Keys never leave the device.
   Math, as in EIP-5564: S = p_eph · P_view (33-byte compressed point); s_h = keccak256(S); view tag = s_h[0];
   P_stealth = P_spend + s_h·G; address = keccak256(uncompressed P_stealth without 0x04)[12:].
   Receiver: S' = p_view · P_eph; same hash; p_stealth = (p_spend + s_h) mod n. Verified against a Python
   reference (coincurve) with fixed vectors in selftest.html. */
import { secp256k1 as secp, keccak_256, concatBytes } from "./vendor/noble.js";   // vendored @noble/curves 1.8.1 + @noble/hashes 1.7.1, see vendor/SHA256SUMS

const N = secp.CURVE.n;
export const hex = b => "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
// audit 1086 I-1: strict. Garbage from an untrusted indexer used to turn into zero bytes (a different, valid-looking value); now it throws, callers that scan wrap it.
export const unhex = h => { h = String(h); h = h.startsWith("0x") ? h.slice(2) : h; if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error("not hex"); if (h.length % 2) h = "0" + h; return Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16)); };
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

// ---- key derivation from ONE wallet signature over EIP-712 typed data (domain-labelled in the wallet UI)
// audit 1086 M-1 (key-request phishing), DECISION: not changed. The keys are a pure function of this exact typed data, so adding an origin / contract / salt to it would give every
// existing user DIFFERENT keys and strand their money; an unbound request cannot be told apart from ours by the wallet. What we do instead: the page tells the user to sign only on its own
// host (app.js), and the typed data names the rule in `purpose`. A future opt-in "v2" request (origin-bound, new meta-address) can be offered next to this one, never replace it.
export const KEY_DOMAIN = { name: "DeepYield Stealth", version: "1" };   // no chainId: wallets refuse typed data whose chainId differs from the active chain, and the same wallet must get the same keys on every chain;
export const KEY_TYPES = { StealthKeys: [{ name: "purpose", type: "string" }, { name: "account", type: "address" }] };
export const KEY_PURPOSE = "Derive my private stealth receiving keys. Never sign this on another site.";
const utf8 = s => new TextEncoder().encode(s);
const encType = "StealthKeys(string purpose,address account)";
/** EIP-712 digest of the key-derivation request for `account` (what the wallet signs with eth_signTypedData_v4). */
export function keyRequestDigest(account) {
  const domainType = "EIP712Domain(string name,string version)";
  const ds = keccak_256(unhex(hex(keccak_256(utf8(domainType))) + hex(keccak_256(utf8(KEY_DOMAIN.name))).slice(2) + hex(keccak_256(utf8(KEY_DOMAIN.version))).slice(2)));
  const sh = keccak_256(unhex(hex(keccak_256(utf8(encType))) + hex(keccak_256(utf8(KEY_PURPOSE))).slice(2) + account.toLowerCase().replace(/^0x/, "").padStart(64, "0")));
  return keccak_256(unhex("0x1901" + hex(ds).slice(2) + hex(sh).slice(2)));
}
export const keyRequestTypedData = account => JSON.stringify({ types: { EIP712Domain: [{ name: "name", type: "string" }, { name: "version", type: "string" }], ...KEY_TYPES },
  primaryType: "StealthKeys", domain: KEY_DOMAIN, message: { purpose: KEY_PURPOSE, account } });
/** Receiver keys from the wallet's signature. Refuses anything that is not a plain 65-byte ECDSA signature by `account`
 *  (smart wallets, passkeys, ERC-1271/6492 wrappers give randomised or wrapped signatures: keys could not be re-derived
 *  later and incoming money would be lost). Derives from r||s only, so v = 0/1 vs 27/28 cannot change the keys. */
export function keysFromSignature(sigHex, account) {
  if (!/^(0x)?([0-9a-fA-F]{2})+$/.test(String(sigHex))) throw new Error("This wallet did not return a plain signature (not hex).");   // audit 1098 I: odd length / junk is refused here, not padded
  const sig = unhex(sigHex);
  if (sig.length !== 65) throw new Error("This wallet did not return a plain signature (smart wallet or passkey?). Stealth needs an ordinary key-based wallet such as MetaMask.");
  const raw = sig.slice(0, 64); let rs = raw; let v = sig[64]; if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) throw new Error("unexpected signature format");
  const fromRs = (b) => {
    const d = (t) => toBytes32(mod(toBig(keccak_256(concatBytes(b, utf8(t)))), N) || 1n);
    const spendPriv = d("deepyield-stealth/spend/v1"), viewPriv = d("deepyield-stealth/view/v1");
    return { spendPriv, viewPriv, spendPub: secp.getPublicKey(spendPriv, true), viewPub: secp.getPublicKey(viewPriv, true) };
  };
  const owns = (b, bit) => addressOf(secp.Signature.fromCompact(b).addRecoveryBit(bit).recoverPublicKey(keyRequestDigest(account)).toRawBytes(true)).toLowerCase() === account.toLowerCase();
  // ECDSA is malleable: (r, s, v) and (r, n-s, v^1) both verify for the same account but would give a different key set. Normalise to the
  // canonical low-s form first, so the keys depend only on the account and the message (a high-s signature must not yield other keys).
  const sig0 = secp.Signature.fromCompact(raw), high = sig0.hasHighS(), v0 = v;
  if (high) { rs = sig0.normalizeS().toCompactRawBytes(); v ^= 1; }
  if (!owns(rs, v)) throw new Error("the signature does not come from the connected account");
  const keys = fromRs(rs);
  // audit 1098 L-1: a wallet that emitted HIGH-s signatures used to get keys derived from the raw bytes. Those keys are still derived (verified to belong to the account) and
  // returned as keys.legacy so the scan and the withdraw still find the old payments. They are never put in a meta-address; scan and withdraw only.
  if (high && owns(raw, v0)) keys.legacy = fromRs(raw);
  return keys;
}
/** Test helper: sign the key request with a raw private key the way an EOA wallet would (65-byte r||s||v). */
export function signKeyRequestWith(privBytes, account) {
  const sig = secp.sign(keyRequestDigest(account), privBytes, { lowS: true });
  return hex(sig.toCompactRawBytes()) + (27 + sig.recovery).toString(16).padStart(2, "0");
}
export const addressFromPriv = priv => addressOf(secp.getPublicKey(priv, true));
/** Meta-address: st:<chain>:0x<P_spend><P_view> (66 bytes). */
export const metaAddress = (keys, chain = "base") => "st:" + chain + ":" + hex(concatBytes(keys.spendPub, keys.viewPub));
export function parseMeta(s) {
  const m = String(s).trim().match(/^(?:st:[a-z0-9]+:)?(0x[0-9a-fA-F]{132})$/);
  if (!m) throw new Error("not a stealth meta-address");
  const b = unhex(m[1]), spendPub = b.slice(0, 33), viewPub = b.slice(33, 66);
  try { secp.ProjectivePoint.fromHex(spendPub); secp.ProjectivePoint.fromHex(viewPub); } catch { throw new Error("not a valid stealth meta-address (a key is not a point on the curve)"); }   // audit 1098 I-4
  return { spendPub, viewPub };
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
  let ephPub; try { ephPub = unhex(ephPubHex); } catch { return null; }        // hostile indexer data: skip, never throw
  if (ephPub.length !== 33) return null;
  let sh;
  try { sh = hashedShared(keys.viewPriv, ephPub); } catch { return null; }
  if (viewTagHex && (sh[0] !== parseInt(viewTagHex, 16))) return null;
  try {                                                    // audit 1086 L-3: sh = 0 or >= n (2^-128) must not abort a scan loop
    const P = secp.ProjectivePoint.fromHex(keys.spendPub).add(secp.ProjectivePoint.fromPrivateKey(sh));
    const stealth = addressOf(P.toRawBytes(true));
    const priv = toBytes32(mod(toBig(keys.spendPriv) + toBig(sh), N));
    return { stealth, stealthPriv: hex(priv) };
  } catch { return null; }
}

/** ERC-5564 metadata for a token payment: viewTag | 0xa9059cbb | token | amount (57 bytes). Decode helper. */
export function decodeMetadata(metaHex) {
  let b; try { b = unhex(metaHex); } catch { return null; }
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
