/* Return ZEC stuck on a hop t-address without a Zcash wallet.
   Since NU6.3 (Ironwood) WebZjs cannot shield, but a transparent-only v5 transaction is still valid. This module derives the
   hop's transparent key from its mnemonic (BIP44 m/44'/133'/account'/0/index), builds and signs a t -> t transaction (ZIP 225 / ZIP 244),
   and broadcasts it through the same lightwalletd proxy WebZjs uses. Only transparent inputs/outputs; no shielded parts at all. */
import { secp256k1 } from "./vendor/noble.js";
import { blake2b, sha256, sha512, hmac, ripemd160 } from "./vendor/zec-hash.js";

export const NU6_3_BRANCH = 0x37a5165b;        // librustzcash zcash_protocol BranchId::Nu6_3 (mainnet activation 3,428,143)
export const V5_GROUP = 0x26a7270a, V5_HEADER = (5 | 0x80000000) >>> 0;
export const FEE = 10_000n;                     // ZIP-317: max(2, logical actions) * 5000 for 1 in / 1 out
const P2PKH = [0x1c, 0xb8], P2SH = [0x1c, 0xbd];
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const enc = s => new TextEncoder().encode(s);
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u32 = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64 = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const cs = n => n < 253 ? Uint8Array.of(n) : n <= 0xffff ? Uint8Array.of(253, n & 255, n >> 8) : cat(Uint8Array.of(254), u32(n));
const vbytes = b => cat(cs(b.length), b);
export const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
export const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const h256 = (person, ...parts) => blake2b(cat(...parts), { dkLen: 32, personalization: person instanceof Uint8Array ? person : enc(person) });

// ---- base58check t-addresses
function b58decode(s) {
  let n = 0n; for (const c of s) { const v = B58.indexOf(c); if (v < 0) throw new Error("bad address"); n = n * 58n + BigInt(v); }
  let h = n.toString(16); if (h.length % 2) h = "0" + h; const lead = s.match(/^1*/)[0].length;
  return cat(new Uint8Array(lead), n ? unhex(h) : new Uint8Array(0));
}
function b58encode(b) {
  let n = BigInt("0x" + (hex(b) || "0")), s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x) break; s = "1" + s; } return s;
}
const check = p => sha256(sha256(p)).slice(0, 4);
export function tAddrScript(addr) {
  const b = b58decode(addr); if (b.length !== 26) throw new Error("bad address");
  const p = b.slice(0, 22), c = b.slice(22); if (hex(check(p)) !== hex(c)) throw new Error("bad address checksum");
  const h = p.slice(2);
  if (p[0] === P2PKH[0] && p[1] === P2PKH[1]) return cat(Uint8Array.of(0x76, 0xa9, 0x14), h, Uint8Array.of(0x88, 0xac));
  if (p[0] === P2SH[0] && p[1] === P2SH[1]) return cat(Uint8Array.of(0xa9, 0x14), h, Uint8Array.of(0x87));
  throw new Error("not a mainnet transparent address");
}
export const p2pkhAddr = pub => { const p = cat(Uint8Array.from(P2PKH), ripemd160(sha256(pub))); return b58encode(cat(p, check(p))); };

// ---- BIP32 (secp256k1) private derivation
const N = secp256k1.CURVE.n, H = 0x80000000;
const toBig = b => BigInt("0x" + hex(b)), to32 = n => unhex(n.toString(16).padStart(64, "0"));
export function deriveT(seed, path) {
  let I = hmac(sha512, enc("Bitcoin seed"), seed), k = toBig(I.slice(0, 32)), c = I.slice(32);
  for (const i of path) {
    const data = i >= H ? cat(Uint8Array.of(0), to32(k), u32be(i)) : cat(secp256k1.getPublicKey(to32(k), true), u32be(i));
    I = hmac(sha512, c, data); const t = toBig(I.slice(0, 32)); if (t >= N) throw new Error("bip32: invalid child");
    k = (t + k) % N; if (k === 0n) throw new Error("bip32: invalid child"); c = I.slice(32);
  }
  const priv = to32(k), pub = secp256k1.getPublicKey(priv, true);
  return { priv, pub, addr: p2pkhAddr(pub) };
}
function u32be(n) { return Uint8Array.of(n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255); }
export const tPath = (account, index = 0) => [44 + H, 133 + H, account + H, 0, index];
/** Find which account/index of the mnemonic seed owns `addr` (the hop used account 0, current address). */
export function findKey(seed, addr, accounts = 4, indexes = 5) {
  for (let a = 0; a < accounts; a++) for (let i = 0; i < indexes; i++) { const k = deriveT(seed, tPath(a, i)); if (k.addr === addr) return { ...k, account: a, index: i }; }
  return null;
}

// ---- v5 transparent-only transaction (ZIP 225) and its digests (ZIP 244)
/** tx = { branch, lockTime, expiry, vin: [{ txid (display hex), n, seq, value, script (scriptPubKey bytes), sig? }], vout: [{ value, script }] } */
const outpoint = x => cat(unhex(x.txid).reverse(), u32(x.n));
const txout = o => cat(u64(o.value), vbytes(o.script));
const headerDigest = tx => h256("ZTxIdHeadersHash", u32(V5_HEADER), u32(V5_GROUP), u32(tx.branch), u32(tx.lockTime), u32(tx.expiry));
const prevouts = tx => h256("ZTxIdPrevoutHash", ...tx.vin.map(outpoint));
const sequences = tx => h256("ZTxIdSequencHash", ...tx.vin.map(x => u32(x.seq)));
const outputs = tx => h256("ZTxIdOutputsHash", ...tx.vout.map(txout));
const saplingDigest = () => h256("ZTxIdSaplingHash"), orchardDigest = () => h256("ZTxIdOrchardHash");
const branchPerson = (tag, tx) => cat(enc(tag), u32(tx.branch));
export function txid(tx) {
  const t = tx.vin.length + tx.vout.length > 0 ? h256("ZTxIdTranspaHash", prevouts(tx), sequences(tx), outputs(tx)) : h256("ZTxIdTranspaHash");
  return hex(h256(branchPerson("ZcashTxHash_", tx), headerDigest(tx), t, saplingDigest(), orchardDigest()).reverse());
}
/** SIGHASH_ALL digest for transparent input i. */
export function sighash(tx, i) {
  const x = tx.vin[i];
  const t = h256("ZTxIdTranspaHash", Uint8Array.of(1), prevouts(tx), h256("ZTxTrAmountsHash", ...tx.vin.map(v => u64(v.value))),
    h256("ZTxTrScriptsHash", ...tx.vin.map(v => vbytes(v.script))), sequences(tx), outputs(tx),
    h256("Zcash___TxInHash", outpoint(x), u64(x.value), vbytes(x.script), u32(x.seq)));
  return h256(branchPerson("ZcashTxHash_", tx), headerDigest(tx), t, saplingDigest(), orchardDigest());
}
export function serialize(tx) {
  return cat(u32(V5_HEADER), u32(V5_GROUP), u32(tx.branch), u32(tx.lockTime), u32(tx.expiry),
    cs(tx.vin.length), ...tx.vin.map(x => cat(outpoint(x), vbytes(x.sig || new Uint8Array(0)), u32(x.seq))),
    cs(tx.vout.length), ...tx.vout.map(txout),
    cs(0), cs(0), cs(0));                                       // no Sapling spends/outputs, no Orchard actions
}
function push(b) { if (b.length > 75) throw new Error("push too long"); return cat(Uint8Array.of(b.length), b); }
/** Sign every input with one key (all inputs are the same P2PKH address). Low-s DER + SIGHASH_ALL. */
export function signAll(tx, key) {
  const vin = tx.vin.map((x, i) => {
    const s = secp256k1.sign(sighash(tx, i), key.priv, { lowS: true });
    return { ...x, sig: cat(push(cat(s.toDERRawBytes(), Uint8Array.of(1))), push(key.pub)) };
  });
  return { ...tx, vin };
}
/** Sweep all UTXOs of one key to `to` (amount = total - FEE, no change). */
export function buildSweep({ utxos, key, to, branch = NU6_3_BRANCH, expiry = 0 }) {
  const total = utxos.reduce((s, u) => s + BigInt(u.value), 0n), amount = total - FEE;
  if (amount <= 0n) throw new Error("nothing to send");
  const script = cat(Uint8Array.of(0x76, 0xa9, 0x14), ripemd160(sha256(key.pub)), Uint8Array.of(0x88, 0xac));
  const tx = { branch, lockTime: 0, expiry, vin: utxos.map(u => ({ txid: u.txid, n: u.n, seq: 0xffffffff, value: BigInt(u.value), script })), vout: [{ value: amount, script: tAddrScript(to) }] };
  for (const u of utxos) if (u.script && hex(u.script) !== hex(script)) throw new Error("UTXO is not this key's");
  const signed = signAll(tx, key);
  return { raw: serialize(signed), txid: txid(signed), amount };
}

// ---- lightwalletd over gRPC-web (unary calls only)
const pbVarint = n => { n = BigInt(n); const o = []; do { let b = Number(n & 127n); n >>= 7n; if (n) b |= 128; o.push(b); } while (n); return Uint8Array.from(o); };
const pbField = (no, wire, body) => cat(pbVarint(no << 3 | wire), wire === 2 ? cat(pbVarint(body.length), body) : body);
function pbRead(b) {
  const out = []; let i = 0;
  const vi = () => { let n = 0n, s = 0n; for (;;) { const x = b[i++]; n |= BigInt(x & 127) << s; s += 7n; if (!(x & 128)) return n; } };
  while (i < b.length) { const k = Number(vi()), no = k >> 3, w = k & 7;
    if (w === 0) out.push([no, vi()]); else if (w === 2) { const l = Number(vi()); out.push([no, b.slice(i, i + l)]); i += l; }
    else if (w === 1) { out.push([no, b.slice(i, i + 8)]); i += 8; } else if (w === 5) { out.push([no, b.slice(i, i + 4)]); i += 4; } else throw new Error("protobuf wire " + w); }
  return out;
}
async function grpc(base, method, msg, fetchFn = fetch) {
  const body = cat(Uint8Array.of(0), Uint8Array.of(msg.length >>> 24 & 255, msg.length >>> 16 & 255, msg.length >>> 8 & 255, msg.length & 255), msg);
  const r = await fetchFn(base.replace(/\/$/, "") + "/cash.z.wallet.sdk.rpc.CompactTxStreamer/" + method, { method: "POST", headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" }, body });
  const b = new Uint8Array(await r.arrayBuffer());
  if (!r.ok) throw new Error("lightwalletd " + r.status);
  let i = 0, data = null, trailer = "";
  while (i + 5 <= b.length) { const f = b[i], l = b[i + 1] << 24 | b[i + 2] << 16 | b[i + 3] << 8 | b[i + 4], p = b.slice(i + 5, i + 5 + l); i += 5 + l; if (f & 0x80) trailer += new TextDecoder().decode(p); else data = p; }
  const st = /grpc-status:\s*(\d+)/.exec(trailer) || [null, r.headers.get("grpc-status") || "0"];
  if (st[1] !== "0") throw new Error("lightwalletd: " + decodeURIComponent((/grpc-message:\s*(.*)/.exec(trailer) || [])[1] || r.headers.get("grpc-message") || "error " + st[1]).trim());
  return data || new Uint8Array(0);
}
/** UTXOs of one t-address: [{ txid (display hex), n, value, script, height }] */
export async function getUtxos(base, addr, fetchFn) {
  const res = await grpc(base, "GetAddressUtxos", cat(pbField(1, 2, enc(addr)), pbField(2, 0, pbVarint(0)), pbField(3, 0, pbVarint(0))), fetchFn);
  return pbRead(res).filter(([no]) => no === 1).map(([, m]) => {
    const u = { n: 0, value: 0n, height: 0 }; for (const [no, v] of pbRead(m)) {
      if (no === 1) u.txid = hex(v.slice().reverse()); else if (no === 2) u.n = Number(v); else if (no === 3) u.script = v; else if (no === 4) u.value = v; else if (no === 5) u.height = Number(v); }
    return u;
  });
}
export async function broadcast(base, raw, fetchFn) {
  const res = pbRead(await grpc(base, "SendTransaction", pbField(1, 2, raw), fetchFn));
  const code = Number((res.find(([no]) => no === 1) || [0, 0n])[1]), msg = new TextDecoder().decode((res.find(([no]) => no === 2) || [0, new Uint8Array(0)])[1]);
  if (code !== 0) throw new Error("Rejected by network: " + msg);
  return msg;
}
/** Is this transaction known to lightwalletd (mempool or chain)? txid = display hex. lightwalletd's TxFilter.hash is the little-endian (wire) txid.
 *  true = known, false = clearly unknown (NotFound / "No such mempool or blockchain transaction"); any other failure throws, so a caller never mistakes "could not ask" for "not there". */
export async function txKnown(base, txid, fetchFn) {
  if (!/^[0-9a-fA-F]{64}$/.test(txid || "")) throw new Error("bad txid");
  try {
    const res = pbRead(await grpc(base, "GetTransaction", pbField(3, 2, unhex(txid).reverse()), fetchFn));
    const data = res.find(([no]) => no === 1);
    return !!(data && data[1].length > 0);
  } catch (e) {
    if (/not ?found|no such (mempool|blockchain)|-5\b|code = NotFound/i.test(String(e && e.message))) return false;
    throw e;
  }
}
