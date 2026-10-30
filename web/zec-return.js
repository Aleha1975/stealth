/* Return ZEC stuck on a hop t-address without a Zcash wallet.
   Since NU6.3 (Ironwood) WebZjs cannot shield, but a transparent-only v5 transaction is still valid. This module derives the
   hop's transparent key from its mnemonic (BIP44 m/44'/133'/account'/0/index), builds and signs a t -> t transaction (ZIP 225 / ZIP 244),
   and broadcasts it through the same lightwalletd proxy WebZjs uses. Only transparent inputs/outputs; no shielded parts at all. */
import { secp256k1 } from "./vendor/noble.js";
import { blake2b, sha256, sha512, hmac, ripemd160 } from "./vendor/zec-hash.js";

export const NU6_3_BRANCH = 0x37a5165b;        // librustzcash zcash_protocol BranchId::Nu6_3 (mainnet activation 3,428,143)
export const V5_GROUP = 0x26a7270a, V5_HEADER = (5 | 0x80000000) >>> 0;
export const FEE = 10_000n;                     // ZIP-317: max(2, logical actions) * 5000 for 1 in / 1 out
export const sweepFee = nIn => 5_000n * BigInt(Math.max(2, nIn));   // n inputs, 1 output: at least the ZIP-317 conventional fee (overpays by one action per ~75 inputs, never underpays)
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
  if (k === 0n || k >= N) throw new Error("bip32: invalid master key");
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
export const BRANCH_ACTIVATION = 3_428_143;      // NU6.3 mainnet activation height: below it 0x37a5165b is not valid, so we refuse (a newer upgrade needs a code update, fail closed)
export const EXPIRY_DELTA = 40;                  // ZIP 203 default: the tx dies 40 blocks after the tip it was built on
export const MIN_INPUT = 5_001n;                 // an input worth <= its own 5000 zat of fee is net negative: skipped
export const MIN_OUTPUT = 1_000n;                // the sweep must pay at least this (above the relay dust rule); a caller that skips the quote minimum is still covered
export const MAX_INPUTS = 50;                    // per transaction (far below the 100 kB standardness limit); the rest is swept by the next press
const MAX_TIP = 0x7fffffff, MAX_MONEY = 2_100_000_000_000_000n;
/** Consensus branch id for the chain tip height. Refuses heights below the NU6.3 activation. (Known: it does NOT fail closed on a later upgrade; a stale branch id is rejected by the network after the quote, nothing is lost. 1103 I-4.) */
export function branchForHeight(h) {
  if (!Number.isInteger(h) || h < BRANCH_ACTIVATION || h > MAX_TIP) throw new Error("chain tip " + h + " is below the NU6.3 activation (or invalid); refusing to build");
  return NU6_3_BRANCH;
}
/** What a sweep will actually spend: skips dust, biggest first, at most MAX_INPUTS. buildSweep applies it too, so callers can size quotes with the same set. */
export const sweepSet = utxos => utxos.filter(u => BigInt(u.value) >= MIN_INPUT).sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : BigInt(b.value) < BigInt(a.value) ? -1 : 0)).slice(0, MAX_INPUTS);
/** Sweep the UTXOs of one key to `to` (amount = total - sweepFee(inputs), no change). Pass `tip` (GetLatestBlock height): branch id comes from it and the tx expires at tip + 40.
 *  Without `tip` an explicit `branch` AND `expiry` are required (tests / replays); nothing defaults to "never expires". */
export function buildSweep({ utxos, key, to, tip, branch, expiry }) {
  if (tip !== undefined) { branch = branchForHeight(tip); expiry = tip + EXPIRY_DELTA; for (const u of utxos) if (u.height > tip) throw new Error("UTXO is above the reported tip; refusing"); }
  else if (!(branch >= 0) || !(expiry > 0)) throw new Error("tip (or explicit branch and expiry) required");
  if (!(expiry > 0 && expiry < 500_000_000)) throw new Error("bad expiry height");
  utxos = sweepSet(utxos); if (!utxos.length) throw new Error("nothing to send");
  const total = utxos.reduce((s, u) => s + BigInt(u.value), 0n), amount = total - sweepFee(utxos.length);
  if (amount <= 0n || amount < MIN_OUTPUT) throw new Error("nothing to send");
  const script = cat(Uint8Array.of(0x76, 0xa9, 0x14), ripemd160(sha256(key.pub)), Uint8Array.of(0x88, 0xac));
  const tx = { branch, lockTime: 0, expiry, vin: utxos.map(u => ({ txid: u.txid, n: u.n, seq: 0xffffffff, value: BigInt(u.value), script })), vout: [{ value: amount, script: tAddrScript(to) }] };
  for (const u of utxos) if (u.script && hex(u.script) !== hex(script)) throw new Error("UTXO is not this key's");
  const signed = signAll(tx, key);
  return { raw: serialize(signed), txid: txid(signed), amount, expiry, branch };
}

// ---- lightwalletd over gRPC-web (unary calls only). Everything from the server is untrusted: bounded, parsed strictly, fail closed.
const MAX_FRAME = 1 << 20, MAX_BODY = 2 << 20, TIMEOUT_MS = 20_000, MAX_UTXO_ENTRIES = 500;
const pbVarint = n => { n = BigInt(n); const o = []; do { let b = Number(n & 127n); n >>= 7n; if (n) b |= 128; o.push(b); } while (n); return Uint8Array.from(o); };
const pbField = (no, wire, body) => cat(pbVarint(no << 3 | wire), wire === 2 ? cat(pbVarint(body.length), body) : body);
/** Parse a protobuf message into [[fieldNo, value], ...]. `each(no, v)` (optional) is called per field and may return true to stop early (the rest is not looked at).
 *  `partial`: the input is a prefix of a longer message; an incomplete last field is dropped instead of being an error. */
function pbRead(b, { each = null, partial = false } = {}) {
  const out = []; let i = 0, cut = false;
  const vi = () => { let n = 0n, s = 0n; for (let k = 0; k < 10; k++) { if (i >= b.length) throw new Error("protobuf: truncated varint"); const x = b[i++]; n |= BigInt(x & 127) << s; s += 7n; if (!(x & 128)) return n; } throw new Error("protobuf: varint too long"); };
  const take = l => { if (l < 0 || i + l > b.length) throw new Error("protobuf: truncated field"); const v = b.slice(i, i + l); i += l; return v; };
  while (i < b.length) {
    const start = i;
    try {
      const k = vi(), no = Number(k >> 3n), w = Number(k & 7n); if (no < 1 || no > 0x1fffffff) throw new Error("protobuf: bad field number");
      let v;
      if (w === 0) v = vi(); else if (w === 2) { const l = vi(); if (l > BigInt(MAX_BODY)) throw new Error("protobuf: field too long"); v = take(Number(l)); }
      else if (w === 1) v = take(8); else if (w === 5) v = take(4); else throw new Error("protobuf wire " + w);
      out.push([no, v]);
    } catch (e) { if (partial && /truncated/.test(e.message)) { i = start; cut = true; break; } throw e; }
    if (each && each(out[out.length - 1][0], out[out.length - 1][1])) { cut = true; break; }      // 1103 L-3: an error raised by `each` (a bad inner entry) is never mistaken for the end of a cut reply
  }
  out.cut = cut; return out;
}
async function readBody(r, partial = false) {
  const cl = r.headers && r.headers.get && r.headers.get("content-length"); if (!partial && cl && Number(cl) > MAX_BODY) throw new Error("lightwalletd: reply too large");
  if (r.body && r.body.getReader) {
    const rd = r.body.getReader(), parts = []; let n = 0;
    for (;;) { const { done, value } = await rd.read(); if (done) break; n += value.length; if (n > MAX_BODY) { try { await rd.cancel(); } catch {} if (!partial) throw new Error("lightwalletd: reply too large"); const keep = cat(...parts, value).slice(0, MAX_BODY); keep.cut = true; return keep; } parts.push(value); }
    return cat(...parts);
  }
  const b = new Uint8Array(await r.arrayBuffer()); if (b.length > MAX_BODY) { if (!partial) throw new Error("lightwalletd: reply too large"); const keep = b.slice(0, MAX_BODY); keep.cut = true; return keep; } return b;
}
/** Split a gRPC-web body into { data, trailer }. Lengths are unsigned and bounded; anything truncated, trailing or duplicated throws. */
export function grpcFrames(b, maxFrame = MAX_FRAME) {
  if (b.length > MAX_BODY) throw new Error("lightwalletd: reply too large");
  let i = 0, data = null, trailer = null;
  while (i < b.length) {
    if (i + 5 > b.length) throw new Error("lightwalletd: truncated frame header");
    const f = b[i], l = ((b[i + 1] << 24) | (b[i + 2] << 16) | (b[i + 3] << 8) | b[i + 4]) >>> 0;
    if (l > maxFrame) throw new Error("lightwalletd: frame too large");
    if (i + 5 + l > b.length) throw new Error("lightwalletd: truncated frame");
    if (f & 0x7f) throw new Error("lightwalletd: bad frame flags");
    const p = b.slice(i + 5, i + 5 + l); i += 5 + l;
    if (f & 0x80) { if (trailer !== null) throw new Error("lightwalletd: duplicate trailer"); trailer = new TextDecoder().decode(p); }
    else { if (trailer !== null || data !== null) throw new Error("lightwalletd: unexpected data frame"); data = p; }
  }
  return { data, trailer };
}
async function grpc(base, method, msg, fetchFn = fetch, { maxFrame = MAX_FRAME, partial = false } = {}) {
  const body = cat(Uint8Array.of(0), Uint8Array.of(msg.length >>> 24 & 255, msg.length >>> 16 & 255, msg.length >>> 8 & 255, msg.length & 255), msg);
  const ac = typeof AbortController === "function" ? new AbortController() : null, timer = setTimeout(() => ac && ac.abort(), TIMEOUT_MS);
  let r, b;
  try {
    r = await fetchFn(base.replace(/\/$/, "") + "/cash.z.wallet.sdk.rpc.CompactTxStreamer/" + method, { method: "POST", headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" }, body, signal: ac ? ac.signal : undefined });
    if (!r.ok) throw new Error("lightwalletd " + r.status);
    b = await readBody(r, partial);
  } finally { clearTimeout(timer); }
  if (b.cut) {                                      // flood: only a prefix was read; the first data frame's start is all we use (status cannot be seen, a bad header status still counts)
    const hs = r.headers.get("grpc-status"); if (hs != null && hs !== "0") throw new Error("lightwalletd: error " + hs);
    if (b.length < 5 || b[0] !== 0) throw new Error("lightwalletd: bad truncated reply");
    const l = ((b[1] << 24) | (b[2] << 16) | (b[3] << 8) | b[4]) >>> 0;       // 1103 L-3: the first frame's own length is honoured; bytes after it are not message content
    if (5 + l <= b.length) {
      const d = b.slice(5, 5 + l), rest = b.slice(5 + l);
      if (rest.length >= 5 && (rest[0] & 0x80)) { const rl = ((rest[1] << 24) | (rest[2] << 16) | (rest[3] << 8) | rest[4]) >>> 0; if (5 + rl <= rest.length) { const tr = new TextDecoder().decode(rest.slice(5, 5 + rl)), m = /^grpc-status:[ \t]*(\d+)/mi.exec(tr); if (m && m[1] !== "0") throw new Error("lightwalletd: error " + m[1]); } }
      return d;                                                              // the message is complete (only the trailer was cut off)
    }
    const d = b.slice(5); d.partial = true; return d;
  }
  const { data, trailer } = grpcFrames(b, maxFrame);
  const status = (/^grpc-status:[ \t]*(\d+)[ \t]*\r?$/mi.exec(trailer || "") || [null, r.headers.get("grpc-status")])[1];
  if (status == null || !/^\d+$/.test(status)) throw new Error("lightwalletd: no grpc-status in the reply");
  if (status !== "0") {
    let m; try { m = decodeURIComponent((/^grpc-message:[ \t]*(.*?)\r?$/mi.exec(trailer || "") || [])[1] || r.headers.get("grpc-message") || "error " + status).trim(); } catch { m = "error " + status; }
    const e = new Error("lightwalletd: " + m.slice(0, 300)); e.grpcStatus = Number(status); throw e;
  }
  if (data === null) throw new Error("lightwalletd: reply without a message");
  return data;
}
const bigOf = (v, what) => { if (typeof v !== "bigint") throw new Error("lightwalletd: bad " + what); return v; };
/** Wall-clock bound on the tip (audit 1100 L-1). The chain makes one block per ~75 s, so the height cannot be far from anchor + (now - anchorTime)/75. A lying lightwalletd could
 *  otherwise pick the expiry (a tip of 499,999,000 = a transaction that never expires). The anchor is a real block (height 3,535,162 at 2026-10-29 21:54:31 UTC); the tolerance is 200 blocks
 *  plus 0.3% of the elapsed blocks, which covers the slow drift of the real average block time as the anchor ages.
 *  1103 L-2 (known, not changed): 200 blocks is ~4.2 h, so a lying server can still choose a tip that far ahead; the loss is bounded by the refund path. A device clock off by more than that is refused too. */
export const TIP_ANCHOR = { height: 3_535_162, time: 1_793_310_871 }, TIP_SLACK = 200, BLOCK_SECONDS = 75;
export function tipWithinClock(h, nowMs = Date.now()) {
  const elapsed = Math.max(0, (nowMs / 1000 - TIP_ANCHOR.time) / BLOCK_SECONDS), expect = TIP_ANCHOR.height + elapsed, slack = TIP_SLACK + elapsed * 0.003;
  return Math.abs(h - expect) <= slack;
}
/** Current chain tip height (GetLatestBlock), refused if it disagrees with the wall clock. `opts.now` (ms) is for tests. */
export async function getTip(base, fetchFn, opts = {}) {
  const h = bigOf((pbRead(await grpc(base, "GetLatestBlock", new Uint8Array(0), fetchFn)).find(([no]) => no === 1) || [])[1], "tip height");
  if (h < BigInt(BRANCH_ACTIVATION) || h > BigInt(MAX_TIP)) throw new Error("lightwalletd: implausible chain tip " + h);
  if (!tipWithinClock(Number(h), opts.now)) throw new Error("lightwalletd reported chain tip " + h + ", which does not match this device's clock (is the date and time on this device right? it must be within about 4 hours); refusing to build a transaction on it");
  return Number(h);
}
/** UTXOs of one t-address: [{ txid (display hex), n, value, script, height }], each one validated; duplicates and foreign scripts are errors.
 *  Audit 1100 L-3 / 1103 M-1: a page stops after MAX_UTXO_ENTRIES (500) entries WORTH SPENDING (>= MIN_INPUT), so a dust prefix cannot push the real deposit out of view; dust is still listed
 *  (it counts as "not empty"). Further pages continue from the last height (at most MAX_UTXO_PAGES). `list.truncated` is true when more may exist beyond what was read; a caller must then
 *  never treat an empty sweepSet() as "nothing here". */
export async function getUtxos(base, addr, fetchFn) {
  const mine = tAddrScript(addr), MAX_UTXO_PAGES = 6, seen = new Set(), list = []; let start = 0, more = false;
  for (let pg = 0; pg < MAX_UTXO_PAGES; pg++) {
    let res; try { res = await grpc(base, "GetAddressUtxos", cat(pbField(1, 2, enc(addr)), pbField(2, 0, pbVarint(start)), pbField(3, 0, pbVarint(0))), fetchFn, { maxFrame: MAX_BODY, partial: true }); }
    catch (e) { if (pg === 0) throw e; more = true; break; }          // a later page that fails keeps what the first pages proved (flood protection); the list is flagged truncated
    const before = new Set(seen); let big = 0, added = 0, maxH = start;
    const entry = m => {
      if (!(m instanceof Uint8Array)) throw new Error("lightwalletd: bad UTXO entry");
      const u = { n: 0, value: 0n, height: 0 }; let has = 0;
      for (const [no, v] of pbRead(m)) {
        if (no === 1) { if (!(v instanceof Uint8Array) || v.length !== 32) throw new Error("lightwalletd: bad UTXO txid"); u.txid = hex(v.slice().reverse()); has |= 1; }
        else if (no === 2) { if (bigOf(v, "UTXO index") >= 0x100000000n) throw new Error("lightwalletd: bad UTXO index"); u.n = Number(v); }
        else if (no === 3) { if (!(v instanceof Uint8Array)) throw new Error("lightwalletd: bad UTXO script"); u.script = v; }
        else if (no === 4) { if (bigOf(v, "UTXO value") <= 0n || v > MAX_MONEY) throw new Error("lightwalletd: bad UTXO value"); u.value = v; has |= 2; }
        else if (no === 5) { if (bigOf(v, "UTXO height") > BigInt(MAX_TIP)) throw new Error("lightwalletd: bad UTXO height"); u.height = Number(v); }
        else if (no === 6) { if (!(v instanceof Uint8Array) || new TextDecoder().decode(v) !== addr) throw new Error("lightwalletd: UTXO of another address"); } }
      if (has !== 3) throw new Error("lightwalletd: incomplete UTXO");
      if (u.script && hex(u.script) !== hex(mine)) throw new Error("lightwalletd: UTXO script is not this address's");
      const id = u.txid + ":" + u.n; if (seen.has(id)) { if (before.has(id)) return; throw new Error("lightwalletd: duplicate UTXO"); } seen.add(id);     // an entry repeated from an earlier page (same boundary height) is skipped
      list.push(u); added++; if (u.height > maxH) maxH = u.height; if (u.value >= MIN_INPUT) big++;
    };
    let fields; try {
      fields = pbRead(res, { partial: !!res.partial, each: (no, v) => { if (no === 1) entry(v); return big >= MAX_UTXO_ENTRIES; } });
      if (res.partial && !fields.cut) throw new Error("lightwalletd: truncated reply");
      if (res.partial && big < MAX_UTXO_ENTRIES) throw new Error("lightwalletd: reply too large");
    } catch (e) { if (pg === 0) throw e; more = true; break; }
    more = fields.cut && big >= MAX_UTXO_ENTRIES;
    if (!more) break;
    if (!added || maxH <= start) break;                                  // no progress: the rest cannot be reached
    start = maxH;
  }
  list.truncated = more;
  return list;
}
/** Send a raw tx. Succeeds only on a well-formed reply with errorCode 0 whose returned txid equals `expectTxid` (display hex, the locally computed one). */
export async function broadcast(base, raw, fetchFn, expectTxid) {
  if (!/^[0-9a-f]{64}$/i.test(expectTxid || "")) throw new Error("broadcast needs the locally computed txid");
  const res = pbRead(await grpc(base, "SendTransaction", pbField(1, 2, raw), fetchFn));
  const c = res.find(([no]) => no === 1), m = res.find(([no]) => no === 2);
  if (c && typeof c[1] !== "bigint" || m && !(m[1] instanceof Uint8Array)) throw new Error("lightwalletd: malformed broadcast reply");
  const code = c ? c[1] : 0n, msg = m ? new TextDecoder().decode(m[1]) : "";
  if (code !== 0n) throw new Error("Rejected by network: " + msg.slice(0, 300));
  const got = msg.trim().replace(/^"|"$/g, "").toLowerCase();
  if (got !== expectTxid.toLowerCase()) throw new Error("lightwalletd confirmed a different txid than ours (" + got.slice(0, 80) + "); not treating it as sent");
  return got;
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
    // only a structured NotFound (grpc-status 5) or zcashd's own -5 text carried by lightwalletd counts as "not there"; gateway text such as "host not found" must not
    if (e && (e.grpcStatus === 5 || (e.grpcStatus === 2 && /^lightwalletd: (-5: )?No such mempool or blockchain transaction/i.test(String(e.message))))) return false;
    throw e;
  }
}

/** Broadcast, then require lightwalletd to hand back OUR raw bytes for our txid (GetTransaction) before calling it sent (audit 1100 L-2): the SendTransaction reply alone can be
 *  forged from the public txid. An ambiguous end of SendTransaction (timeout/abort) is resolved by the same lookup instead of being retried blindly. A rejection by the network is final.
 *  The server can still censor after confirming; the swap status poll is the end-to-end check. opts: { sleep, tries, everyMs }. */
export async function sendAndConfirm(base, raw, fetchFn, expectTxid, { sleep = ms => new Promise(r => setTimeout(r, ms)), tries = 4, everyMs = 1500 } = {}) {
  let sendErr = null;
  try { await broadcast(base, raw, fetchFn, expectTxid); }
  catch (e) { if (/^Rejected by network|different txid/.test(String(e && e.message))) throw e; sendErr = e; }
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    try {
      const res = pbRead(await grpc(base, "GetTransaction", pbField(3, 2, unhex(expectTxid).reverse()), fetchFn));
      const data = res.find(([no]) => no === 1);
      if (data && data[1] instanceof Uint8Array && data[1].length === raw.length && hex(data[1]) === hex(raw)) return expectTxid.toLowerCase();
      lastErr = new Error("lightwalletd does not return our transaction");
    } catch (e) { lastErr = e; }
    if (i < tries - 1) await sleep(everyMs);
  }
  throw new Error((sendErr ? "Broadcast did not complete (" + sendErr.message + ") and " : "lightwalletd accepted the broadcast but ") + "does not know the transaction (" + (lastErr && lastErr.message) + "). It was NOT confirmed as sent; do not assume the money moved.");
}
/** "The server says there is nothing here" must never hide a hop by itself (audit 1100 M-1). Feed each empty answer in; hide only after EMPTY_N consistent answers at least
 *  EMPTY_GAP_MS apart that span at least EMPTY_SPAN_MS. A non-empty answer resets it. -> { obs, hide } ; persist `obs` in the hop record, `hide` is the verdict. */
export const EMPTY_N = 3, EMPTY_GAP_MS = 5 * 60_000, EMPTY_SPAN_MS = 30 * 60_000;
export function noteEmpty(prev, empty, now = Date.now()) {
  if (!empty) return { obs: null, hide: false };
  if (!prev || !(prev.first <= now) || !(prev.count >= 1)) return { obs: { first: now, last: now, count: 1 }, hide: false };
  const obs = now - prev.last >= EMPTY_GAP_MS ? { first: prev.first, last: now, count: prev.count + 1 } : { first: prev.first, last: prev.last, count: prev.count };
  return { obs, hide: obs.count >= EMPTY_N && obs.last - obs.first >= EMPTY_SPAN_MS };
}
