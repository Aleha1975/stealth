// node server/test_zec_return_hostile.mjs — hostile lightwalletd mocks against web/zec-return.js (audit round 1 fixes). Offline: never touches the network.
import * as R from "../web/zec-return.js";
import { secp256k1 } from "../web/vendor/noble.js";
let bad = 0; const ok = (m, c, d) => { console.log((c ? "PASS " : "FAIL ") + m + (c ? "" : " " + (d || ""))); if (!c) bad++; };
const cat = (...a) => Uint8Array.from(a.flatMap(x => [...x])), enc = s => new TextEncoder().encode(s);
const fr = (flag, b) => cat([flag, b.length >>> 24 & 255, b.length >>> 16 & 255, b.length >>> 8 & 255, b.length & 255], b), trailer = t => fr(0x80, enc(t)), OKT = trailer("grpc-status: 0\r\n");
const vi = n => { n = BigInt(n); const o = []; do { let b = Number(n & 127n); n >>= 7n; if (n) b |= 128; o.push(b); } while (n); return o; };
const ld = (no, b) => cat(vi(no << 3 | 2), vi(b.length), b), vf = (no, v) => cat(vi(no << 3), vi(v));
const resp = (bytes, o = {}) => ({ ok: o.ok !== false, status: o.status || 200, headers: { get: k => (o.h || {})[k] ?? null }, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) });
const mk = (bytes, o) => async () => resp(bytes, o);
const rejects = async (p, re) => p.then(() => false, e => re ? re.test(e.message) : true);
const key = R.deriveT(new Uint8Array(64).fill(7), R.tPath(0, 0)), TO = "t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLt", TX = "a0".repeat(32);
const withTimeout = (p, ms = 3000) => Promise.race([p, new Promise(r => setTimeout(() => r("HANG"), ms))]);

// M-1 unsigned/bounded frame length (the old signed parse looped forever on ff ff ff fb)
for (const [name, hdr] of [["0xfffffffb", [0, 255, 255, 255, 251]], ["0x80000000", [0, 128, 0, 0, 0]], ["0xffffffff", [0, 255, 255, 255, 255]], ["0x7fffffff", [0, 127, 255, 255, 255]]]) {
  const r = await withTimeout(R.getUtxos("https://lw", key.addr, mk(Uint8Array.from([...hdr, 1, 2, 3, 4, 5, 6]))).then(() => "ok", e => e.message));
  ok("M-1 frame length " + name + " fails closed, no hang", r !== "HANG" && r !== "ok" && /frame/.test(r), r); }
ok("M-1 truncated frame (length > bytes) throws", await rejects(R.getUtxos("https://lw", key.addr, mk(Uint8Array.from([0, 0, 0, 0, 9, 1, 2]))), /truncated/));
ok("M-1 trailing garbage after the last frame throws", await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, []), OKT, [1, 2, 3]))), /truncated/));
ok("M-1 total body > 2 MiB refused (content-length and streamed)", await rejects(R.getUtxos("https://lw", key.addr, mk(fr(0, []), { h: { "content-length": String(3 << 20) } }), /too large/)) &&
  await rejects(R.getUtxos("https://lw", key.addr, async () => ({ ok: true, status: 200, headers: { get: () => null }, body: { getReader: () => { let n = 0; return { read: async () => n++ < 5 ? { done: false, value: new Uint8Array(1 << 20) } : { done: true }, cancel: async () => {} }; } } })), /too large/));
ok("M-1 frame over 1 MiB refused", await rejects(R.getUtxos("https://lw", key.addr, mk(cat([0, 0, 0x20, 0, 0], new Uint8Array(0x200000)))), /frame too large|too large/));
ok("M-1 unknown flag bits / two data frames / data after trailer refused", await rejects(R.getUtxos("https://lw", key.addr, mk(fr(0x02, []))), /flags/) && await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, []), fr(0, []), OKT))), /unexpected/) && await rejects(R.getUtxos("https://lw", key.addr, mk(cat(OKT, fr(0, [])))), /unexpected/));
ok("L-5 request has a timeout signal; a stalled server is aborted", await (async () => { let sig; await R.getUtxos("https://lw", key.addr, async (u, i) => { sig = i.signal; return resp(cat(fr(0, []), OKT)); }); return sig && typeof sig.aborted === "boolean"; })());

// L-2 broadcast strictness
const bc = (bytes, o) => R.broadcast("https://lw", Uint8Array.of(1), mk(bytes, o), TX);
const okMsg = m => cat(fr(0, cat(m === undefined ? [] : ld(2, enc(m)))), OKT);
ok("L-2 empty 200 body / trailer-only / no grpc-status all fail", await rejects(bc(new Uint8Array(0))) && await rejects(bc(OKT), /without a message/) && await rejects(bc(fr(0, []))) && await rejects(bc(cat(fr(0, []), trailer("x: y\r\n"))), /no grpc-status/));
ok("L-2 success with a different txid is NOT success", await rejects(bc(okMsg("b1".repeat(32))), /different txid/));
ok("L-2 success with an empty message is NOT success", await rejects(bc(okMsg(undefined)), /different txid/));
ok("L-2 matching txid (plain / quoted / upper-case) succeeds", (await bc(okMsg(TX))) === TX && (await bc(okMsg('"' + TX + '"'))) === TX && (await bc(okMsg(TX.toUpperCase()))) === TX);
ok("L-2 errorCode != 0 rejected, with the message", await rejects(bc(cat(fr(0, cat(vf(1, 18), ld(2, enc("bad-txns")))), OKT)), /Rejected by network: bad-txns/));
ok("L-2 field 1 as bytes / field 2 as varint (malformed) refused", await rejects(bc(cat(fr(0, ld(1, [1])), OKT)), /malformed/) && await rejects(bc(cat(fr(0, vf(2, 5)), OKT)), /malformed/));
ok("L-2 grpc-status header (no trailer) non-zero fails; missing everywhere fails", await rejects(bc(fr(0, []), { h: { "grpc-status": "13", "grpc-message": "boom" } }), /boom/) && await rejects(bc(fr(0, []))));
ok("L-2 expectTxid is mandatory", await rejects(R.broadcast("https://lw", Uint8Array.of(1), mk(okMsg(TX))), /locally computed/));
ok("L-2 HTTP error status fails", await rejects(bc(new Uint8Array(0), { ok: false, status: 502 }), /502/));

// L-1 / L-6 expiry and branch from the tip
const utx = [{ txid: TX, n: 1, value: 1_000_000n, height: 3_600_000 }];
const sw = R.buildSweep({ utxos: utx, key, to: TO, tip: 3_600_010 });
const raw = sw.raw, dv = new DataView(raw.buffer, raw.byteOffset);
ok("L-1 expiry = tip + 40 is in the serialized tx (and the sighash)", sw.expiry === 3_600_050 && dv.getUint32(16, true) === 3_600_050 && dv.getUint32(8, true) === R.NU6_3_BRANCH);
const sw2 = R.buildSweep({ utxos: utx, key, to: TO, tip: 3_600_011 });
ok("L-1 a different tip changes the signed bytes/txid", sw2.txid !== sw.txid);
ok("L-1 no tip and no explicit expiry: refused (never 'never expires')", (() => { try { R.buildSweep({ utxos: utx, key, to: TO }); return false; } catch { return true; } })());
ok("L-6 tip below NU6.3 activation (3,428,143) refused; at activation accepted", (() => { try { R.buildSweep({ utxos: utx, key, to: TO, tip: 3_428_142 }); return false; } catch (e) { return /activation/.test(e.message); } })() && R.buildSweep({ utxos: [{ ...utx[0], height: 3_428_000 }], key, to: TO, tip: 3_428_143 }).branch === R.NU6_3_BRANCH);
ok("L-6 tip 0/NaN/float refused", [0, NaN, 3_600_000.5, -1].every(t => { try { R.branchForHeight(t); return false; } catch { return true; } }));
ok("L-1 a UTXO above the reported tip (lying tip) refused", (() => { try { R.buildSweep({ utxos: [{ ...utx[0], height: 3_700_000 }], key, to: TO, tip: 3_600_000 }); return false; } catch (e) { return /above the reported tip/.test(e.message); } })());
const tipRes = h => mk(cat(fr(0, cat(vf(1, h), ld(2, new Uint8Array(32)))), OKT));
ok("L-1 getTip: parses GetLatestBlock height; request is an empty message", await (async () => { let body, url; const t = await R.getTip("https://lw", async (u, i) => { body = i.body; url = u; return resp(cat(fr(0, vf(1, 3_600_000)), OKT)); }); return t === 3_600_000 && body.length === 5 && /GetLatestBlock$/.test(url); })());
ok("L-1 getTip: absent / below activation / absurd / non-varint height refused", await rejects(R.getTip("https://lw", mk(cat(fr(0, []), OKT)))) && await rejects(R.getTip("https://lw", tipRes(5)), /implausible/) && await rejects(R.getTip("https://lw", tipRes(2n ** 40n)), /implausible/) && await rejects(R.getTip("https://lw", mk(cat(fr(0, ld(1, [1])), OKT))), /bad tip/));

// L-3/L-4 dust and input cap
const many = n => Array.from({ length: n }, (_, i) => ({ txid: i.toString(16).padStart(64, "0"), n: 0, value: 100_000n + BigInt(i), height: 1 }));
ok("L-4 dust (<= 5000 zat) skipped, not counted in fee", (() => { const s = R.buildSweep({ utxos: [...utx, { txid: "bb".repeat(32), n: 0, value: 5000n, height: 1 }, { txid: "cc".repeat(32), n: 0, value: 1n, height: 1 }], key, to: TO, tip: 3_600_010 }); return s.amount === 1_000_000n - 10_000n; })());
ok("L-4 only dust: nothing to send", (() => { try { R.buildSweep({ utxos: [{ ...utx[0], value: 5000n }], key, to: TO, tip: 3_600_010 }); return false; } catch (e) { return /nothing/.test(e.message); } })());
ok("L-3 at most 50 inputs (biggest first); sweepSet matches what buildSweep spends", (() => { const u = many(700), set = R.sweepSet(u), s = R.buildSweep({ utxos: u, key, to: TO, tip: 3_600_010 }); return set.length === 50 && set[0].value === 100_699n && s.amount === set.reduce((a, x) => a + x.value, 0n) - R.sweepFee(50) && s.raw.length < 10_000; })());

// L-5 UTXO / protobuf validation
const U = (o = {}) => { const f = { txid: ld(1, Uint8Array.from({ length: 32 }, (_, i) => i)), n: vf(2, 0), script: ld(3, R.tAddrScript(key.addr)), value: vf(4, 50_000), height: vf(5, 3_600_000), ...o }; return cat(...Object.values(f).filter(x => x)); };
const list = (...us) => mk(cat(fr(0, cat(...us.map(u => ld(1, u)))), OKT));
const gu = (...us) => R.getUtxos("https://lw", key.addr, list(...us));
const good = await gu(U());
ok("L-5 a valid UTXO parses (txid reversed to display hex, value BigInt)", good.length === 1 && good[0].txid === R.hex(Uint8Array.from({ length: 32 }, (_, i) => 31 - i)) && good[0].value === 50_000n && good[0].n === 0);
ok("L-5 empty list is an empty array", (await gu()).length === 0);
for (const [name, u, re] of [["txid of 31 bytes", U({ txid: ld(1, new Uint8Array(31)) }), /txid/], ["txid as varint", U({ txid: vf(1, 5) }), /txid/], ["index as bytes", U({ n: ld(2, [1]) }), /index/], ["index >= 2^32", U({ n: vf(2, 2n ** 32n) }), /index/],
  ["value zero", U({ value: vf(4, 0) }), /value/], ["value > 21M ZEC", U({ value: vf(4, 2_100_000_000_000_001n) }), /value/], ["value as bytes", U({ value: ld(4, [1]) }), /value/], ["value negative int64 (2^64-1)", U({ value: vf(4, 2n ** 64n - 1n) }), /value/],
  ["missing value", U({ value: null }), /incomplete/], ["missing txid", U({ txid: null }), /incomplete/], ["foreign script", U({ script: ld(3, R.tAddrScript(TO)) }), /script/], ["script as varint", U({ script: vf(3, 1) }), /script/],
  ["echoed address differs", U({ addr: ld(6, enc(TO)) }), /another address/], ["height huge", U({ height: vf(4 + 1, 2n ** 40n) }), /height/]]) ok("L-5 hostile UTXO: " + name, await rejects(gu(u), re));
ok("L-5 duplicate outpoint refused", await rejects(gu(U(), U()), /duplicate/));
ok("L-5 UTXO entry that is a varint refused", await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, vf(1, 5)), OKT))), /bad UTXO entry/));
ok("L-5 echoed own address accepted", (await gu(U({ addr: ld(6, enc(key.addr)) }))).length === 1);
ok("L-5 varint of 11+ continuation bytes refused quickly (no BigInt blowup)", await (async () => { const t = Date.now(); const r = await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, cat([8], new Uint8Array(1_000_000).fill(0x80), [0])), OKT)), /varint too long/)); return r && Date.now() - t < 1000; })());
ok("L-5 truncated length-delimited field / truncated varint / bad wire type / field number 0 refused", await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, [0x0a, 50, 1]), OKT))), /truncated/) && await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, [0x08, 0x80]), OKT))), /truncated/) && await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, [0x0b]), OKT))), /wire/) && await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, [0x00, 1]), OKT))), /field number/));
ok("L-5 field tag >= 2^32 no longer aliases to field 1", await rejects(R.getUtxos("https://lw", key.addr, mk(cat(fr(0, cat(vi((1n << 32n) | (1n << 3n) | 2n), vi(1), [0])), OKT))), /bad field number|too long|truncated/) || (await R.getUtxos("https://lw", key.addr, mk(cat(fr(0, cat(vi((1n << 35n) | 2n), vi(1), [0])), OKT)))).length === 0);

// txKnown: structured NotFound only
const tk = (t, m) => R.txKnown("https://lw", TX, mk(trailer("grpc-status: " + t + "\r\ngrpc-message: " + m + "\r\n"))).then(v => v, e => "THROW");
ok("txKnown: status 5 = false; zcashd -5 text under status 2 = false; gateway 'not found' text / 'host not found' / status 12 THROW", await tk(5, "x") === false && await tk(2, "-5: No such mempool or blockchain transaction") === false && await tk(14, "upstream host not found") === "THROW" && await tk(2, "method not found") === "THROW" && await tk(12, "unknown service not found") === "THROW");

// I-1 master key range; I-3 multi-input signing consistency
{ const u = many(3), s = R.buildSweep({ utxos: u, key, to: TO, tip: 3_600_010 }), set = R.sweepSet(u);
  ok("I-3 3-input sweep: fee 15000, per-input sighashes differ, every signature verifies, txid independent of signatures", (() => {
    const script = R.tAddrScript(key.addr), t2 = { branch: s.branch, lockTime: 0, expiry: s.expiry, vin: set.map(x => ({ txid: x.txid, n: x.n, seq: 0xffffffff, value: x.value, script })), vout: [{ value: s.amount, script: R.tAddrScript(TO) }] };
    const sig = R.signAll(t2, key), hs = [0, 1, 2].map(i => R.hex(R.sighash(t2, i)));
    const okSig = sig.vin.every((x, i) => { const sl = x.sig[0], der = x.sig.slice(1, sl); return secp256k1.verify(secp256k1.Signature.fromDER(der).normalizeS(), R.sighash(t2, i), key.pub, { lowS: false }); });
    return s.amount === set.reduce((a, x) => a + x.value, 0n) - 15_000n && new Set(hs).size === 3 && okSig && R.txid(sig) === R.txid(t2) && R.txid(t2) === s.txid; })()); }
console.log(bad ? bad + " failed" : "all passed"); process.exit(bad ? 1 : 0);
