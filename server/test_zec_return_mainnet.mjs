// node server/test_zec_return_mainnet.mjs — parse a real mainnet v5 transparent tx (block 3534915, NU6.3 branch) and check txid, re-serialization and the input signature against our ZIP-244 sighash
import fs from "fs";
import * as R from "../web/zec-return.js";
import { secp256k1 } from "../web/vendor/noble.js";
const D = new URL("./fixtures/", import.meta.url).pathname;
const b = R.unhex(fs.readFileSync(D + "zec_v5_46abf62c.hex", "utf8").trim()), ins = JSON.parse(fs.readFileSync(D + "zec_v5_46abf62c_inputs.json")).inputs;
const dv = new DataView(b.buffer); let i = 0; const u32 = () => { const v = dv.getUint32(i, true); i += 4; return v; };
const cs = () => { const v = b[i++]; if (v < 253) return v; if (v === 253) { const r = dv.getUint16(i, true); i += 2; return r; } return u32(); };
u32(); u32(); const branch = u32(), lockTime = u32(), expiry = u32();
const vin = []; for (let n = cs(); n--;) { const txid = R.hex(b.slice(i, i + 32).reverse()); i += 32; const idx = u32(); const l = cs(); const sig = b.slice(i, i + l); i += l; vin.push({ txid, n: idx, sig, seq: u32() }); }
const vout = []; for (let n = cs(); n--;) { const value = dv.getBigUint64(i, true); i += 8; const l = cs(); vout.push({ value, script: b.slice(i, i + l) }); i += l; }
console.log("rest", R.hex(b.slice(i)));
vin.forEach((x, k) => { const m = ins.find(p => p.txid === x.txid && p.n === x.n) || ins[k]; x.value = BigInt(m.value); x.script = R.unhex(m.script); });
const tx = { branch, lockTime, expiry, vin, vout };
console.log("txid", R.txid(tx), R.txid(tx) === "46abf62cec0a6fce1ee80479c8169ecbdd6e47b140248a95fa755483029ae5d8" ? "MATCH" : "MISMATCH");
console.log("reserialize", R.hex(R.serialize(tx)) === R.hex(b) ? "MATCH" : "MISMATCH");
const s = vin[0].sig, sl = s[0], der = s.slice(1, sl), pub = s.slice(sl + 2, sl + 2 + s[sl + 1]);
console.log("sig valid over our sighash:", secp256k1.verify(secp256k1.Signature.fromDER(der).normalizeS(), R.sighash(tx, 0), pub, { lowS: false }), "hashtype", s[sl]);
