// node server/test_zec_return.mjs — BIP32 vector, t-address script, live UTXO read; prints a fixed tx's txid/sighash for the Python ZIP-244 cross-check
import * as R from "../web/zec-return.js";
let bad = 0; const ok = (c, m) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) bad++; };
// BIP32 test vector 1: m/0'/1/2'/2/1000000000 private key
const k = R.deriveT(R.unhex("000102030405060708090a0b0c0d0e0f"), [0x80000000, 1, 0x80000002, 2, 1000000000]);
ok(R.hex(k.priv) === "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", "bip32 vector 1 leaf key");
ok(R.hex(R.tAddrScript("t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLt")) === "76a914569609e3bf69aa3446ce00ac6bebe67e075e8f9588ac", "t1 address -> P2PKH script");
let threw = false; try { R.tAddrScript("t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLu"); } catch { threw = true; } ok(threw, "bad checksum refused");
const key = R.deriveT(new Uint8Array(64).fill(7), R.tPath(0, 0));
const utxos = [{ txid: "a083616da180465d19aa92f019ec4b57e1bf145319ca8030b0856f973c379534", n: 0, value: 1434934n }];
const tx = { branch: R.NU6_3_BRANCH, lockTime: 0, expiry: 0, vin: [{ txid: utxos[0].txid, n: 0, seq: 0xffffffff, value: 1434934n, script: R.unhex("76a914" + "11".repeat(20) + "88ac") }], vout: [{ value: 1424934n, script: R.tAddrScript("t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLt") }] };
console.log("FIXED " + JSON.stringify({ txid: R.txid(tx), sighash: R.hex(R.sighash(tx, 0)), raw: R.hex(R.serialize(tx)) }));
const sw = R.buildSweep({ utxos, key, to: "t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLt" });
ok(sw.amount === 1424934n, "sweep amount = total - fee");
console.log("SWEEP " + JSON.stringify({ raw: R.hex(sw.raw), txid: sw.txid, pub: R.hex(key.pub), addr: key.addr }));
if (process.argv.includes("--live")) {
  const u = await R.getUtxos("https://zcash-mainnet.chainsafe.dev", "t1RmRrhYbbAka8JZ4APf27rnZ43cHy9NqLt");
  console.log("LIVE", JSON.stringify(u, (k, v) => typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? R.hex(v) : v));
  ok(u.length === 1 && u[0].txid === utxos[0].txid && u[0].value === 1434934n, "live UTXO matches explorer");
}
console.log(bad ? bad + " failed" : "all passed"); process.exit(bad ? 1 : 0);
