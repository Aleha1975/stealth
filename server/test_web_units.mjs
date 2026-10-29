/* Unit tests of the audit hardening that need neither anvil nor forge. Run: node test_web_units.mjs */
import { unhex, hex, checkAnnouncement, decodeMetadata, keysFromSignature, signKeyRequestWith, addressFromPriv, metaAddress } from "../web/stealth-crypto.js";
import { paymentNonce, feeWithinCap } from "../web/pay-auth.js";
import { requestQuote, buildQuoteRequest } from "../web/private-withdraw.js";
import { CHAINS } from "../web/chains.js";
import { cleanLog, ipKey, parseEnvLine } from "./relay-util.mjs";
import { makeScreen } from "./sanctions/screen.mjs";
import fs from "fs"; import os from "os"; import path from "path";
let fail = 0; const t = (n, c) => { console.log((c ? "PASS " : "FAIL ") + n); if (!c) fail++; };
const throws = f => { try { f(); return false; } catch { return true; } };

// 1086 I-1 strict hex
t("unhex: valid hex still works", hex(unhex("0x0aFF")) === "0x0aff" && unhex("abc").length === 2);
t("unhex: non-hex throws instead of turning into zero bytes", throws(() => unhex("0xzz1g")) && throws(() => unhex("12 34")));
// hostile indexer data never aborts a scan
const keys = keysFromSignature(signKeyRequestWith(new Uint8Array(32).fill(7), addressFromPriv(new Uint8Array(32).fill(7))), addressFromPriv(new Uint8Array(32).fill(7)));
t("checkAnnouncement: garbage ephemeral key -> null, no throw", checkAnnouncement(keys, "0xnothex", "0x00") === null && checkAnnouncement(keys, "0x" + "ab".repeat(10), "0x00") === null);
t("decodeMetadata: garbage -> null, no throw", decodeMetadata("0xzz") === null);
// 1086 I-3 pay-auth validation
const good = { chainId: 4663, stealthPay: "0x" + "11".repeat(20), token: "0x" + "22".repeat(20), stealth: "0x" + "33".repeat(20), eph: "0x02" + "44".repeat(32), viewTag: "0xab", fee: 50000n, feeRecipient: "0x" + "55".repeat(20) };
t("paymentNonce: valid input works", /^0x[0-9a-f]{64}$/.test(paymentNonce(good)));
t("paymentNonce: negative fee / bad address / bad tag / non-hex eph throw", throws(() => paymentNonce({ ...good, fee: -1n })) && throws(() => paymentNonce({ ...good, token: "0x12" })) && throws(() => paymentNonce({ ...good, viewTag: "0xabcd" })) && throws(() => paymentNonce({ ...good, eph: "0xzz" })) && throws(() => paymentNonce({ ...good, fee: 1n << 256n })));
// 1086 L-1 fee cap
const U = 1_000_000n;
t("feeWithinCap: 0.05 of 10 ok; 0.05 of 0.10 ok; 0.06 of 0.10 refused (> half)", feeWithinCap(50000n, 10n * U) && feeWithinCap(50000n, 100000n) && !feeWithinCap(60000n, 100000n));
t("feeWithinCap: above 1.00 absolute refused even on a big payment; negative refused", !feeWithinCap(2n * U, 1000n * U) && !feeWithinCap(-1n, 10n * U));
// 1086 L-2 deposit address sanity
{ const from = CHAINS.rh, stealth = "0x" + "ab".repeat(20), recipient = "0x" + "cd".repeat(20);
  const req = buildQuoteRequest({ from, to: from, amount: 5n * U, recipient, refundTo: stealth, dry: false });
  const mk = dep => async () => ({ ok: true, json: async () => ({ quote: { amountIn: req.amount, amountOut: "4900000", depositAddress: dep }, quoteRequest: { recipient, refundTo: stealth, originAsset: req.originAsset, destinationAsset: req.destinationAsset } }) });
  const run = dep => requestQuote({ req, fetchFn: mk(dep) }).then(() => true, () => false);
  t("requestQuote: a normal deposit address passes; our own refund / recipient / zero address is refused", (await run("0x" + "ee".repeat(20))) && !(await run(stealth)) && !(await run(recipient)) && !(await run("0x" + "00".repeat(20)))); }
// 1087 L-1 log injection
t("cleanLog: no line break survives", !/[\r\n\u2028\u2029\u0000]/.test(cleanLog("a\nb\r\nc\u2028d\u0000e")) && cleanLog("plain text 1.0") === "plain text 1.0");
// 1087 M-1 IPv6 /64
t("ipKey: IPv4 unchanged, mapped IPv4 -> IPv4", ipKey("1.2.3.4") === "1.2.3.4" && ipKey("::ffff:1.2.3.4") === "1.2.3.4");
t("ipKey: addresses of one /64 share a key, other /64 differ", ipKey("2001:db8:1:2::1") === ipKey("2001:0db8:0001:0002:ffff:ffff:ffff:ffff") && ipKey("2001:db8:1:2::1") !== ipKey("2001:db8:1:3::1") && ipKey("2001:db8:1:2::1") === "2001:db8:1:2::/64");
t("ipKey: compressed forms and junk", ipKey("::1") === "0:0:0:0::/64" && ipKey("not an ip") === "not an ip" && ipKey("") === "");
// 1087 L-2 env parsing
t("parseEnvLine: plain, export, quoted with # and quote, comment", JSON.stringify(parseEnvLine("A=1")) === '["A","1"]' && parseEnvLine("export B='x#y\"z'")[1] === 'x#y"z' && parseEnvLine('C="http://h/?k=a#b"  # c')[1] === "http://h/?k=a#b" && parseEnvLine("D=val  # note")[1] === "val" && parseEnvLine("# only a comment") === null);
// 1087 L-3 sanctions list sanity
{ const d = fs.mkdtempSync(path.join(os.tmpdir(), "sanc-")), f = path.join(d, "evm.json"), logs = [];
  fs.writeFileSync(f, JSON.stringify({ addresses: [], published: "x" }));
  t("sanctions: an empty list is a load error (fail closed)", throws(() => makeScreen(f, m => logs.push(m))));
  process.env.STEALTH_SANCTIONS_MIN = "2"; fs.writeFileSync(f, JSON.stringify({ addresses: ["0x" + "1".repeat(40)], published: "x" }));
  t("sanctions: fewer entries than STEALTH_SANCTIONS_MIN is refused", throws(() => makeScreen(f, m => logs.push(m))));
  delete process.env.STEALTH_SANCTIONS_MIN; fs.writeFileSync(f, JSON.stringify({ addresses: ["0x" + "1".repeat(40)], published: "x", fetched: "2020-01-01T00:00:00Z" }));
  const lg = []; makeScreen(f, (...m) => lg.push(m.join(" ")));
  t("sanctions: a list fetched years ago raises an ALERT but still screens", lg.some(l => /^ALERT sanctions list is older/.test(l)));
  fs.rmSync(d, { recursive: true, force: true }); }
console.log(fail ? "FAILED " + fail : "all passed"); process.exit(fail ? 1 : 0);
