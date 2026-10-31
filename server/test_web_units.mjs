/* Unit tests of the audit hardening that need neither anvil nor forge. Run: node test_web_units.mjs */
import { unhex, hex, checkAnnouncement, decodeMetadata, keysFromSignature, signKeyRequestWith, addressFromPriv, metaAddress } from "../web/stealth-crypto.js";
import { paymentNonce, feeWithinCap } from "../web/pay-auth.js";
import * as PWm from "../web/private-withdraw.js";
import { requestQuote, buildQuoteRequest } from "../web/private-withdraw.js";
import { CHAINS } from "../web/chains.js";
import { cleanLog, ipKey, parseEnvLine } from "./relay-util.mjs";
import { makeScreen } from "./sanctions/screen.mjs";
import { postRelay } from "../web/relay-post.js";
import { parseMeta, deriveForPayment } from "../web/stealth-crypto.js";
import { secp256k1 as secp } from "../web/vendor/noble.js";
import * as CR from "../web/chain-read.js";
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

// ---- audit 1098 round 2
const PRIV = new Uint8Array(32).fill(9), ACC = addressFromPriv(PRIV), A2 = "0x" + "a2".repeat(20), A3 = "0x" + "a3".repeat(20);
// L-1 high-s wallet: canonical keys + legacy (raw) keys, both belonging to the account
{ const good = signKeyRequestWith(PRIV, ACC), rs = unhex(good).slice(0, 64), v = unhex(good)[64] - 27;
  const sg = secp.Signature.fromCompact(rs), hi = new secp.Signature(sg.r, secp.CURVE.n - sg.s), hv = v ^ 1;
  const highHex = "0x" + Buffer.from(hi.toCompactRawBytes()).toString("hex") + (27 + hv).toString(16);
  const kLow = keysFromSignature(good, ACC), kHigh = keysFromSignature(highHex, ACC);
  t("1098 L-1: high-s signature gives the same canonical keys as the low-s one (no malleability)", metaAddress(kLow, "rh") === metaAddress(kHigh, "rh") && !kLow.legacy);
  t("1098 L-1: high-s signature also yields legacy keys (derived from the raw bytes), different from the canonical ones", !!kHigh.legacy && metaAddress(kHigh.legacy, "rh") !== metaAddress(kHigh, "rh"));
  // an old payment made to the legacy meta-address is found with the legacy keys only
  const d = deriveForPayment(parseMeta(metaAddress(kHigh.legacy, "rh")));
  t("1098 L-1: a payment to the legacy meta-address is found by the legacy keys, not by the canonical ones", checkAnnouncement(kHigh.legacy, d.ephPub, d.viewTag)?.stealth === d.stealth && checkAnnouncement(kHigh, d.ephPub, d.viewTag) === null);
  t("1098 L-1: odd-length / non-hex signature refused", throws(() => keysFromSignature(good.slice(0, -1), ACC)) && throws(() => keysFromSignature("0xzz", ACC)));
  t("1098 I-4: parseMeta rejects a key that is not a curve point", throws(() => parseMeta("st:rh:0x" + "02" + "00".repeat(32) + "02" + "00".repeat(32))) && parseMeta(metaAddress(kLow, "rh")).spendPub.length === 33); }
// L-3 relay-post: 502/504 and dropped connections are settled on chain before any retry
{ const R = (status, json) => ({ ok: status < 400, status, json: async () => { if (json === undefined) throw new Error("not json"); return json; } });
  const run = (replies, check, delays = [1, 1, 1]) => { let calls = 0, msgs = []; const f = async () => { const x = replies[Math.min(calls++, replies.length - 1)]; if (x instanceof Error) throw x; return x; };
    return postRelay(f, "/relay", { a: 1 }, { sleep: async () => {}, delays, check, onBusy: m => msgs.push(m) }).then(v => ({ v, calls, msgs }), e => ({ e: e.message, calls, msgs })); };
  let o = await run([R(504), R(200, { hash: "0x" + "ab".repeat(32) })], async () => false);
  t("1098 L-3: 504 + authorization unused on chain -> retried, then succeeds; user told it is being checked", o.v?.d.hash && o.calls === 2 && o.msgs.some(m => /may or may not have received it/.test(m)));
  o = await run([R(502), R(200, { hash: "0x1" })], async () => true);
  t("1098 L-3: 502 + authorization already used on chain -> NO second request, reported as used", o.v?.d.used === true && o.calls === 1);
  o = await run([R(504)], async () => { throw new Error("rpc down"); });
  t("1098 L-3: 504 and the chain cannot be read -> stop, say do not pay again, no retry", /Do not pay again/.test(o.e || "") && o.calls === 1);
  o = await run([new Error("network down"), R(200, { hash: "0x" + "cd".repeat(32) })], async () => false);
  t("1098 L-3: a dropped connection is treated like a 504 (checked, then retried)", o.v?.d.hash && o.calls === 2);
  o = await run([new Error("network down")], null);
  t("1098 L-3: without a check function a dropped connection still throws", o.e === "network down");
  o = await run([R(504)], async () => false, [1, 1]);
  t("1098 L-3: persistent 504, never on chain -> final message does not claim 'nothing was sent'", /NOT found on chain|before paying again/.test(o.e || "") && !/Nothing was sent/.test(o.e) && o.calls === 3);
  o = await run([R(503), R(200, { hash: "0x" + "ee".repeat(32) })], async () => { throw new Error("must not be called for 503"); });
  t("1098 L-3: 503/429 (rejected before proxying) are retried without touching the chain", o.v?.d.hash && o.calls === 2);
  o = await run([R(400, { error: "nope" })], async () => true);
  t("1098 L-3: a real JSON answer is returned at once", o.v?.d.error === "nope" && o.calls === 1); }
// M-2 / L-4 chain reads
{ const word = n => "0x" + BigInt(n).toString(16).padStart(64, "0"), TOK = "0x" + "77".repeat(20), seen = [];
  const batch = async calls => { seen.push(...calls); return calls.map(([m, p]) => m === "eth_getBalance" ? word(5) : word(BigInt("0x" + p[0].data.slice(-4)))); };
  const b = await CR.getBalances(batch, TOK, [A2, A3]);
  t("1098 M-2: balances come from RPC calls (eth_call balanceOf + eth_getBalance) per address, parsed as BigInt", b.get(A2).eth === 5n && b.get(A3).usdc === BigInt("0x" + "a3".repeat(2)) && seen.length === 4 && seen.every(([m]) => m === "eth_call" || m === "eth_getBalance"));
  t("1098 M-2: a short / garbled RPC batch answer is an error, not zero", await CR.getBalances(async () => [word(1)], TOK, [A2]).then(() => false, () => true) && await CR.getBalances(async c => c.map(() => "nonsense"), TOK, [A2]).then(() => false, () => true));
  const fb = (j, ok = true) => async () => ({ ok, status: ok ? 200 : 500, json: async () => j });
  t("1098 M-2: fetchBatch validates ids / errors / missing results", (await CR.fetchBatch(fb([{ id: 2, result: "0x2" }, { id: 1, result: "0x1" }]), "u", [["a", []], ["b", []]])).join() === "0x1,0x2" && await CR.fetchBatch(fb([{ id: 1, result: "0x1" }, { id: 1, result: "0x1" }]), "u", [["a", []], ["b", []]]).then(() => false, () => true) && await CR.fetchBatch(fb([{ id: 1, error: { message: "x" } }]), "u", [["a", []]]).then(() => false, () => true) && await CR.fetchBatch(fb({ result: "0x1" }), "u", [["a", []]]).then(() => false, () => true));
  const tx = "0x" + "11".repeat(32), pad32 = a => "0x" + "0".repeat(24) + a.slice(2).toLowerCase();
  const rcOf = (o = {}) => ({ transactionHash: tx, status: "0x1", from: A2, blockNumber: "0x10", logs: [{ address: TOK, topics: [CR.TRANSFER_TOPIC, pad32(A2), pad32(A3)], data: word(1234) }], ...o });
  const rpcOf = rc => async (m) => { if (m === "eth_getTransactionReceipt") return rc; throw new Error("unexpected " + m); };
  const good = await CR.fetchReceipt(rpcOf(rcOf()), tx);
  t("1098 L-4: Transfer event matched on token, from, to and exact value; any other value/recipient/token fails", CR.hasTransfer(good, { token: TOK, from: A2, to: A3, value: 1234n }) && !CR.hasTransfer(good, { token: TOK, from: A2, to: A3, value: 1235n }) && !CR.hasTransfer(good, { token: TOK, from: A2, to: A2, value: 1234n }) && !CR.hasTransfer(good, { token: "0x" + "78".repeat(20), from: A2, to: A3, value: 1234n }));
  t("1098 L-4: a receipt for another hash / a reverted receipt / a forged shape is not accepted as success", await CR.fetchReceipt(rpcOf(rcOf({ transactionHash: "0x" + "22".repeat(32) })), tx).then(() => false, () => true) && !(await CR.fetchReceipt(rpcOf(rcOf({ status: "0x0" })), tx)).ok && await CR.fetchReceipt(rpcOf({ status: "0x1" }), tx).then(() => false, () => true));
  const SP = "0x" + "55".repeat(20), ETHT = CR.ETH_TOKEN, paid = CR.PAID_TOPIC;
  const prc = await CR.fetchReceipt(rpcOf(rcOf({ logs: [{ address: SP, topics: [paid, pad32(A3), pad32(TOK)], data: word(99) }] })), tx);
  t("1098 L-4: Paid event matched on contract, stealth, token and amount", CR.hasPaid(prc, { stealthPay: SP, stealth: A3, token: TOK, amount: 99n }) && !CR.hasPaid(prc, { stealthPay: SP, stealth: A2, token: TOK }) && !CR.hasPaid(prc, { stealthPay: SP, stealth: A3, token: ETHT }) && !CR.hasPaid(prc, { stealthPay: "0x" + "56".repeat(20), stealth: A3 }));
  // waitFinal: API-offered replacement hash is followed only if the chain agrees (same sender and nonce)
  const orig = "0x" + "aa".repeat(32), repl = "0x" + "bb".repeat(32), evil = "0x" + "cc".repeat(32);
  const chain = (txs, rcs) => async (m, p) => m === "eth_getTransactionByHash" ? (txs[p[0]] || null) : m === "eth_getTransactionReceipt" ? (rcs[p[0]] || null) : (() => { throw new Error("unexpected " + m); })();
  const rcFor = h => ({ transactionHash: h, status: "0x1", logs: [], from: A2 }), sl = { sleep: async () => {}, tries: 12, everyMs: 0 };
  let r = await CR.waitFinal(chain({ [orig]: { hash: orig, from: A2, nonce: "0x5" }, [repl]: { hash: repl, from: A2, nonce: "0x5" } }, { [repl]: rcFor(repl) }), orig, { ...sl, follow: async () => repl });
  t("1098 L-4: a replacement with the same sender and nonce is followed to its mined receipt", r.ok && r.hash === repl);
  r = await CR.waitFinal(chain({ [orig]: { hash: orig, from: A2, nonce: "0x5" }, [evil]: { hash: evil, from: A3, nonce: "0x5" } }, { [evil]: rcFor(evil) }), orig, { ...sl, tries: 8, follow: async () => evil }).then(() => "ok", e => e.message);
  t("1098 L-4: a fabricated 'replaced by' hash from another sender is never followed (times out instead of Done)", /not mined yet/.test(r));
  r = await CR.waitFinal(chain({}, { [orig]: rcFor(orig) }), orig, { ...sl, expect: () => false });
  t("1098 L-4: mined but without the expected event -> not ok (unexpected)", r.ok === false && r.unexpected === true);
  r = await CR.waitFinal(chain({}, { [orig]: { ...rcFor(orig), status: "0x0" } }), orig, sl);
  t("1098 L-4: reverted receipt -> not ok", r.ok === false); }
// authorizationState read
{ const seen = []; const used = await CR.authorizationUsed(async (m, p) => { seen.push(p[0].data); return "0x" + "0".repeat(63) + "1"; }, "0x" + "77".repeat(20), A2, "0x" + "12".repeat(32));
  t("1098 L-3: authorizationUsed encodes authorizationState(from, nonce) and reads the bool", used === true && seen[0].startsWith("0xe94a0102") && seen[0].length === 10 + 128 && await CR.authorizationUsed(async () => "0x" + "0".repeat(64), "0x" + "77".repeat(20), A2, "0x" + "12".repeat(32)) === false); }
// M-2: no stealth address may reach our API (static check of the page code)
{ const src = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  t("1098 M-2: app.js never puts a stealth address in an API URL (no /balances, no addrs=)", !/\/balances/.test(src) && !/addrs=/.test(src));
  t("1098 M-2: the only API reads left carry no stealth address (head, announcements, pages, relay stats/status/screen/sanctions-list)", [...src.matchAll(/api\("([^"]*)"/g)].every(m => /^\/(head|announcements\?|relay\/stats|relay\/status\?hash=|relay\/screen\?addr=|relay\/sanctions-list$)/.test(m[1])));
  t("1098 L-4: receipts are not read from our API any more", !/\/receipt\?/.test(src)); }
// ---- round 3 (audit 1101)
{ const TOK = "0x" + "77".repeat(20), pad32 = a => "0x" + "0".repeat(24) + a.slice(2).toLowerCase(), nonce = "0x" + "12".repeat(32), nonce2 = "0x" + "13".repeat(32);
  const au = (n, o = {}) => ({ ok: true, logs: [{ address: TOK, topics: [CR.AUTH_USED_TOPIC, pad32(A2), n], data: "0x" }], ...o });
  t("1101 L-1: a receipt counts for THIS request only if the token emitted AuthorizationUsed(authorizer, nonce) with its nonce", CR.hasAuthUsed(au(nonce), { token: TOK, authorizer: A2, nonce }) && !CR.hasAuthUsed(au(nonce2), { token: TOK, authorizer: A2, nonce }) && !CR.hasAuthUsed(au(nonce), { token: TOK, authorizer: A3, nonce }) && !CR.hasAuthUsed(au(nonce), { token: "0x" + "78".repeat(20), authorizer: A2, nonce }) && !CR.hasAuthUsed({ ...au(nonce), ok: false }, { token: TOK, authorizer: A2, nonce }));
  t("1101 L-1: AUTH_USED_TOPIC is keccak(AuthorizationUsed(address,bytes32))", CR.AUTH_USED_TOPIC === "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5");
  // L-4: the original hash keeps being polled after a replacement is followed
  const orig = "0x" + "aa".repeat(32), repl = "0x" + "bb".repeat(32); let step = 0;
  const rpc = async (m, p) => m === "eth_getTransactionByHash" ? { hash: p[0], from: A2, nonce: "0x5" } : m === "eth_getTransactionReceipt" ? (p[0] === orig && step >= 6 ? { transactionHash: orig, status: "0x1", logs: [], from: A2 } : null) : (() => { throw new Error(m); })();
  const r = await CR.waitFinal(rpc, orig, { sleep: async () => { step++; }, tries: 12, everyMs: 0, follow: async () => repl });
  t("1101 L-4: after following a replacement, the ORIGINAL that mines first is still found", r.ok && r.hash === orig);
  // L-5: timeouts
  let sig; await CR.fetchBatch(async (u, i) => { sig = i.signal; return { ok: true, json: async () => [{ id: 1, result: "0x1" }] }; }, "u", [["a", []]]);
  t("1101 L-5: batch reads carry a timeout signal; timeoutSignal aborts", sig && typeof sig.aborted === "boolean" && CR.timeoutSignal(1) instanceof AbortSignal); }
{ const src = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const scanSrc = src.slice(src.indexOf("async function scan()"), src.indexOf("async function refreshBalances"));
  t("1101 M-1: scan lists the payments (render) BEFORE the balance read, and the read is best effort in pages", scanSrc.indexOf("render()") > 0 && scanSrc.indexOf("render()") < scanSrc.indexOf("await refreshBalances") && /PAGE = 50/.test(src) && /catch \{ if \(t === 0\)/.test(src));
  t("1101 L-3: reads never fall back to the wallet provider unless asked (only the token's domain separator asks)", /const chainRpc = async \(u, init, allowWallet = false\)/.test(src) && (src.match(/\}, true\)/g) || []).length === 1 && /if \(allowWallet\) return walletRpc/.test(src));
  t("1101 I-2: key derivation and scan are single-flight; a scan works on its own list and keys", /\$\("btn-keys"\)\.addEventListener\("click", once\(/.test(src) && /\$\("btn-scan"\)\.addEventListener\("click", once\(/.test(src) && /const K = keys, mine = \[\]/.test(src) && /if \(keys !== K\) return;/.test(src));
  t("1101 L-1/L-2: the withdraw receipt must carry the request's nonce; a confirmation timeout says 'do not send again' and arms a pending guard", /hasAuthUsed\(x, \{ token: USDC, authorizer: w\.stealth, nonce \}\)/.test(src) && /not confirmed yet \(tx/.test(src) && /pendingWd\.set/.test(src) && /AUTH_USED_TOPIC, "0x" \+ padAddr\(w\.stealth\), nonce/.test(src));
  t("1105 L-4: every hop-record writer outside the machine takes the machine's Web Lock", (src.match(/underHopLock\(/g) || []).length >= 5);
  t("1103 L-1: the sweep is recorded BEFORE it is broadcast, and an earlier one that is on the network is resumed, not rebuilt", src.indexOf("const intent =") > 0 && src.indexOf("const intent =") < src.indexOf("sweepIntents.set(h, intent)") && src.indexOf("sweepIntents.set(h, intent)") < src.indexOf("ZR.sendAndConfirm(ZC.lightwalletd") && /ZR\.txKnown\(ZC\.lightwalletd, prev\.txid\)/.test(src));
  t("1103 M-1: a dust-only or too-long list is never an 'empty' observation", /unspendable = true/.test(src) && src.indexOf("unspendable) {") < src.indexOf("noteEmptyFor(HM, h, true)"));
  t("statuses still tick every second", /setInterval\(\(\) => \{ const r = \[\.\.\.hops\.values\(\)\]\.filter\(h => h\.running\);[^]*?\}, 1000\);/.test(src)); }

// ---------- round 4 (audits 1109 / 1110): confirmation depth, resilient polling, armed-before-send guard ----------
{ const src = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  // 1109 I-3: timeoutSignal without AbortSignal.timeout still times out
  const saved = AbortSignal.timeout; delete AbortSignal.timeout; let sg; try { sg = CR.timeoutSignal(20); } finally { AbortSignal.timeout = saved; }
  await new Promise(r => setTimeout(r, 60));
  t("1109 I-3: without AbortSignal.timeout an AbortController fallback still aborts", sg instanceof AbortSignal && sg.aborted === true);
  // 1109 L-4: one failed poll does not end the wait; persistent failures still say 'not mined yet'
  const H1 = "0x" + "cc".repeat(32); let calls = 0;
  const flaky = async (m, p) => { if (m === "eth_getTransactionReceipt") { if (calls++ < 2) throw new Error("the chain RPC did not answer"); return { transactionHash: H1, status: "0x1", logs: [], from: "0x" + "11".repeat(20), blockNumber: "0x10" }; } return null; };
  const fr = await CR.waitFinal(flaky, H1, { sleep: async () => {}, tries: 6, everyMs: 0 });
  t("1109 L-4: a failed receipt poll is retried, the wait still ends in the result", fr.ok === true && calls === 3);
  const dead = async (m) => { if (m === "eth_getTransactionReceipt") throw new Error("the chain RPC did not answer"); return null; };
  const de = await CR.waitFinal(dead, H1, { sleep: async () => {}, tries: 3, everyMs: 0 }).then(() => null, e => e.message);
  t("1109 L-4: if every poll fails the error is the 'not mined yet' one (which carries the do-not-pay-again wording in the app)", /^not mined yet: /.test(de || "") && /last read error/.test(de));
  // 1109 I-8: confirmation depth
  let tipN = 16; const deep = async (m) => m === "eth_blockNumber" ? "0x" + tipN.toString(16) : m === "eth_getTransactionReceipt" ? { transactionHash: H1, status: "0x1", logs: [], from: "0x" + "11".repeat(20), blockNumber: "0x10" } : null;
  const d1 = await CR.waitFinal(deep, H1, { sleep: async () => { tipN++; }, tries: 5, everyMs: 0, confirmations: 2 });
  t("1109 I-8: with 2 confirmations the first inclusion is not 'Done' until the next block is on top", d1.ok === true && tipN === 17);
  tipN = 16; const d2 = await CR.waitFinal(deep, H1, { sleep: async () => {}, tries: 3, everyMs: 0, confirmations: 2 }).then(() => "done", e => /not mined yet/.test(e.message) ? "waiting" : e.message);
  t("1109 I-8: a stuck tip never reports Done at depth 1", d2 === "waiting");
  t("1109 I-8: the app asks for 2 confirmations on Robinhood Chain", /confirmations: C\.key === "rh" \? 2 : 1/.test(src));
  // 1109 L-2: the relay POST carries a timeout signal; hung history fetches are bounded
  let rs; await postRelay(async (u, i) => { rs = i.signal; return { ok: true, status: 200, json: async () => ({ hash: "0x" + "1".repeat(64) }) }; }, "u", {}, {});
  t("1109 L-2: the relay POST carries a timeout signal (a hang becomes an ambiguous outcome settled on chain)", rs && typeof rs.aborted === "boolean");
  let qs; await requestQuote({ fetchFn: async (u, i) => { qs = i.signal; return { ok: true, status: 200, json: async () => ({}) }; }, req: {} }).catch(() => {});
  t("1111 L-2: quote / deposit / status calls to NEAR Intents carry a timeout signal", qs && typeof qs.aborted === "boolean");
  t("1109 L-2: history pages and the manifest fetch are bounded", /\/pages\/p"[^;]*signal: timeoutSignal\(60000\)/.test(src) && /manifest\.json", \{ cache: "no-cache", signal: timeoutSignal\(\) \}/.test(src));
  // 1109 L-1: the guard is armed BEFORE the request leaves, persisted, and cleared only by a confirmed outcome
  const wdSrc = src.slice(src.indexOf('$("btn-wd").addEventListener("click"'), src.indexOf("async function waitReceipt"));
  t("1109 L-1: pendingWd is set (until the authorization expires) before postRelay, and persisted", wdSrc.indexOf("pendingWd.set(") > 0 && wdSrc.indexOf("pendingWd.set(") < wdSrc.indexOf("await postRelay(") && /\(now \+ 3600 \+ 60\) \* 1000/.test(wdSrc) && /localStorage\.setItem\(PW_KEY/.test(src));
  t("1109 L-1: it is cleared only on the relayer's own JSON refusal, a revert or success (not on an unknown outcome)", /if \(ans\.definite\) pendingWd\.delete/.test(wdSrc) && /d\.definite === true/.test(fs.readFileSync(new URL("..\/web\/private-withdraw.js", import.meta.url), "utf8")) && (wdSrc.match(/pendingWd\.delete/g) || []).length === 3 && !/Date\.now\(\) \+ 600_000/.test(src));
  // 1109 L-3, I-1, I-2, I-5, I-6
  t("1109 L-3: a failed log read inside txOfLogs is retried; the final message says the withdrawal is already on chain", /try \{ l = \(await recentLogs\(rpcOne, filter\)\)/.test(src) && /already on chain \(its authorization is used\)/.test(src));
  t("1109 I-1/I-2: the left-over uses the captured amount; a non-bigint balance is refused", /left: all - value/.test(src) && /typeof all !== "bigint" \|\| !\(value > 0n\)/.test(src) && !/left: w\.usdc - value/.test(src));
  t("1109 I-5: a failed re-read always marks the row unread", /if \(!x\) \{ f\.usdc = null; unread\+\+; continue; \}/.test(src));
  t("1109 I-6: hopCtx defines authUsed once; the stale wallet-RPC comment is gone", (src.slice(src.indexOf("const hopCtx"), src.indexOf("const rpcOne")).match(/authUsed:/g) || []).length === 1 && !/go through the connected wallet's own RPC/.test(src));
  const html = fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8");
  t("1109 I-7: the CSP keeps blob: and says why", /script-src 'self' blob:/.test(html) && /I-7: script-src\/worker-src blob: is deliberate/.test(html));
  // 1110 L-1 / L-2 (returnZec lives in app.js: checked on its text, like the other sweep guards)
  const rz = src.slice(src.indexOf("async function returnZec"), src.indexOf("async function staleV1"));
  t("1110 L-1: an unresolved sweep intent is followed in the empty branch BEFORE any empty observation, and an ended one only pauses it", rz.indexOf("const sp = await prevOf()") > 0 && rz.indexOf("const sp = await prevOf()") < rz.indexOf("noteEmptyFor(HM, h, true)") && /if \(!sp\.ended\) return await finishSweep/.test(rz) && /ended: fin\.status/.test(rz));
  t("1110 L-2: no second sweep before the first one's expiry height has passed (the intent stores it)", /expiry: sw\.expiry/.test(rz) && /tipNow <= until/.test(rz) && /!prev\.ended/.test(rz));
  // 1137 M-1 / L-1 / L-2
  const lk = rz.slice(rz.indexOf("const saved = await underHopLock"), rz.indexOf("if (!saved)")), fs_ = src.slice(src.indexOf("async function finishSweep"), src.indexOf("async function staleV1"));
  t("1137 M-1: inside the lock the intent is re-read and a different unended one refuses, before set() and the broadcast", lk.indexOf("sweepIntents.get(h)") > 0 && lk.indexOf("sweepIntents.get(h)") < lk.indexOf("sweepIntents.set(h, intent)") && /cur\.txid !== intent\.txid\) return "busy"/.test(lk) && /saved === "busy"/.test(rz));
  t("1137 M-1: only a definite refusal marks the stored intent not-sent; an unknown outcome stays live; a not-sent intent is not followed", /catch \(e\) \{ if \(\/\^Rejected by network\|different txid\/\.test/.test(lk) && /notSent: true/.test(lk) && /prevOk\(sp\) && !sp\.notSent/.test(rz) && !/notSent: true[^\n]*\n[^\n]*else/.test(lk) && /throw e; \}/.test(lk));
  t("1137 L-1: every end (SUCCESS too) settles the intent with ended + endedAt, before the Done text; an ended SUCCESS is not reported as a refund on its way", fs_.indexOf("ended: fin.status, endedAt") > 0 && fs_.indexOf("ended: fin.status, endedAt") < fs_.indexOf('"Done: ') && /sp\.ended !== "SUCCESS" && Date\.now\(\) - \(sp\.endedAt/.test(rz));
  t("1137 L-2: a lost wallet's found shielded value is read before the card is forgotten and said in the Done text", /const sh = h\.lost && lost\.get\(h\.lost\) && lost\.get\(h\.lost\)\.shielded;/.test(fs_) && fs_.indexOf("const sh =") < fs_.indexOf("lostForget(h.lost)") && /\(sh \? " Shielded ZEC[^"]*may remain/.test(fs_)); }

// ---- round 5 (audit 1121): pendingWd memory fallback, lost-answer retry, honest busy text
{ const src = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const a = src.indexOf("const PW_KEY"), b = src.indexOf("const spent = new Map()"), code = src.slice(a, b);
  const mk = ls => new Function("localStorage", "Date", code + "; return pendingWd;")(ls, Date);
  const until = Date.now() + 3600_000;
  const writeFails = { getItem: () => null, setItem: () => { throw new Error("QuotaExceededError"); } };      // reads fine, writes throw
  const p1 = mk(writeFails); p1.set("0xaa", until);
  t("1121 L-1: storage that reads fine but refuses writes still keeps the guard armed (memory copy is consulted)", p1.get("0xaa") === until);
  p1.delete("0xaa"); t("1121 L-1: ... and delete clears it", p1.get("0xaa") === 0);
  const store = {}; const ok1 = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } };
  const p2 = mk(ok1); p2.set("0xbb", until); const p3 = mk(ok1);
  t("1121 L-1: normal storage still shares the guard across instances (reload / second tab)", p3.get("0xbb") === until);
  const broken = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } }; const p4 = mk(broken); p4.set("0xcc", until);
  t("1121 L-1: storage that throws everywhere falls back to memory", p4.get("0xcc") === until);
  const wdSrc = src.slice(src.indexOf('$("btn-wd").addEventListener("click"'), src.indexOf("async function waitReceipt"));
  t("1121 L-2: 'authorization already used' is followed on chain (txOfLogs) and never clears the guard; only a 400/403/429 JSON refusal clears it",
    /PW\.relayOutcome\(r, d\)/.test(wdSrc) && /if \(ans\.kind === "error"\) \{ if \(ans\.definite\) pendingWd\.delete/.test(wdSrc) && /if \(ans\.kind === "used"\) d\.hash = await txOfLogs/.test(wdSrc) && !/if \(d\.error\) pendingWd\.delete/.test(wdSrc) && /authorization already used/i.test(fs.readFileSync(new URL("../web/private-withdraw.js", import.meta.url), "utf8")));
  const rp = fs.readFileSync(new URL("../web/relay-post.js", import.meta.url), "utf8");
  t("1121 I-2: a busy/503 final message no longer says 'Nothing was sent'", !/Nothing was sent/.test(rp) && /may be out/.test(rp));
  t("1122 L-3: a SUCCESS return hides the card only after a hopSummary shows nothing left (shielded included)", /left && !HM\.holdsZec\(left\)\) await hideHop/.test(src)); }
  t("fast route: an UNKNOWN part keeps the pendingWd guard after a reload", /if \(!rec\.parts\.some\(p => p\.state === "UNKNOWN"\)\) pendingWd\.delete\(k\)/.test(fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8")));
// ---- audit 1125 (round 6)
{ const src = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const a = src.indexOf("const FAST_KEY"), b = src.indexOf("async function fastWithdraw"), code = src.slice(a, b);
  const mkStore = () => { const st = {}; return { getItem: k => st[k] ?? null, setItem: (k, v) => { st[k] = v; }, removeItem: k => { delete st[k]; }, key: i => Object.keys(st)[i] ?? null, get length() { return Object.keys(st).length; } }; };
  const mk = ls => new Function("localStorage", "PW", "$", code + "; return { fastRecs, fastClaim, fastNotes, fastNeedsNote };")(ls, PWm, () => ({}));
  const ls = mkStore(), A = mk(ls), S = "0x" + "ab".repeat(20);
  const recOf = (st, extra = {}) => ({ v: 1, stealth: S, startedAt: 1, parts: [{ amount: "3000000", state: st, depositAddress: "0x" + "e1".repeat(20), txHash: null }], ...extra });
  A.fastClaim(recOf("PLANNED")); const A2 = mk(ls);         // a second tab sees the same storage
  let err = null; try { A2.fastClaim(recOf("PLANNED", { startedAt: 2 })); } catch (e) { err = e.message; }
  t("1125 F-1: a second withdraw from an address with an open record is refused and the stored record is untouched", /still open/.test(err || "") && A.fastRecs.read()[S].startedAt === 1);
  const r1 = A.fastRecs.read()[S]; r1.parts[0].state = "DEPOSITED"; A.fastRecs.put(r1);
  err = null; try { A2.fastClaim(recOf("PLANNED", { startedAt: 3 })); } catch (e) { err = e.message; }
  t("1125 F-1: ... also when the open part is DEPOSITED (poll timed out), its deposit address stays", /still open/.test(err || "") && A.fastRecs.read()[S].parts[0].depositAddress === "0x" + "e1".repeat(20));
  r1.parts[0].state = "SUCCESS"; A.fastRecs.put(r1); A2.fastClaim(recOf("PLANNED", { startedAt: 4 }));
  t("1125 F-1: once the record is finished a new withdraw can start (one record per withdraw, no queue)", A.fastRecs.read()[S].startedAt === 4);
  const src2 = src.slice(src.indexOf("async function fastWithdraw"), src.indexOf("async function resumeFast"));
  t("1125 F-1: the record is claimed INSIDE the lock (a refused tab writes nothing) and the unclaimed run never touches guard or notes", /const run = \(\) => \{ fastClaim\(rec\); claimed = true;/.test(src2) && !/save\(rec\); const run/.test(src2) && /const settleGuard = \(\) => \{ if \(claimed/.test(src2));
  // F-2
  const N1 = mkStore(), M1 = mk(N1).fastNotes, ACC = "0xAAAA000000000000000000000000000000000001"; M1.add("addr 0xe1", ACC); M1.add("addr 0xe1", ACC); M1.add("other", ACC);
  t("1125 F-2: notes with a deposit address persist across a reload, are not duplicated, and are listed together", mk(N1).fastNotes.read(ACC).map(x => x.t).join("|") === "addr 0xe1|other");
  M1.drop(M1.read(ACC).map(x => x.id), ACC); t("1125 F-2: ... until dismissed", mk(N1).fastNotes.read(ACC).length === 0);
  // 1130 L-3: per account, no silent drop at 20, Dismiss removes only what was on screen
  { const N = mkStore(), F = mk(N).fastNotes, B = "0xBBBB000000000000000000000000000000000002";
    F.add("for A", ACC); F.add("for B", B); for (let i = 0; i < 30; i++) F.add("n" + i, ACC);
    t("1130 L-3: notes are scoped to the wallet account (B never sees A's deposit addresses)", F.read(B).map(x => x.t).join() === "for B" && F.read(ACC).every(x => x.t !== "for B"));
    t("1130 L-3: the 21st note no longer drops the oldest (cap is 200)", F.read(ACC).length === 31 && F.read(ACC)[0].t === "for A");
    const shown = F.read(ACC).map(x => x.id); F.add("arrived after the user looked", ACC); F.drop(shown, ACC);
    t("1130 L-3: Dismiss removes only the notes that were shown; one that arrived later stays", F.read(ACC).map(x => x.t).join() === "arrived after the user looked");
    N.setItem("stealth-fast-notes", JSON.stringify(["old plain note"])); t("1130 L-3: an old string-array store is still read (shown to every account until dismissed)", mk(N).fastNotes.read(B).map(x => x.t).join() === "old plain note"); }
  t("1125 F-2: only UNKNOWN/FAILED parts with a deposit address need a note", A.fastNeedsNote(recOf("UNKNOWN")) && A.fastNeedsNote(recOf("FAILED")) && A.fastNeedsNote(recOf("STUCK")) && !A.fastNeedsNote(recOf("SUCCESS")) && !A.fastNeedsNote(recOf("NOT_SENT")));
  const rsrc = src.slice(src.indexOf("async function resumeFast"), src.indexOf("// ---- unfinished hops"));
  t("1125 F-2: resumeFast lists every summary (no overwrite of box.textContent per record), keeps address notes, dismiss button exists", /fastNotes\.add\(text, acct\); \} else extra\.push\(text\)/.test(rsrc) && !/box\.textContent = "Earlier private withdraw \("/.test(rsrc) && /showFastBox\(extra\)/.test(rsrc) && /id="btn-fast-dismiss"/.test(fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8")));
  // 1130 L-1: one key per address, storage failure surfaced, start refused when the record cannot persist
  { const L = mkStore(), X = mk(L), S2 = "0x" + "cd".repeat(20);
    X.fastRecs.put({ ...recOf("PLANNED"), stealth: S }); X.fastRecs.put({ ...recOf("PLANNED"), stealth: S2 });
    t("1130 L-1: each address has its own storage key, so a write for one never rewrites the other (no shared map)", L.getItem("stealth-fast-wd:" + S) && L.getItem("stealth-fast-wd:" + S2) && L.getItem("stealth-fast-wd") == null && Object.keys(X.fastRecs.read()).length === 2);
    const before = L.getItem("stealth-fast-wd:" + S2); X.fastRecs.put({ ...recOf("DEPOSITED"), stealth: S }); t("1130 L-1: ... a put for A leaves B's stored bytes untouched", L.getItem("stealth-fast-wd:" + S2) === before);
    L.setItem("stealth-fast-wd", JSON.stringify({ ["0x" + "11".repeat(20)]: { ...recOf("PLANNED"), stealth: "0x" + "11".repeat(20) } })); const mig = X.fastRecs.read();
    t("1130 L-1: an old single-map record is migrated to its own key and the old key removed", mig["0x" + "11".repeat(20)] && L.getItem("stealth-fast-wd:" + "0x" + "11".repeat(20)) && L.getItem("stealth-fast-wd") == null);
    const bad = mkStore(); bad.setItem = () => { throw new Error("QuotaExceededError"); }; const Y = mk(bad); let e1 = null; try { Y.fastClaim(recOf("PLANNED", { stealth: S })); } catch (e) { e1 = e.message; }
    t("1130 L-1: when the record cannot be stored the withdraw is refused with a clear message (nothing is sent)", /Could not save the withdraw record/.test(e1 || "") && /QuotaExceeded/.test(e1 || "") && Object.keys(Y.fastRecs.read()).length === 0);
    const silent = mkStore(); silent.setItem = () => {}; let e2 = null; try { mk(silent).fastClaim(recOf("PLANNED")); } catch (e) { e2 = e.message; }
    t("1130 L-1: storage that swallows writes silently is caught by the read-back", /nothing was sent/.test(e2 || "")); }
  { const src3 = src.slice(src.indexOf("async function fastWithdraw"), src.indexOf("async function resumeFast"));
    t("1130 L-1: the in-run save surfaces a storage failure (no empty catch)", /const save = r => \{ try \{ fastRecs\.put\(r\); \} catch \(e\) \{ say\("pay-hint"/.test(src3)); }
  // 1130 M-2: abandon + STUCK are not open
  { const r = { parts: [{ amount: "1", state: "DEPOSITED", depositAddress: "0xd" }, { amount: "1", state: "SIGNED", depositAddress: "0xs" }, { amount: "1", state: "PLANNED" }, { amount: "1", state: "SUCCESS" }] };
    t("1130 M-2: STUCK is not in FAST_OPEN (a parked part no longer blocks later fast withdraws)", !PWm.FAST_OPEN.has("STUCK") && PWm.fastDone({ parts: [{ state: "STUCK" }]}) && !PWm.fastOpenRec({ parts: [{ state: "STUCK" }] }));
    PWm.abandonRec(r); t("1130 M-2: abandon parks DEPOSITED as STUCK (deposit address kept), SIGNED as UNKNOWN, PLANNED as NOT_SENT, leaves SUCCESS", r.parts.map(p => p.state).join() === "STUCK,UNKNOWN,NOT_SENT,SUCCESS" && r.parts[0].depositAddress === "0xd" && PWm.fastDone(r) && /deposit address 0xd/.test(PWm.fastSummary(r)[0])); }
  { const appSrc = src.slice(src.indexOf("$(\"btn-fast-abandon\")"), src.indexOf("// ---- unfinished hops"));
    t("1130 M-2: an explicit 'Abandon this record' button exists, asks first, skips records another tab runs, and keeps the deposit address in a note", /id="btn-fast-abandon"/.test(fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8")) && /confirm\(/.test(appSrc) && /ifAvailable: true/.test(appSrc) && /PW\.abandonRec/.test(appSrc) && /fastNotes\.add\(/.test(appSrc)); }
  // 1130 L-2: the log window follows validBefore
  { const nowS = 1_800_000_000, vb = nowS + 3600;
    t("1130 L-2: logSpanSince: a fresh authorization needs at least 5000 blocks, an old one more, capped", CR.logSpanSince(vb, nowS) >= 5000 && CR.logSpanSince(vb, nowS) < CR.logSpanSince(vb, nowS + 3 * 3600) && CR.logSpanSince(vb, nowS + 100 * 3600) === 200000 && CR.logSpanSince(vb, nowS - 999) === 5000);
    const asked = []; const rpcF = async (m, p) => { if (m === "eth_blockNumber") return "0x" + (1_000_000).toString(16); asked.push(Number(BigInt(p[0].fromBlock))); if (asked.length === 1) throw new Error("range too large"); return []; };
    await CR.recentLogs(rpcF, { address: "0x" + "11".repeat(20), topics: [], span: 150000 });
    t("1130 L-2: a node that refuses the wide window still gets the 5000-block one", asked.length === 2 && asked[0] === 850000 && asked[1] === 995000);
    t("1130 L-2: both call sites pass the window derived from validBefore", (src.match(/span: logSpanSince\(/g) || []).length === 2); }
  // F-3
  const ro = PWm.relayOutcome;
  { const appSrc = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), sa = appSrc.slice(appSrc.indexOf("function setAcct("), appSrc.indexOf("async function connect("));
    t("1132 M-1: setAcct() ends with a guarded showFastBox() (cannot throw, needs the DOM box) so per-account notes appear after connecting", /try \{ if \(\$\("fast-resume"\)\) \{ showFastBox\(\);/.test(sa) && /\} catch \{\}/.test(sa) && !/typeof showFastBox/.test(sa));
    t("1132 I-1: the stats handler computes payFee and payBpsNow into locals first and assigns both together", /const f = BigInt\(s\.pay_fee\), b = payBps\(s\); payFee = f; payBpsNow = b;/.test(appSrc) && !/payFee = BigInt\(s\.pay_fee\); payBpsNow/.test(appSrc)); }
  t("1130 M-1: relayOutcome: only a 400 with the explicit definite:true is a definite refusal; plain 400 / 403 / 429 / 500 / no-JSON are in progress; 'already used', d.used, ok unchanged", ro({ ok: false, status: 400 }, { error: "x", definite: true }).definite === true && ro({ ok: false, status: 400 }, { error: "x" }).definite === false
    && ro({ ok: false, status: 429 }, { error: "x", definite: true }).definite === false && ro({ ok: false, status: 403 }, { error: "x" }).definite === false && ro({ ok: false, status: 400 }, { error: "a previous attempt for this authorization is still being confirmed" }).definite === false
    && ro({ ok: false, status: 400 }, { error: "a withdrawal from this address is already in progress" }).definite === false
    && ro({ ok: false, status: 500 }, { error: "x" }).definite === false && ro({ ok: false, status: 400 }, { error: "Authorization already used" }).kind === "used" && ro({ ok: true, status: 202 }, { used: true }).kind === "used" && ro({ ok: true, status: 200 }, { hash: "0x1" }).kind === "ok" && ro({ ok: false, status: 400 }, {}).definite === false);
  // F-4 / F-6
  t("1125 F-4: the per-address guard stays armed between parts (cleared on the last part, on a definite refusal, or when nothing is left signed)", /onDeposited: info => \{ if \(info\.index === rec\.parts\.length - 1\) pendingWd\.delete\(k\)/.test(src2) && /onRefused: \(\) => pendingWd\.delete\(k\)/.test(src2));
  t("1125 F-6: a record whose lock another tab holds is not reported as 'earlier'", /let ran = false;/.test(rsrc) && /if \(!ran\) continue;/.test(rsrc)); }
// ---- configurable fees (owner decision: OFF by default, can be removed or changed). Golden strings below were produced by the code BEFORE the fee fields existed.
{ const H = await import("../web/zec-hop.js"), CH = await import("../web/chains.js"), PA = await import("../web/pay-auth.js"), RU = await import("./relay-util.mjs");
  const A = "0x" + "11".repeat(20), B = "0x" + "22".repeat(20), T = "t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ";
  const GOLD = ['{"dry":true,"swapType":"EXACT_INPUT","slippageTolerance":100,"originAsset":"nep141:hood-0x5fc5360d0400a0fd4f2af552add042d716f1d168.omft.near","depositType":"ORIGIN_CHAIN","destinationAsset":"nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near","amount":"5000000","refundTo":"0x2222222222222222222222222222222222222222","refundType":"ORIGIN_CHAIN","recipient":"0x1111111111111111111111111111111111111111","recipientType":"DESTINATION_CHAIN","deadline":"1970-01-01T01:00:00.000Z","confidentiality":"public"}',
    '{"dry":true,"swapType":"EXACT_INPUT","slippageTolerance":100,"originAsset":"nep141:hood-0x5fc5360d0400a0fd4f2af552add042d716f1d168.omft.near","depositType":"ORIGIN_CHAIN","destinationAsset":"nep141:zec.omft.near","amount":"5000000","refundTo":"0x2222222222222222222222222222222222222222","refundType":"ORIGIN_CHAIN","recipient":"t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ","recipientType":"DESTINATION_CHAIN","deadline":"1970-01-01T01:00:00.000Z","confidentiality":"public"}',
    '{"dry":true,"swapType":"EXACT_INPUT","slippageTolerance":100,"originAsset":"nep141:zec.omft.near","depositType":"ORIGIN_CHAIN","destinationAsset":"nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near","amount":"300000","refundTo":"t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ","refundType":"ORIGIN_CHAIN","recipient":"0x1111111111111111111111111111111111111111","recipientType":"DESTINATION_CHAIN","deadline":"1970-01-01T01:00:00.000Z","confidentiality":"public"}'];
  const reqs = (extra = {}) => [buildQuoteRequest({ from: CHAINS.rh, to: CHAINS.base, amount: 5000000n, recipient: A, refundTo: B, dry: true, now: 0, ...extra }),
    H.reqIn({ chain: CHAINS.rh, amount: 5000000n, tAddr: T, stealth: B, dry: true, now: 0, rand: () => 0.5, ...extra }), H.reqOut({ dest: CHAINS.base, amount: 300000n, recipient: A, refundT: T, dry: true, now: 0, rand: () => 0.5 })];
  t("fees OFF by default: privateFee is {0, ''} and appFeesOf gives nothing", CH.privateFee.appFeeBps === 0 && CH.privateFee.appFeeRecipient === "" && CH.appFeesOf() === null);
  t("fees OFF: the direct quote request, the first leg and the second leg are byte-identical to the pre-fee code", reqs().map(r => JSON.stringify(r)).every((x, i) => x === GOLD[i]) && reqs().every(r => !("appFees" in r)));
  t("fees: only ONE of the two values set (bps without recipient, recipient without bps) adds nothing", CH.appFeesOf({ appFeeBps: 30, appFeeRecipient: "" }) === null && CH.appFeesOf({ appFeeBps: 0, appFeeRecipient: "fees.near" }) === null
    && reqs({ fees: { appFeeBps: 30, appFeeRecipient: "" } }).map(r => JSON.stringify(r)).every((x, i) => x === GOLD[i]));
  const ON = { appFeeBps: 30, appFeeRecipient: "fees.near" };
  t("fees ON (30 bps, a NEAR account): appFees is [{recipient, fee: 30}] (1Click: basis points)", JSON.stringify(CH.appFeesOf(ON)) === JSON.stringify([{ recipient: "fees.near", fee: 30 }]));
  { const on = reqs({ fees: ON });
    t("fees ON: the direct request and the FIRST leg get appFees as the last field, everything else unchanged; the SECOND leg never gets it",
      JSON.stringify(on[0]) === GOLD[0].slice(0, -1) + ',"appFees":[{"recipient":"fees.near","fee":30}]}' && JSON.stringify(on[1]) === GOLD[1].slice(0, -1) + ',"appFees":[{"recipient":"fees.near","fee":30}]}' && JSON.stringify(on[2]) === GOLD[2]);
    const out2 = H.reqOut({ dest: CHAINS.base, amount: 300000n, recipient: A, refundT: T, dry: true, now: 0, rand: () => 0.2 }), sh = H.sharedFields(on[1], out2);   // a different jitter, as in a real hop
    t("fees ON: the two hop legs still share nothing but protocol constants (appFees is on one leg only)", sh.every(x => H.CONSTANT_FIELDS.has(x.split("=")[0])) && !sh.some(x => /appFees/.test(x))); }
  { const keep = { ...CH.privateFee }; Object.assign(CH.privateFee, ON); const on = reqs(); Object.assign(CH.privateFee, keep);
    t("fees ON through the config object itself (the one place to edit): same result as passing it; switching back restores the old bytes", "appFees" in on[0] && "appFees" in on[1] && !("appFees" in on[2]) && reqs().map(r => JSON.stringify(r)).every((x, i) => x === GOLD[i])); }
  t("fees: a bad rate or account is refused loudly, never sent (1.5 bps, 0 handled as off, 2000 bps, negative, upper-case/space account)", [1.5, 2000, -5].every(b => throws(() => CH.appFeesOf({ appFeeBps: b, appFeeRecipient: "fees.near" }))) && throws(() => CH.appFeesOf({ appFeeBps: 30, appFeeRecipient: "Fees Near" })) && CH.appFeesOf({ appFeeBps: 0, appFeeRecipient: "fees.near" }) === null);
  // pay fee: flat fee unchanged; percentage fee = max(flat, ceil(bps)) with the page and the relayer on the same formula
  const U6 = 1_000_000n, flat = 50000n, dec = 6;
  t("pay fee, bps 0 (default): exactly the old numbers (you pay 10 -> get 9.95; receiver gets 10 -> pay 10.05)", JSON.stringify(PA.payAmounts({ src: "amount", text: "10", decimals: dec, fee: flat }), (k, v) => typeof v === "bigint" ? v.toString() : v) === '{"send":"10000000","get":"9950000","fee":"50000"}'
    && PA.payAmounts({ src: "amount-get", text: "10", decimals: dec, fee: flat }).send === 10_050_000n && PA.payAmounts({ src: "amount", text: "10", decimals: dec, fee: flat, bps: 0 }).fee === flat);
  { const a = x => PA.payAmounts({ src: "amount", text: x, decimals: dec, fee: flat, bps: 10 }), g = x => PA.payAmounts({ src: "amount-get", text: x, decimals: dec, fee: flat, bps: 10 });
    t("pay fee 0.10% with a 0.05 minimum: $10 -> fee 0.05 (minimum wins), $100 -> 0.10, $10 000 -> 10.00", a("10").fee === 50000n && a("100").fee === 100000n && a("10000").fee === 10_000_000n && a("100").get === 99_900_000n);
    t("pay fee 0.10%: 'receiver gets' is exact on both sides of the minimum crossover (send - fee(send) == get for 300 amounts)", Array.from({ length: 300 }, (_, i) => String(1 + i * 3.37)).every(x => { const r = g(x); return r && r.send - PA.payFeeFor(r.send, flat, 10) === r.get && r.fee === PA.payFeeFor(r.send, flat, 10); })); }
  t("pay fee: page and relayer use the same formula (flat/ceil), bps 0/10/100 over 3000 amounts", [0, 10, 100].every(b => Array.from({ length: 3000 }, (_, i) => BigInt(i * 7919 + 1)).every(x => RU.payFeeFor(x, flat, b) === PA.payFeeFor(x, flat, b))) && RU.payFeeFor(1_234_567n, flat, 100) === 50000n && RU.payFeeFor(10n * U6, flat, 100) === 100000n && RU.payFeeFor(10n * U6 + 1n, flat, 100) === 100001n);
  t("pay fee cap: default unchanged (above 1.00 refused); with a percentage allowance a 0.10% fee on $10 000 passes, 2% never does, and half-of-payment still applies", !PA.feeWithinCap(10_000_000n, 10_000n * U6) && PA.feeWithinCap(10_000_000n, 10_000n * U6, 1_000_000n, 100) && !PA.feeWithinCap(200n * U6, 10_000n * U6, 1_000_000n, 100) && !PA.feeWithinCap(60000n, 100000n, 1_000_000n, 100)); }
// 1133 (round 6): lost-record recovery guards
{ const HP = await import("../web/zec-hop.js"), T = 3_500_000, o = (x, e = {}) => [{ n: 0, account: 0, index: 0, value: 1n, height: x, latest: x, pending: false, ...e }];
  t("1133 M-1: a lost-record finding younger than LOST_MIN_AGE (100 blocks) is young; unconfirmed or unknown tip is young too", HP.LOST_MIN_AGE === 100 && HP.lostYoung(o(T - 99), T) && !HP.lostYoung(o(T - 100), T) && HP.lostYoung(o(0, { pending: true }), T) && HP.lostYoung(o(T - 999), undefined));
  t("1133 M-2: store.add refuses an existing key (code EXISTS) and leaves the old record", await (async () => { const m = HP.memStore(); await m.add("k", { v: 1 }); const e = await m.add("k", { v: 2 }).then(() => null, x => x.code); return e === "EXISTS" && (await m.get("k")).v === 1; })());
  t("1133 L-2: the wallets scanned are below the prior hop count, skip only local records, and never more than LOST_MAX_N", JSON.stringify(HP.lostRange(7, [2]).ns) === "[0,1,3,4,5,6]" && HP.lostRange(1e9, []).ns.length === HP.LOST_MAX_N && HP.lostRange(1e9, []).capped && HP.lostRange(0, []).ns.length === 0);
  t("1133 L-4: Continue needs all ZEC on one account at index 0", HP.lostContinueAcct(o(0).concat(o(0))) === 0 && HP.lostContinueAcct([{ account: 0, index: 0 }, { account: 1, index: 0 }]) === null);
  t("1133 I-4: the birthday anchor is the earliest announcement of the address", HP.firstBlock([{ stealth: "0xAB", block: 9 }, { stealth: "0xab", block: 4 }, { stealth: "0xcd", block: 1 }], "0xaB") === 4); }
// 1135 / 1136 (round 7): recovery flow
{ const RUm = await import("./relay-util.mjs"), named = (name, extra = {}) => Object.assign(new Error(name), { name, ...extra });
  const up = e => RUm.classifyError(e) instanceof RUm.Upstream;
  t("1135 L-1: classifyError turns a plain HTTP 429 (also nested in viem wrappers) into Upstream, so the pub reads never charge the signer; 403 / 413 stay costly; 5xx unchanged", up(named("HttpRequestError", { status: 429 })) && up(Object.assign(new Error("x"), { cause: named("HttpRequestError", { status: 429 }) })) && up(named("X", { status: 429 }))
    && !up(named("HttpRequestError", { status: 403 })) && !up(named("HttpRequestError", { status: 413 })) && up(named("HttpRequestError", { status: 503 })) && RUm.classifyError(named("HttpRequestError", { status: 403 })).unknown === true);
  const rsrc = fs.readFileSync(new URL("./relayer.mjs", import.meta.url), "utf8");
  t("1135 L-1: nodeCall has no dead '!isTransport(last)' clause, and isTransport no longer special-cases 429 (classifyError does)", !/!isTransport\(last\)/.test(rsrc) && !/x\.status === 429/.test(rsrc.slice(rsrc.indexOf("const isTransport"), rsrc.indexOf("export const nodeCall"))));
  const ro = PWm.relayOutcome, cfg = m => ro({ ok: false, status: 400 }, { error: m });
  t("1135 L-2: a 400 that names a relayer setting is config (never definite, so the guard stays); a 'still being confirmed' 400, a definite one, a 403 and a 429 are not", ["fee authorization required", "below the minimum of $0.10", "fees are not enabled", "fee below the minimum"].every(m => cfg(m).config === true && cfg(m).definite === false)
    && cfg("a previous attempt for this authorization is still being confirmed").config === false && ro({ ok: false, status: 400 }, { error: "fee authorization required", definite: true }).config === false && ro({ ok: false, status: 403 }, { error: "fee authorization required" }).config === false && ro({ ok: false, status: 429 }, { error: "below the minimum" }).config === false);
  const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), pw = fs.readFileSync(new URL("../web/private-withdraw.js", import.meta.url), "utf8");
  t("1135 L-2: both routes show the true reason with CONFIG_NOTE, the fast route points at Abandon, and no guard is cleared on a config refusal (only o.definite does)", /ans\.message \+ \(ans\.config \? PW\.CONFIG_NOTE/.test(app) && /e\.config \? PW\.CONFIG_NOTE \+ " Use Abandon below/.test(app) && /if \(o\.config\) e\.config = true/.test(pw) && !/o\.config\)[^;]*onRefused/.test(pw) && /finally \{ fastBusy\.delete\(k\); showFastBox\(\)/.test(app));
  // L-3 / L-4: the fast box and its notes, run on the page's own code with a fake DOM
  const code = app.slice(app.indexOf("const FAST_KEY"), app.indexOf("async function fastWithdraw")), ls = (() => { const st = {}; return { getItem: k => st[k] ?? null, setItem: (k, v) => { st[k] = v; }, removeItem: k => { delete st[k]; }, raw: st }; })(), els = {};
  const $d = id => els[id] || (els[id] = { textContent: "", hidden: true }), P = new Function("localStorage", "PW", "$", "let acct = null;" + code + "; return { fastNotes, showFastBox, setAcct: a => { acct = a; }, setLive: x => { fastLive = x; }, extra: () => fastExtra, dismiss: () => { fastNotes.drop(shownNotes, acct); fastExtra = []; showFastBox(); } };")(ls, PWm, $d);
  const ACC = "0xAAAA000000000000000000000000000000000001", ACC2 = "0xBBBB000000000000000000000000000000000002";
  P.setAcct(null); P.showFastBox(["Done: 3.00 sent"]); P.setAcct(ACC); P.showFastBox(); P.showFastBox();
  t("1135 L-3: a one-time summary (no note needed) is re-drawn by every later showFastBox() (e.g. from setAcct) until dismissed, and is not duplicated", $d("fast-resume").textContent === "Done: 3.00 sent" && $d("btn-fast-dismiss").hidden === false);
  P.setLive("Earlier private withdraw: waiting 12 s"); P.showFastBox(); const live = $d("fast-resume").textContent; P.setLive(""); P.showFastBox();
  t("1135 L-3: the progress text of a running resume is kept in front by a redraw, not overwritten, and goes when the run ends", /^Earlier private withdraw: waiting 12 s\n\nDone: 3.00 sent$/.test(live) && $d("fast-resume").textContent === "Done: 3.00 sent");
  P.dismiss(); t("1135 L-3: Dismiss clears the transient lines too", $d("fast-resume").hidden === true && P.extra().length === 0);
  t("1135 L-4: a note without a known owning account is refused (nothing is written under the shared bucket); with one it is stored for that account only", P.fastNotes.add("deposit 0xe1", null) === false && P.fastNotes.add("deposit 0xe1", "") === false && !ls.raw["stealth-fast-notes"] && P.fastNotes.add("deposit 0xe1", ACC) === true && P.fastNotes.read(ACC2).length === 0 && P.fastNotes.read(ACC).length === 1);
  ls.raw["stealth-fast-notes"] = JSON.stringify({ "": [{ id: "x", t: "legacy" }] });
  t("1135 L-4: what older builds left in the shared bucket is still readable (a deposit address must not vanish), is never added to, and Dismiss removes it", P.fastNotes.read(ACC2).map(x => x.t).join() === "legacy" && (P.fastNotes.add("n2", ACC), JSON.parse(ls.raw["stealth-fast-notes"])[""].length === 1) && (P.fastNotes.drop(["x"], ACC2), !JSON.parse(ls.raw["stealth-fast-notes"])[""]));
  const rf = app.slice(app.indexOf("async function resumeFast"), app.indexOf("// ---- unfinished hops")), fw = app.slice(app.indexOf("async function fastWithdraw"), app.indexOf("async function resumeFast"));
  t("1135 L-4: resumeFast without an account keeps the record (no note, no delete) and follows it again when setAcct gets one; a withdraw's notes belong to the account that started it; Abandon needs an account", /if \(!acct\) \{ extra\.push\(text\); fastDeferred = true; continue; \}/.test(rf) && /fastDeferred\) \{ fastDeferred = false; resumeFast\(\)/.test(app) && /const owner = acct/.test(fw) && !/, acct\)/.test(fw) && /if \(!acct\) \{ say\("pay-hint", "Connect your wallet first/.test(app));
}
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  t("the private route preview warns when the fee is above the loss cap, and the confirmation comes before the payout", /Number\(fee\) \/ Number\(value\) > HM\.MAX_LOSS/.test(app) && /Private fast is cheaper below that/.test(app)); }
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), blk = app.slice(app.indexOf("// LOSTDONE-BEGIN"), app.indexOf("// LOSTDONE-END")), L = new Function(blk + "; return { lostDone, lostSay };")();
  const fin = app.slice(app.indexOf("async function finishSweep"), app.indexOf("// A transfer from the first version"));
  L.lostSay("0xabc", "Done: \u2248 5.69 USDG sent to your wallet.", true);
  t("lost Return: the result is kept in lostDone under the address, apart from the lost card (lostForget does not touch it)", L.lostDone.get("0xabc").text.startsWith("Done: \u2248 5.69") && L.lostDone.get("0xabc").ok === true && !/lostDone/.test(app.slice(app.indexOf("const lostForget"), app.indexOf("const zecText"))));
  t("lost Return: finishSweep stores the final text (SUCCESS or a non-SUCCESS swap status) BEFORE the card is forgotten and the rescan runs", fin.indexOf("lostSay(h.lost, doneText") > 0 && fin.indexOf("lostSay(h.lost, doneText") < fin.indexOf("lostForget(h.lost)") && /Swap ended as " \+ fin\.status/.test(fin));
  t("lost Return: every renderHops draws the kept results with a Dismiss that removes only that one; the box stays visible for them", /for \(const \[k, d\] of lostDone\)[^\n]*lostDone\.delete\(k\)/.test(app) && /box\.hidden = !hops\.size && !lost\.size && !lostDone\.size/.test(app));
  t("lost Return: only the user's Scan clears the results (not checkLost / the background rescan after a Return)", /async function scan\(\) \{[^\n]*\n[^\n]*\n\s*if \(lostDone\.size\) \{ lostDone\.clear\(\)/.test(app) && (app.match(/lostDone\.clear\(\)/g) || []).length === 1);
}
console.log(fail ? "FAILED " + fail : "all passed"); process.exit(fail ? 1 : 0);
