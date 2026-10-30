/* Unit tests of the audit hardening that need neither anvil nor forge. Run: node test_web_units.mjs */
import { unhex, hex, checkAnnouncement, decodeMetadata, keysFromSignature, signKeyRequestWith, addressFromPriv, metaAddress } from "../web/stealth-crypto.js";
import { paymentNonce, feeWithinCap } from "../web/pay-auth.js";
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
  t("1103 L-1: the sweep is recorded BEFORE it is broadcast, and an earlier one that is on the network is resumed, not rebuilt", src.indexOf("const intent =") > 0 && src.indexOf("const intent =") < src.indexOf("await ZR.sendAndConfirm") && /ZR\.txKnown\(ZC\.lightwalletd, prev\.txid\)/.test(src));
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
  t("1109 L-1: it is cleared only on the relayer's own JSON refusal, a revert or success (not on an unknown outcome)", /if \(d\.error && \[400, 403, 429\]\.includes\(r\.status\)\) pendingWd\.delete/.test(wdSrc) && (wdSrc.match(/pendingWd\.delete/g) || []).length === 3 && !/Date\.now\(\) \+ 600_000/.test(src));
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
  t("1110 L-2: no second sweep before the first one's expiry height has passed (the intent stores it)", /expiry: sw\.expiry/.test(rz) && /tipNow <= until/.test(rz) && /!prev\.ended/.test(rz)); }

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
    /usedErr = !!d\.error && \/authorization already used\/i/.test(wdSrc) && /if \(!usedErr && \(!r\.ok \|\| d\.error\)\)/.test(wdSrc) && /if \(d\.used \|\| usedErr\) d\.hash = await txOfLogs/.test(wdSrc) && !/if \(d\.error\) pendingWd\.delete/.test(wdSrc));
  const rp = fs.readFileSync(new URL("../web/relay-post.js", import.meta.url), "utf8");
  t("1121 I-2: a busy/503 final message no longer says 'Nothing was sent'", !/Nothing was sent/.test(rp) && /may be out/.test(rp));
  t("1122 L-3: a SUCCESS return hides the card only after a hopSummary shows nothing left (shielded included)", /left && !left\.some\(x => x\.transparent \+ x\.orchard > 0n\)\) await hideHop/.test(src)); }
  t("fast route: an UNKNOWN part keeps the pendingWd guard after a reload", /if \(!rec\.parts\.some\(p => p\.state === "UNKNOWN"\)\) pendingWd\.delete\(k\)/.test(fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8")));
console.log(fail ? "FAILED " + fail : "all passed"); process.exit(fail ? 1 : 0);
