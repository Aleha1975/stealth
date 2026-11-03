/* Unit tests of the audit hardening that need neither anvil nor forge. Run: node test_web_units.mjs */
import { keccak, unhex, hex, checkAnnouncement, decodeMetadata, keysFromSignature, signKeyRequestWith, addressFromPriv, metaAddress } from "../web/stealth-crypto.js";
import { paymentNonce, feeWithinCap } from "../web/pay-auth.js";
import * as PWm from "../web/private-withdraw.js";
import { requestQuote, buildQuoteRequest } from "../web/private-withdraw.js";
import { CHAINS, assetOf, assetKey, fmtUnits, addChainParams } from "../web/chains.js";
import { cleanLog, ipKey, parseEnvLine } from "./relay-util.mjs";
import { makeScreen } from "./sanctions/screen.mjs";
import { postRelay } from "../web/relay-post.js";
import { parseMeta, deriveForPayment } from "../web/stealth-crypto.js";
import { secp256k1 as secp } from "../web/vendor/noble.js";
import * as CR from "../web/chain-read.js";
import { hopView } from "../web/hop-card.js";
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
  t("1101 I-2: key derivation and scan are single-flight; a scan works on its own list and keys", /\$\("btn-keys"\)\.addEventListener\("click", once\(/.test(src) && /\$\("btn-scan"\)\.addEventListener\("click", once\(/.test(src) && /const K = keys, A = acct, mine = \[\]/.test(src) && /if \(keys !== K\) return;/.test(src));
  t("1101 L-1/L-2: the withdraw receipt must carry the request's nonce; a confirmation timeout says 'do not send again' and arms a pending guard", /hasAuthUsed\(x, \{ token: USDC, authorizer: w\.stealth, nonce \}\)/.test(src) && /not confirmed yet \(tx/.test(src) && /pendingWd\.set/.test(src) && /AUTH_USED_TOPIC, "0x" \+ padAddr\(w\.stealth\), nonce/.test(src));
  t("1105 L-4: every hop-record writer outside the machine takes the machine's Web Lock", (src.match(/underHopLock\(/g) || []).length >= 5);
  t("1103 L-1: the sweep is recorded BEFORE it is broadcast (runSweep), and an earlier one that is on the network is resumed, not rebuilt", (() => { const z = fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8"), r = z.slice(z.indexOf("export async function runSweep")); return r.indexOf("d.set(intent)") > 0 && r.indexOf("d.set(intent)") < r.indexOf("await send()") && /resolvePrevIntent/.test(r) && /follow/.test(r) && /sendAndConfirm\(ZC\.lightwalletd/.test(src); })());
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
  t("1109 I-5: a failed re-read always marks the row unread", /if \(!x\) \{ f\.usdc = null; f\.eth = null; unread\+\+; continue; \}/.test(src));
  t("1109 I-6: hopCtx defines authUsed once; the stale wallet-RPC comment is gone", (src.slice(src.indexOf("const hopCtx"), src.indexOf("const rpcOne")).match(/authUsed:/g) || []).length === 1 && !/go through the connected wallet's own RPC/.test(src));
  const html = fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8");
  t("1109 I-7: the CSP keeps blob: and says why", /script-src 'self' blob:/.test(html) && /I-7: script-src\/worker-src blob: is deliberate/.test(html));
  // 1110 L-1 / L-2 (returnZec lives in app.js: checked on its text, like the other sweep guards)
  const rz = src.slice(src.indexOf("async function returnZec"), src.indexOf("async function staleV1"));
  t("1110 L-1: an unresolved sweep intent is followed in the empty branch BEFORE any empty observation, and an ended one only pauses it", rz.indexOf("const sp = await prevOf()") > 0 && rz.indexOf("const sp = await prevOf()") < rz.indexOf("noteEmptyFor(HM, h, true)") && /if \(!sp\.ended\) return await finishSweep/.test(rz) && /status/.test(src));
  t("1110 L-2: no second sweep before the first one's expiry height has passed (the intent stores it)", /expiry: sw\.expiry/.test(rz) && /tipNow <= until/.test(fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8")) && /!prev\.ended|!c\.ended|!d\.prevOk\(prev\)|prevOk\(prev\) && !prev\.ended/.test(fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8")));
  // 1137 M-1 / L-1 / L-2
  const lk = rz.slice(rz.indexOf("const saved = await underHopLock"), rz.indexOf("if (!saved)")), fs_ = src.slice(src.indexOf("async function finishSweep"), src.indexOf("async function staleV1"));
  t("1138 M-1: runSweep re-reads the intent inside the lock; only a different intent the pre-check did not see refuses; no 6 h gate", (() => { const z = fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8"); return /d\.get\(\)/.test(z) && /cur\.txid !== intent\.txid && !\(expire && cur\.txid === expire\.txid\)\) return "busy"/.test(z) && !/6 \* 3600_000/.test(rz) && !/6 \* 3600_000/.test(z) && /saved === "busy"/.test(z); })());
  t("1138 L-1: only e.definite === true marks the intent not-sent (no message regex at either call site); a not-sent intent is not followed", (() => { const z = fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8"); return /known === false\) d\.set\(\{ \.\.\.intent, ended: "NOT_SENT", notSent: true/.test(z) && /if \(e && e\.definite === true\) throw e/.test(z) && !/Rejected by network\|different txid/.test(z + src) && /prevOk\(sp\) && !sp\.notSent/.test(rz); })());
  t("1137 L-1: every end (SUCCESS too) settles the intent (settleIntent: ended + endedAt) before the Done text; an ended SUCCESS is not reported as a refund on its way", fs_.indexOf("settleIntent({") > 0 && fs_.indexOf("settleIntent({") < fs_.indexOf('"Done: ') && /settle: status => ZR\.settleIntent/.test(fs_) && /ended: status, endedAt/.test(fs.readFileSync(new URL("../web/zec-return.js", import.meta.url), "utf8")) && /sp\.ended !== "SUCCESS" && sp\.ended !== "UNTRACKED" && Date\.now\(\) - \(sp\.endedAt/.test(rz));
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
  t("the private route preview: pressing Confirm is the approval (approvedLoss passed to the hop), the text says so and promises neither a confirmation nor a fixed amount", /approvedLoss: pv\.loss/.test(app) && /pv = \{ key, loss \}/.test(app) && /Pressing Confirm private transfer accepts this total cost/.test(app) && /loss > HM\.MAX_LOSS/.test(app) && !/about 50 /.test(app) && !/You will be asked to confirm before the payout/.test(app) && /usually cheaper from a few tens/.test(app) && /interactive: true/.test(app)); }
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), blk = app.slice(app.indexOf("// LOSTDONE-BEGIN"), app.indexOf("// LOSTDONE-END")), L = new Function(blk + "; return { lostDone, lostSay };")();
  const fin = app.slice(app.indexOf("async function finishSweep"), app.indexOf("// A transfer from the first version"));
  L.lostSay("0xabc", "Done: \u2248 5.69 USDG sent to your wallet.", true);
  t("lost Return: the result is kept in lostDone under the address, apart from the lost card (lostForget does not touch it)", L.lostDone.get("0xabc").text.startsWith("Done: \u2248 5.69") && L.lostDone.get("0xabc").ok === true && !/lostDone/.test(app.slice(app.indexOf("const lostForget"), app.indexOf("const zecText"))));
  t("lost Return: finishSweep stores the final text (SUCCESS or a non-SUCCESS swap status) BEFORE the card is forgotten and the rescan runs", fin.indexOf("lostSay(h.lost, doneText") > 0 && fin.indexOf("lostSay(h.lost, doneText") < fin.indexOf("lostForget(h.lost)") && /Swap ended as " \+ fin\.status/.test(fin));
  t("lost Return: every renderHops draws the kept results with a Dismiss that removes only that one; the box stays visible for them", /for \(const \[k, d\] of lostDone\)[^\n]*lostDone\.delete\(k\)/.test(app) && /box\.hidden = !hops\.size && !lost\.size && !lostDone\.size/.test(app));
  t("lost Return: only the user's Scan clears the results (not checkLost / the background rescan after a Return)", /async function scan\(\) \{[^\n]*\n[^\n]*\n\s*if \(lostDone\.size\) \{ lostDone\.clear\(\)/.test(app) && (app.match(/lostDone\.clear\(\)/g) || []).length === 2 && /if \(changed\) \{ keys = null; found = \[\]; try \{ hops\.clear\(\); lost\.clear\(\); lostNone\.clear\(\); lostDone\.clear\(\)/.test(app));
}

// ---- 1138 M-1 behavioural: the sweep intent protocol (zec-return.js runSweep / settleIntent) against fake storage, lock and node
{ const ZRm = await import("../web/zec-return.js"), TXA = "a".repeat(64), TXB = "b".repeat(64), TXC = "c".repeat(64), DEP = "t1" + "3".repeat(33), H6 = 6 * 3600_000 + 60_000;
  const prevOk = p => p && /^[0-9a-f]{64}$/i.test(p.txid || "") && /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(p.deposit || "");
  const world = (init, o = {}) => { const w = { cur: init, sent: [], sets: [], locked: false, ...o };
    w.d = { prevOf: async () => w.cur, prevOk, get: () => w.cur, set: v => { if (w.setFails) return false; w.cur = v; w.sets.push(v); return true; }, lock: async fn => w.locked ? undefined : fn(),
      txKnownFn: async () => { if (w.known instanceof Error) throw w.known; return w.known; }, tipFn: async () => w.tip ?? 3_600_000, midCheck: async () => false, now: () => w.now ?? Date.now(),
      quote: async () => { if (w.during) w.cur = w.during; return { intent: { txid: TXB, deposit: DEP, amountOut: "1", at: Date.now(), expiry: 3_600_040 }, send: async () => { w.sent.push(TXB); if (w.sendErr) throw w.sendErr; } }; } };
    return w; };
  const X = (extra = {}) => ({ txid: TXA, deposit: DEP, amountOut: "1", at: Date.now() - 2 * 3600_000, expiry: 3_600_000, ...extra });
  { const w = world(X(), { known: false, tip: 3_600_500 }); const r = await ZRm.runSweep(w.d);
    t("1138 M-1: unended intent X, past its expiry, tx unknown, Return pressed -> a NEW sweep is broadcast (X ended EXPIRED under the lock)", w.sent.length === 1 && r.intent.txid === TXB && w.sets[0].ended === "EXPIRED" && w.sets[0].txid === TXA && w.cur.txid === TXB && !w.cur.ended); }
  { const w = world(X({ at: Date.now() - H6 }), { known: false, tip: 3_600_500 }); await ZRm.runSweep(w.d);
    t("1138 M-1: the same with an intent older than 6 h (no age gate): swept anew", w.sent.length === 1 && w.sets[0].ended === "EXPIRED"); }
  { const w = world(X({ at: Date.now() - H6 }), { known: true }); const r = await ZRm.runSweep(w.d);
    t("1138 M-1: tab-closed REFUNDED case older than 6 h: its tx is known -> followed (finishSweep settles it), nothing new is sent yet", r.follow && r.follow.txid === TXA && w.sent.length === 0);
    const ok = await ZRm.settleIntent({ lock: w.d.lock, get: w.d.get, set: w.d.set, sw: r.follow, status: "REFUNDED", sleep: async () => {} });
    const r2 = await ZRm.runSweep({ ...w.d, quote: w.d.quote });
    t("1138 M-1: ... after the settle (ended REFUNDED) the next Return sweeps instead of refusing", ok && w.cur.txid === TXB && r2.intent && w.sent.length === 1 && !w.cur.ended); }
  { const w = world(X(), { known: false, tip: 3_600_500, during: { txid: TXC, deposit: DEP, amountOut: "1", at: Date.now(), expiry: 1 } }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 M-1: a DIFFERENT intent that appeared during the quote wait still refuses 'busy', nothing sent", err && /already in progress/.test(err.message) && w.sent.length === 0 && w.cur.txid === TXC); }
  { const w = world(X({ expiry: 3_600_000 }), { known: false, tip: 3_599_000 }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 M-1: before the expiry height a not-known tx may still be mined: no second sweep", err && /may still be mined/.test(err.message) && w.sent.length === 0); }
  { const w = world(X(), { known: new Error("down") }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 M-1: the node cannot answer -> no second sweep, press again", err && /Cannot tell/.test(err.message) && w.sent.length === 0); }
  { const w = world(null, { known: false, sendErr: Object.assign(new Error("Rejected by network: bad"), { definite: true }) }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 L-1: a definite refusal marks the intent NOT_SENT (the node confirms it does not know the tx); the error still propagates", err && w.cur.notSent === true && w.cur.ended === "NOT_SENT"); }
  { const w = world(null, { sendErr: new Error("Rejected by network: txn-already-in-mempool different txid") }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 L-1: an unknown outcome (no typed flag, whatever its text says) leaves the intent LIVE", err && !w.cur.ended && !w.cur.notSent && w.cur.txid === TXB); }
  { const w = world(null, { setFails: true }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 M-1: if the intent cannot be recorded nothing is sent", err && /Could not record/.test(err.message) && w.sent.length === 0); }
  { const w = world(X({ at: Date.now() - 3 * 3600_000 }), { known: false, tip: 3_600_500, setFails: true }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1138 M-1: even if the EXPIRED write fails the pre-check's own intent never blocks (nothing sent only because recording failed)", err && /Could not record/.test(err.message) && !/already in progress/.test(err.message)); }

  // ---- 1139 L-2: missing/spent-inputs answers are UNKNOWN; NOT_SENT only after txKnown says false
  { const def = Object.assign(new Error("Rejected by network: bad"), { definite: true });
    t("1139 L-2: isDefiniteRefusal: -26 (also 64-bit) is definite; -27, -25 (also 64-bit), 'bad-txns-inputs-missingorspent', 'Missing inputs', 'already in mempool' are not", ZRm.isDefiniteRefusal(BigInt.asUintN(64, -26n), "bad-txns") === true && ZRm.isDefiniteRefusal(BigInt.asUintN(64, -27n), "x") === false && ZRm.isDefiniteRefusal(BigInt.asUintN(64, -25n), "x") === false && ZRm.isDefiniteRefusal(1n, "bad-txns-inputs-missingorspent") === false && ZRm.isDefiniteRefusal(1n, "Missing inputs") === false && ZRm.isDefiniteRefusal(1n, "txn-already-in-mempool") === false);
    for (const [name, known] of [["knows it", true], ["cannot be asked", new Error("down")]]) { const w = world(null, { known, sendErr: def }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
      t("1139 L-2: a definite refusal but the node " + name + " -> NOT_SENT is NOT written (intent stays live)", err && !w.cur.ended && !w.cur.notSent && w.cur.txid === TXB); } }
  // ---- 1139 I-2: a margin of blocks beyond the expiry
  { const w = world(X({ expiry: 3_600_000 }), { known: false, tip: 3_600_000 + ZRm.EXPIRY_MARGIN_BLOCKS }); let err = null; await ZRm.runSweep(w.d).catch(e => { err = e; });
    t("1139 I-2: tip at expiry + margin is still 'may be mined' (no second sweep)", ZRm.EXPIRY_MARGIN_BLOCKS >= 3 && err && /may still be mined/.test(err.message) && w.sent.length === 0);
    const w2 = world(X({ expiry: 3_600_000 }), { known: false, tip: 3_600_000 + ZRm.EXPIRY_MARGIN_BLOCKS + 1 }); await ZRm.runSweep(w2.d);
    t("1139 I-2: one block past the margin -> expired, swept anew", w2.sent.length === 1 && w2.sets[0].ended === "EXPIRED"); }
  // ---- 1139 M-1: followSweep (pollStatus not changed)
  { const unreach = new Error("HTTP 502"), sleeps = []; const sleep = async ms => { sleeps.push(ms); };
    { const w = world(X({ at: Date.now() - H6 }), { known: true }); const r = await ZRm.runSweep(w.d); let polls = 0;
      const fin = await ZRm.followSweep({ poll: async () => { polls++; throw unreach; }, txKnownFn: async () => true, sleep, settle: st => ZRm.settleIntent({ lock: w.d.lock, get: w.d.get, set: w.d.set, sw: r.follow, status: st, sleep: async () => {} }) });
      t("1139 M-1: tx known, pollStatus keeps throwing -> after 3 spaced rounds the intent ends UNTRACKED and the user is told (untracked)", fin.untracked === true && fin.status === "UNTRACKED" && polls === 3 && sleeps.length === 2 && w.cur.ended === "UNTRACKED" && fin.settled === true);
      w.known = false; w.tip = 3_600_000;      // the old UTXO "reappears" (refund to the hop address): the next press sweeps, no 'busy', no follow
      const r2 = await ZRm.runSweep(w.d); t("1139 M-1: ... the next Return sweeps a reappearing UTXO (no double-sweep refusal, nothing followed)", !r2.follow && r2.intent && r2.intent.txid === TXB && w.sent.length === 1 && w.cur.txid === TXB && !w.cur.ended); }
    { let polls = 0; const fin = await ZRm.followSweep({ poll: async () => { polls++; if (polls === 1) throw unreach; return { status: "SUCCESS" }; }, txKnownFn: async () => true, sleep, settle: async () => true });
      t("1139 M-1: a single blip (then a good answer) is NOT settled as untracked", fin.status === "SUCCESS" && !fin.untracked && polls === 2); }
    { let settled = 0, err = null; await ZRm.followSweep({ poll: async () => { throw new Error("still not finished after 60 min; check the status later with deposit address t1x"); }, txKnownFn: async () => true, sleep, settle: async () => { settled++; return true; } }).catch(e => { err = e; });
      t("1139 M-1: the 60-minute 'still not finished' timeout (swap running) is rethrown, nothing settled", err && /still not finished/.test(err.message) && settled === 0); }
    for (const [name, k] of [["unreadable", async () => { throw new Error("down"); }], ["unknown to the node", async () => false]]) { let settled = 0, err = null;
      await ZRm.followSweep({ poll: async () => { throw unreach; }, txKnownFn: k, sleep, settle: async () => { settled++; return true; } }).catch(e => { err = e; });
      t("1139 M-1: persistent outage but the tx is " + name + " -> rethrown, not settled", err === unreach && settled === 0); } }
  // ---- 1139 I-1: the preview's fee share and the machine's projectedLoss share one basis
  { const HMm = await import("../web/zec-hop.js");
    for (const [inDec, outDec, value, out] of [[6, 6, 5_000_000n, 4_700_000n], [6, 18, 5_000_000n, 4_700_000_000_000_000_000n], [6, 8, 20_000_000n, 1_890_000_000n]]) {
      const pr = HMm.previewLoss({ value, out, inDec, outDec }), zats = 9_965_000n, rate = Number(out) / Number(zats), full = HMm.projectedLoss({ amountIn: value, inDec, outDec, paidOut: 0, rate, zatsLeft: zats }), naive = Number(value - out) / Number(value);
      t("1139 I-1: preview loss === projectedLoss of one full payout at the same rate (dec " + inDec + "/" + outDec + ")" + (inDec !== outDec ? "; the old (value-out)/value basis differs" : ""), Math.abs(pr - full) < 1e-9 && (inDec === outDec ? Math.abs(naive - pr) < 1e-9 : Math.abs(naive - pr) > 0.5), pr + " " + full + " " + naive); } }
  { // settleIntent: the lock is held by the hop machine for a while -> retried, not skipped
    let n = 0, cur = { txid: TXA }; const sets = [];
    const lock = async fn => (++n <= 3 ? undefined : fn()), get = () => cur, set = v => { cur = v; sets.push(v); return true; };
    const ok = await ZRm.settleIntent({ lock, get, set, sw: { txid: TXA, deposit: DEP }, status: "SUCCESS", sleep: async () => {}, now: () => 7 });
    t("1138 M-1: the settle write is retried while the lock is unavailable and then lands", ok === true && n === 4 && cur.ended === "SUCCESS" && cur.endedAt === 7);
    n = -100; const never = await ZRm.settleIntent({ lock: async () => undefined, get, set, sw: { txid: TXA }, status: "SUCCESS", tries: 3, sleep: async () => {} });
    t("1138 M-1: ... bounded: a lock that never frees returns false (the caller says so), no hang", never === false);
    cur = { txid: TXC }; const other = await ZRm.settleIntent({ lock: async fn => fn(), get, set, sw: { txid: TXA }, status: "SUCCESS", sleep: async () => {} });
    t("1138 M-1: another sweep's intent is never overwritten by a settle", other === true && cur.txid === TXC && !cur.ended);
    t("1138 M-1: a failed storage write is retried too", await (async () => { let k = 0; return ZRm.settleIntent({ lock: async fn => fn(), get: () => ({ txid: TXA }), set: () => ++k > 1, sw: { txid: TXA }, status: "SUCCESS", sleep: async () => {} }); })()); } }
// 1138 L-2: the loss dialog, evaluated from app.js's own text with stubs
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), a = app.indexOf("const confirmHopLoss"), src = app.slice(a, app.indexOf("\n", app.indexOf("Cancel keeps the ZEC shielded", a)) + 1);
  let shown = ""; const f = new Function("confirm", "TOK", "SYM", "zecText", "fmtUnits", src + "; return confirmHopLoss;")(m => { shown = m; return true; }, { decimals: 6 }, "USDG", v => String(v), fmtUnits);
  f({ cap: 0.025, loss: 0.113, approved: 0.1, amount: 10_000_000n, zatsLeft: 20_000_000n, amountOut: 4_000_000n, recipient: "0xabc", destSymbol: "USDC", destDecimals: 6 });
  t("1138 L-2: the dialog names the PAYOUT token (not the connected chain's), says the total is an estimate, shows the cap as 2.5% and the approved preview figure", /USDC/.test(shown) && !/USDG/.test(shown) && /about 8\.00 USDC in total if later payouts get this rate \(an estimate\)/.test(shown) && /2\.5% limit/.test(shown) && /you approved about 10\.0%/.test(shown));
  f({ cap: 0.03, loss: 0.2, amount: 10_000_000n, zatsLeft: 10_000_000n, amountOut: 1_000_000_000_000_000_000n, recipient: "0xabc", destSymbol: "WETH", destDecimals: 18 });
  t("1138 L-2: decimals of the payout token are used (18-decimal token)", /about 1\.00 WETH/.test(shown)); }

// ================= native ETH next to USDG (Robinhood Chain): units =================
{ const E = await import("../web/eth-send.js"), { makeEthChain } = await import("./fake_eth_chain.mjs"), V = await import("viem"), { privateKeyToAccount } = await import("viem/accounts");
  const PRIV = "0x" + "45".repeat(32), ACC = privateKeyToAccount(PRIV), FROM = ACC.address.toLowerCase(), TO = "0x" + "d1".repeat(20), RH = CHAINS.rh, rhOnly = CHAINS.base;
  // --- chains.js: config, assets, text
  t("ETH: Robinhood Chain has the ETH asset id from 1Click (hood.omft.near, 18 decimals); Base has none", RH.eth.assetId === "nep141:hood.omft.near" && RH.native.decimals === 18 && !rhOnly.eth);
  const aT = assetOf(RH, "TOKEN"), aE = assetOf(RH, "ETH");
  t("assetOf: TOKEN = USDG/6 with its 1Click id; ETH = ETH/18 with the hood id; no asset (an old record) = TOKEN; ETH on Base throws", aT.symbol === "USDG" && aT.decimals === 6 && aT.assetId === RH.oneClick.assetId && aE.symbol === "ETH" && aE.decimals === 18 && aE.assetId === "nep141:hood.omft.near" && aE.native && assetOf(RH, undefined).key === "TOKEN" && throws(() => assetOf(rhOnly, "ETH")));
  t("assetKey: only an explicit ETH record is ETH", assetKey({ asset: "ETH" }) === "ETH" && assetKey({}) === "TOKEN" && assetKey(null) === "TOKEN" && assetKey({ asset: "TOKEN" }) === "TOKEN");
  t("fmtUnits: exact, cut not rounded, 2 places minimum, tiny amounts named", fmtUnits(30_000_000_000_000_000n, 18, 6) === "0.03" && fmtUnits(1_234_567_890_123_456_789n, 18, 6) === "1.234567" && fmtUnits(10n ** 18n, 18, 6) === "1.00" && fmtUnits(999_999_999_999n, 18, 6) === "<0.000001" && fmtUnits(0n, 18, 6) === "0.00" && fmtUnits(12_345_678n, 6, 6) === "12.345678" && fmtUnits(5n * 10n ** 17n + 1n, 18, 18, 0) === "0.500000000000000001");
  t("addChainParams still hands the wallet only name/symbol/decimals (the ETH route fields stay out of it)", Object.keys(addChainParams(RH).nativeCurrency).sort().join() === "decimals,name,symbol" && addChainParams(RH).chainId === "0x1237");
  // --- RLP + the signed transaction, against viem
  t("rlp: official vectors (empty, single byte, 55/56-byte strings, lists)", hex(E.rlp(new Uint8Array(0))) === "0x80" && hex(E.rlp(Uint8Array.of(0x7f))) === "0x7f" && hex(E.rlp(Uint8Array.of(0x80))) === "0x8180" && E.rlp(new Uint8Array(55).fill(1)).length === 56 && E.rlp(new Uint8Array(56).fill(1)).length === 58 && hex(E.rlp(new Uint8Array(56).fill(1))).startsWith("0xb838") && hex(E.rlp([])) === "0xc0" && hex(E.rlp([new TextEncoder().encode("cat"), new TextEncoder().encode("dog")])) === "0xc88363617483646f67");
  t("be: minimal big-endian, 0 is empty, negative refused", hex(E.be(0)) === "0x" && hex(E.be(1)) === "0x01" && hex(E.be(256)) === "0x0100" && hex(E.be(2n ** 64n)) === "0x010000000000000000" && throws(() => E.be(-1)));
  for (const [nonce, value, gl, gp] of [[0n, 1n, 21000n, 1n], [7n, 30_000_000_000_000_000n, 25_000n, 1_000_000_000n], [300n, 12_345_678_901_234_567_890n, 21000n, 123_456_789_012n]]) {
    const x = E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce, gasPrice: gp, gasLimit: gl, to: TO, value }), p = V.parseTransaction(x.raw);
    t("signLegacyTx nonce " + nonce + ": viem parses it back to the same nonce, price, gas, destination, value and chain; the signer recovers to the stealth address; the hash is keccak(raw)",
      p.nonce === Number(nonce) && p.gasPrice === gp && p.gas === gl && p.to.toLowerCase() === TO && p.value === value && p.chainId === 4663 && (await V.recoverTransactionAddress({ serializedTransaction: x.raw })).toLowerCase() === FROM && x.hash === V.keccak256(x.raw) && (!p.data || p.data === "0x")); }
  { const via = await ACC.signTransaction({ type: "legacy", chainId: 4663, nonce: 3, gasPrice: 2_000_000_000n, gas: 21000n, to: TO, value: 5n }), mine = E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 3, gasPrice: 2_000_000_000n, gasLimit: 21000n, to: TO, value: 5n });
    t("signLegacyTx is byte-for-byte what viem signs (deterministic RFC 6979 signature)", via === mine.raw); }
  t("signLegacyTx refuses the zero address and a malformed one", throws(() => E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 0, gasPrice: 1, gasLimit: 21000, to: "0x" + "00".repeat(20), value: 1 })) && throws(() => E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 0, gasPrice: 1, gasLimit: 21000, to: "0x12", value: 1 })));
  // --- fee plan and "all"
  { const c = makeEthChain({ gasPrice: 1_000_000_000n, gasEst: 21000n }); c.set(FROM, 10n ** 17n);
    const p = await E.planFee(c.rpc, { from: FROM, to: TO, value: 1n });
    t("planFee: gas limit = estimate + 25 %, price = 2 x the node's, fee = limit x price (worst case)", p.gasLimit === 26250n && p.gasPrice === 2_000_000_000n && p.fee === 26250n * 2_000_000_000n);
    const all = await E.sendableAll(c.rpc, { from: FROM, to: TO, balance: 10n ** 17n });
    t("sendableAll: balance minus the worst-case fee; send it and the transaction fits the balance (nothing is left unable to pay for itself)", all.value === 10n ** 17n - p.fee && all.fee === p.fee);
    const tx = await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: all.value }); await E.sendRaw(c.rpc, tx);
    t("... and it is accepted by the chain, the destination got exactly the value, only the real gas (21000 x price) was spent", c.balOf(TO) === all.value && c.balOf(FROM) === 10n ** 17n - all.value - 21000n * 2_000_000_000n && c.nonceOf(FROM) === 1);
    t("sendableAll: a balance that cannot even pay the fee gives null", await E.sendableAll(c.rpc, { from: FROM, to: TO, balance: p.fee }) === null && await E.sendableAll(c.rpc, { from: FROM, to: TO, balance: 5n }) === null); }
  { const c = makeEthChain(); c.set(FROM, 10n ** 16n); const fee = (await E.planFee(c.rpc, { from: FROM, to: TO, value: 1n })).fee;
    let e1 = null; try { await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: 10n ** 16n - fee / E.PRICE_X + 1n }); } catch (e) { e1 = e; }
    t("prepareSend: an amount that does not fit with the fee at the node's own price is refused BEFORE signing (e.short, 'Nothing was sent')", e1 && e1.short === true && /Nothing was sent/.test(e1.message) && c.sends.length === 0);
    t("prepareSend: exactly balance minus fee fits", (await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: 10n ** 16n - fee })).nonce === "0");
    c.estFail = "execution reverted"; t("prepareSend: a failing gas estimate is an error, nothing is signed", await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: 1n }).then(() => false, e => /reverted/.test(e.message)));
    c.estFail = null; c.bump(FROM); c.bump(FROM);
    t("prepareSend reads the nonce at 'latest' (the count of mined transactions)", (await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: 1n })).nonce === "2");
    t("prepareSend: a zero amount is refused", await E.prepareSend(c.rpc, { priv: PRIV, chainId: 4663, from: FROM, to: TO, value: 0n }).then(() => false, () => true)); }
  // --- send + status
  { const c = makeEthChain(); c.set(FROM, 10n ** 18n); const tx = E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 0, gasPrice: 2_000_000_000n, gasLimit: 26250n, to: TO, value: 1000n }), nos = ms => Promise.resolve();
    const st0 = await E.txStatus(c.rpc, { from: FROM, hash: tx.hash, nonce: tx.nonce }, { sleep: nos });
    await E.sendRaw(c.rpc, tx); await E.sendRaw(c.rpc, tx);      // the second one answers "already known": that is a success, the bytes are the same
    const st1 = await E.txStatus(c.rpc, { from: FROM, hash: tx.hash, nonce: tx.nonce }, { sleep: nos });
    t("txStatus: unsent before, mined after; sending the SAME bytes twice is one payment (already known counts as sent)", st0 === "unsent" && st1 === "mined" && c.balOf(TO) === 1000n && c.nonceOf(FROM) === 1);
    c.hideReceipt = true; t("txStatus: a lagging node (no receipt) but the transaction known = pending, not dead", await E.txStatus(c.rpc, { from: FROM, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }) === "pending"); c.hideReceipt = false;
    const other = E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 1, gasPrice: 2_000_000_000n, gasLimit: 26250n, to: TO, value: 1n });
    t("txStatus: a never-seen transaction whose nonce another transaction used is dead (after a second look)", await E.txStatus(c.rpc, { from: FROM, hash: other.hash, nonce: "0" }, { sleep: nos }) === "dead");
    let looks = 0; const lag = async (m, p) => { if (m === "eth_getTransactionCount") return ++looks === 1 ? "0x1" : "0x0"; return m === "eth_getTransactionReceipt" || m === "eth_getTransactionByHash" ? null : c.rpc(m, p); };
    t("txStatus: 'dead' is only believed if the second look agrees (a node that counted the nonce before serving the receipt)", await E.txStatus(lag, { from: FROM, hash: other.hash, nonce: "0" }, { sleep: nos }) === "unsent");
    const c2 = makeEthChain(); c2.set(FROM, 10n ** 18n); c2.revertNext = true; const rv = E.signLegacyTx({ priv: PRIV, chainId: 4663, nonce: 0, gasPrice: 1n, gasLimit: 26250n, to: TO, value: 7n }); await E.sendRaw(c2.rpc, rv);
    t("txStatus: a reverted transaction is 'failed' and the value did not move", await E.txStatus(c2.rpc, { from: FROM, hash: rv.hash, nonce: "0" }, { sleep: nos }) === "failed" && c2.balOf(TO) === 0n);
    c.refuse = "insufficient funds for gas * price + value"; const e1 = await E.sendRaw(c.rpc, other).then(() => null, e => e);
    t("sendRaw: a node refusal carries e.rpc and counts as a definite refusal; a network failure does not", e1 && e1.rpc === true && E.refused(e1) && !E.refused(new Error("network down")) && !E.refused(Object.assign(new Error("already known"), { rpc: true })));
    t("sendRaw: a node that answers with another hash is refused", await E.sendRaw(async () => "0x" + "ee".repeat(32), other).then(() => false, e => e.mismatch === true)); }
  // --- 1146: the wording of a refusal, the balance check behind a "dead" verdict, and the standard route's reload rule executed from app.js
  { const rj = m => Object.assign(new Error(m), { rpc: true });
    t("1146 L-3: refused() is an allowlist: a fee floor / invalid transaction is a refusal; an unknown wording, a nonce-used text, a hash mismatch and a network failure are not", ["max fee per gas less than block base fee", "intrinsic gas too low", "invalid sender", "exceeds block gas limit", "transaction underpriced"].every(m => E.refused(rj(m)) && E.definiteRefusal(rj(m))) && !E.refused(rj("weird proxy failure")) && !E.refused(rj("nonce too low")) && !E.refused(new Error("network down")));
    t("1146 L-3: mayStillLand covers the geth, Erigon, Nethermind, Besu and proxy wordings the audit named, and they stay refusals that are NOT definite", ["replacement transaction underpriced", "txpool is full", "insufficient funds for gas", "existing tx with same hash", "InsufficientFunds", "FeeTooLowToCompete", "Upfront cost exceeds account balance", "context deadline exceeded", "request timed out"].every(m => E.mayStillLand(rj(m)) && E.refused(rj(m)) && !E.definiteRefusal(rj(m))));
    t("1146 L-5: a plain 'transaction underpriced' does not 'may still land'; 'replacement transaction underpriced' does", !E.mayStillLand(rj("transaction underpriced")) && E.mayStillLand(rj("replacement transaction underpriced")));
    t("1146 L-4: mayHaveLeft: a fall by the amount, an unknown baseline or an unreadable balance all count as 'may have left'; a smaller fall (the fee, a refund) does not", E.mayHaveLeft("1000", "850", "100") && E.mayHaveLeft("1000", "900", "100") && !E.mayHaveLeft("1000", "950", "100") && !E.mayHaveLeft("1000", "1200", "100") && E.mayHaveLeft(null, "1", "1") && E.mayHaveLeft("1", null, "1") && E.mayHaveLeft(undefined, "1", "1")); }
  { const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), es = fs.readFileSync(new URL("../web/eth-send.js", import.meta.url), "utf8");
    t("1146 I-1: the capped balance left after a private ETH part never goes below zero", /left: \(l => l < 0n \? 0n : l\)\(/.test(app));
    t("1146 I-4: each JSDoc sits directly above the export it describes (the refusal doc above refused, the may-still-land doc above mayStillLand)", /\*\/\nconst LANDS = [^\n]*\nexport const mayStillLand/.test(es) && /\*\/\nexport const refused = /.test(es) && !/\*\/\n\/\*\*/.test(es.slice(es.indexOf("const NONCE_USED"))));
    t("1146 L-3: the hop and the routes decide on definiteRefusal / mayStillLand, never on a bare refused()", /ETH\.definiteRefusal\(e\)/.test(fs.readFileSync(new URL("../web/zec-hop.js", import.meta.url), "utf8")) && /definiteRefusal\(e\) && !unknown/.test(es)); }
  { const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), code = app.slice(app.indexOf("const ETH_WD_KEY"), app.indexOf("async function ethFeeOf")), K = "0x" + "ab".repeat(20);
    const mkStore = () => { const st = {}; return { getItem: k => st[k] ?? null, setItem: (k, v) => { st[k] = v; }, removeItem: k => { delete st[k]; } }; };
    const run = async (status, rec, balHex) => { const pend = new Map([[K, 1]]), ls = mkStore(), ethRpc = async m => { if (m === "eth_getBalance") { if (balHex === null) throw new Error("rpc down"); return balHex; } throw new Error("unexpected " + m); };
      const A = new Function("localStorage", "ETH", "ethRpc", "found", "pendingWd", code + "; return { ethWdRec, ethResolve };")(ls, { ...E, txStatus: async () => status }, ethRpc, [{ stealth: K }], pend); A.ethWdRec.put(K, rec);
      const any = await A.ethResolve(); return { any, held: pend.has(K), kept: !!A.ethWdRec.all()[K] }; };
    const fresh = { hash: "0x" + "11".repeat(32), nonce: "0", at: Date.now(), bal: "1000", value: "100" };
    let r = await run("dead", fresh, "0x3e8"); t("1146 L-4 standard reload (executed): 'dead' and the balance did NOT fall -> the guard and record are released", r.any && !r.held && !r.kept);
    r = await run("dead", fresh, "0x352"); t("... 'dead' and the balance fell by the amount (a lagging node, the transfer landed) -> the guard STAYS", !r.any && r.held && r.kept);
    r = await run("dead", fresh, null); t("... 'dead' and the balance cannot be read -> the guard stays", !r.any && r.held && r.kept);
    const old = { hash: fresh.hash, nonce: "0", at: Date.now() };
    r = await run("dead", old, "0x3e8"); t("... 'dead' on a record without a baseline -> the guard stays inside its window", !r.any && r.held && r.kept);
    r = await run("dead", { ...old, at: Date.now() - 4000_000 }, "0x3e8"); t("... and it is released once the window (1 h + 60 s) has run out, so the hold has an end", r.any && !r.held && !r.kept);
    r = await run("dead", { ...fresh, at: Date.now() - 4000_000 }, "0x352"); t("... also with a fall of the balance once the window has run out", r.any && !r.held);
    r = await run("mined", fresh, "0x3e8"); t("mined and reverted still release at once; unsent waits for the window", r.any && !r.held && (await run("failed", fresh, "0x3e8")).any && !(await run("unsent", fresh, "0x3e8")).any); }
  // --- quote request + summary for ETH
  { const r = buildQuoteRequest({ from: RH, to: RH, amount: 3n * 10n ** 16n, recipient: TO, refundTo: "0x" + "ab".repeat(20), dry: true, asset: "ETH", now: 0 });
    t("buildQuoteRequest ETH: origin and destination are the hood ETH asset; the stablecoin request is unchanged", r.originAsset === "nep141:hood.omft.near" && r.destinationAsset === "nep141:hood.omft.near" && r.amount === "30000000000000000" && buildQuoteRequest({ from: RH, to: RH, amount: 1n, recipient: TO, refundTo: TO, dry: true, now: 0 }).originAsset === RH.oneClick.assetId);
    t("buildQuoteRequest ETH: refused where the chain has no ETH route (Base)", throws(() => buildQuoteRequest({ from: rhOnly, to: rhOnly, amount: 1n, recipient: TO, refundTo: TO, dry: true, asset: "ETH" })) && throws(() => buildQuoteRequest({ from: RH, to: rhOnly, amount: 1n, recipient: TO, refundTo: TO, dry: true, asset: "ETH" })));
    const echo = (over = {}) => async (u, init) => ({ ok: true, json: async () => ({ quote: { amountIn: r.amount, amountOut: "29700000000000000", depositAddress: "0x" + "d2".repeat(20), timeEstimate: 30 }, quoteRequest: { ...JSON.parse(init.body), ...over } }) });
    r.dry = false;
    t("requestQuote ETH: a quote that echoes the right ETH assets is accepted", (await requestQuote({ req: r, fetchFn: echo() })).quote.amountOut === "29700000000000000");
    t("requestQuote ETH: a quote for the stablecoin instead of ETH (either side) is refused", await requestQuote({ req: r, fetchFn: echo({ originAsset: RH.oneClick.assetId }) }).then(() => false, e => /does not match/.test(e.message)) && await requestQuote({ req: r, fetchFn: echo({ destinationAsset: RH.oneClick.assetId }) }).then(() => false, e => /does not match/.test(e.message)));
    const sm = PWm.summarizeQuote({ quote: { amountIn: "30000000000000000", amountOut: "29700000000000000", timeEstimate: 30 } }, 18, 18);
    t("summarizeQuote ETH: exact 18-decimal text, fee in ETH, percent right", sm.inText === "0.03" && sm.outText === "0.0297" && sm.feeText === "0.0003" && sm.feePct === "1.00");
    t("summarizeQuote USDG is unchanged", PWm.summarizeQuote({ quote: { amountIn: "5000000", amountOut: "4950000", timeEstimate: 30 } }, 6, 6).feeText === "0.0500"); }
  t("fastPlan: ETH is never split (one part of the whole amount, whatever the size); USDG still splits", [5n, 10n ** 18n, 123_456_789_012_345_678_901n].every(v => { const pl = PWm.fastPlan(v, () => 0.99, "ETH"); return pl.length === 1 && pl[0].amount === v.toString() && pl[0].state === "PLANNED"; }) && PWm.fastPlan(50_000_000n, () => 0.99, "TOKEN").length === 2);
  // --- metadata + Paid for an ETH payment
  { const meta = "0x" + "ab" + "eeeeeeee" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" + (30_000_000_000_000_000n).toString(16).padStart(64, "0"), md = decodeMetadata(meta);
    t("decodeMetadata: an ETH payment reads as token 'ETH' with the exact 18-decimal amount", md.token === "ETH" && md.amount === 30_000_000_000_000_000n && md.viewTag === "0xab");
    const SP = RH.stealthPay, ST = "0x" + "5a".repeat(20), pad32 = a => "0x" + "0".repeat(24) + a.slice(2), log = { address: SP, topics: [CR.PAID_TOPIC, pad32(ST), pad32(CR.ETH_TOKEN)], data: "0x" + (30_000_000_000_000_000n).toString(16).padStart(64, "0") }, rc = { ok: true, logs: [log] };
    t("hasPaid: ETH payment proven by Paid(stealth, ETH sentinel, amount); another amount or another token is not", CR.hasPaid(rc, { stealthPay: SP, stealth: ST, token: CR.ETH_TOKEN, amount: 30_000_000_000_000_000n }) && !CR.hasPaid(rc, { stealthPay: SP, stealth: ST, token: CR.ETH_TOKEN, amount: 29_999_999_999_999_999n }) && !CR.hasPaid(rc, { stealthPay: SP, stealth: ST, token: RH.token.address })); }
  // --- the deployed contract has payETH(address,bytes,bytes1) (selector aea03757) -- offline check of the source selector the page uses
  { const sel = hex(CR.topic("payETH(address,bytes,bytes1)") ? unhex(CR.topic("payETH(address,bytes,bytes1)")).slice(0, 4) : new Uint8Array(4));
    t("payETH(address,bytes,bytes1) selector is 0xaea03757 (also found in the deployed bytecode on Robinhood Chain, read-only, 1 Nov)", sel === "0xaea03757"); }
  // --- app.js: the rules, in its own text
  // --- the supporting pieces must serve ETH as well as USDG (owner's addition): indexer, sanctions, relayer allow-list, texts
  { const { spawnSync } = await import("child_process"), py = `
import os, importlib.util, json
os.environ.update(STEALTH_CHAIN="rh", STEALTH_RPC="http://127.0.0.1:1", STEALTHPAY="${RH.stealthPay}")
sp = importlib.util.spec_from_file_location("ix", "stealth_indexer.py"); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
payer = "0x" + "aa" * 20; st = "0x" + "bb" * 20
eth_rc = {"from": payer, "logs": [{"address": m.STEALTHPAY, "topics": ["0x" + "11" * 32, "0x" + "0" * 24 + "bb" * 20, "0x" + "0" * 24 + "ee" * 20], "data": "0x"}]}
print(json.dumps({"eth": m._real_payer(eth_rc, st), "none": m._real_payer({"from": payer, "logs": []}, st), "tok": m.USDC}))`;
    const r = spawnSync("python3", ["-B", "-I", "-c", "import sys; sys.path.insert(0, '.'); exec(" + JSON.stringify(py) + ")"], { cwd: new URL(".", import.meta.url).pathname, encoding: "utf8" }), o = r.status === 0 ? JSON.parse(r.stdout.trim().split("\n").pop()) : null;
    t("indexer: the payer of a payETH payment (no token Transfer in the receipt) is the transaction sender, i.e. the real payer; the stablecoin logic is unchanged", o && o.eth === "0x" + "aa".repeat(20) && o.none === "0x" + "aa".repeat(20) && o.tok === RH.token.address.toLowerCase(), r.stderr.slice(0, 200));
    const ix = fs.readFileSync(new URL("./stealth_indexer.py", import.meta.url), "utf8"), rl = fs.readFileSync(new URL("./relayer.mjs", import.meta.url), "utf8");
    t("indexer: announcements are stored whole (stealth, caller, eph, meta, view tag) whatever the token, so an ETH payment (selector 0xeeeeeeee) is served by /announcements and the history pages like any other; no filter on the token at ingest", /INSERT OR IGNORE INTO ann\(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer,paid\)/.test(ix) && !/tok == USDC[^\n]*continue/.test(ix.slice(0, ix.indexOf("/known"))) && /"eth": str\(int\.from_bytes/.test(ix));      // and /balances returns the native balance next to the token one
    t("indexer /known (the relay allow-list gate) counts only the chain stablecoin: transfer selector a9059cbb + token + minimum; an ETH payment (selector eeeeeeee) never makes an address 'known', so the gasless relay stays USDG/USDC-only", /m\[1:5\] == bytes\.fromhex\("a9059cbb"\)/.test(ix) && /if tok == USDC and amt >= MIN_KNOWN_USDC: ok = True/.test(ix));
    t("relayer: /relay/pay refuses any token other than the chain stablecoin (the ETH sentinel included), /relay signs only transferWithAuthorization on that token, /relay/stats has no per-asset assumption that ETH could skew (gas, sends, fees only)", /if \(token !== TOKEN\) throw new Error\("unsupported token"\)/.test(rl) && !/0xeeee/i.test(rl) && /address: TOKEN, abi, functionName: "transferWithAuthorization"/.test(rl));
    const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), ew = app.slice(app.indexOf("async function ethWithdraw"), app.indexOf("async function ethStandard"));
    t("sanctions: every ETH recipient (standard route too, which never reaches the relayer's screen) is screened by the page before anything is signed", ew.indexOf("await screenRecipient(to)") > 0 && ew.indexOf("await screenRecipient(to)") < ew.indexOf("ethStandard(") && ew.indexOf("await screenRecipient(to)") < ew.indexOf("fastWithdraw(to, value, hit") && ew.indexOf("await screenRecipient(to)") < ew.indexOf("privateWithdraw(to, value, hit"));
    t("texts: the pay screen no longer says 'no gas' for ETH, the withdraw screen names the fee payer, the route labels carry their ETA from the code constants for ETH too", /id="pay-gas-note"/.test(fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8")) && /you pay the gas from your wallet/.test(app) && /direct, pays its own network fee · " \+ PW\.standardEtaLabel\(\)/.test(app));
    t("minimum amounts: ETH has no invented floor: standard needs amount > 0 and amount + fee <= balance; private routes are bounded by 1Click's own minimum (the dry quote in the preview refuses a too-small amount with its message) and the Zcash route by okSize", /!\(value > 0n\)/.test(ew) && /value \+ fee > all/.test(ew) && /Too small for the private route/.test(app) && /call\(fetchFn, base \+ "\/v0\/quote"/.test(fs.readFileSync(new URL("../web/private-withdraw.js", import.meta.url), "utf8"))); }
  { const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
    t("pay: the ETH choice exists on Robinhood Chain only (the option is removed where chain.eth is not set), and the amount is the exact wei the wallet sends", /if \(ETHOK\) \{ o\[1\]\.value = "NATIVE"; o\[1\]\.textContent = NAT; \} else o\[1\]\.remove\(\)/.test(app) && /const wei = rawIn \?\? BigInt/.test(app) && /raw: a\.send, d, own/.test(app) && /token: ETH_TOKEN, amount: a\.send/.test(app));
    const std = app.slice(app.indexOf("async function ethStandard"), app.indexOf('$("btn-wd").addEventListener'));
    t("1149 L-1 / M-2: the standard route reads a FRESH balance before prepareSend (unreadable = nothing signed), records that as the guard's baseline (not the Scan balance), and keeps the full price margin (noCut)", std.indexOf('eth_getBalance", [w.stealth') > 0 && std.indexOf('eth_getBalance", [w.stealth') < std.indexOf("ETH.prepareSend(") && /bal: String\(fresh\)/.test(std) && !/bal: String\(all\)/.test(std) && /\{ noCut: true \}\)/.test(std));
    t("ETH standard withdraw: the guard and the record are armed BEFORE the first broadcast; the same signed bytes are re-sent; a refusal clears them, an unknown outcome does not", std.indexOf("pendingWd.set(") > 0 && std.indexOf("pendingWd.set(") < std.indexOf("ETH.sendRaw(") && std.indexOf("ethWdRec.put(") < std.indexOf("ETH.sendRaw(") && /if \(sr\.outcome === "refused"\) \{ pendingWd\.delete\(k\); ethWdRec\.del\(k\);/.test(std) && /Check the explorer for tx " \+ tx\.hash \+ " before sending again/.test(std) && (std.match(/ETH\.prepareSend\(/g) || []).length === 1);
    t("ETH standard withdraw: success needs the receipt of the very hash we signed; a revert clears the guard, an unexpected receipt does not", /waitReceipt\(tx\.hash, x => x\.ok && x\.hash === tx\.hash\)/.test(std) && /if \(!rc\.ok && !rc\.unexpected\) \{ pendingWd\.delete\(k\); ethWdRec\.del\(k\); \}/.test(std));
    const h = app.slice(app.indexOf('$("btn-wd").addEventListener'), app.indexOf("async function waitReceipt"));
    t("ETH withdraw is dispatched BEFORE the stablecoin's domain-separator read and EIP-3009 signing (none of that applies to ETH), and the stablecoin handler is otherwise untouched", h.indexOf('if (wdA === "ETH") return await ethWithdraw(to)') > 0 && h.indexOf('if (wdA === "ETH") return await ethWithdraw(to)') < h.indexOf("0x3644e515") && h.indexOf('if (wdA === "ETH") return await ethWithdraw(to)') < h.indexOf("signDigest(") && (h.match(/pendingWd\.delete/g) || []).length === 3);
    const ew = app.slice(app.indexOf("async function ethWithdraw"), app.indexOf("async function ethStandard"));
    t("ETH withdraw: 'all' keeps the network fee back; an amount that does not fit with the fee is refused with both numbers; private routes get the amount only after that check", /exact \? exact\.send : all - fee/.test(ew) && /value \+ fee > all/.test(ew) && ew.indexOf("value + fee > all") < ew.indexOf("fastWithdraw(to, value, hit") && /decimals: C\.native\.decimals/.test(ew));
    t("ETH hop/fast: the hop context carries the ETH sender, hopCtx for a resume takes the asset from the saved record, a fast record stores asset only for ETH", /eth: ethApi\(f, hit\.stealthPriv\)/.test(app) && /ctx\.asset = assetKey\(r\.rec\.st\)/.test(app) && /\.\.\.\(eth \? \{ asset: "ETH" \} : \{\}\), startedAt/.test(app) && /ethStatus: \(r, tx\) => ETH\.txStatus/.test(app));
    const std2 = app.slice(app.indexOf("async function ethStandard"), app.indexOf('$("btn-wd").addEventListener'));
    t("1144 M-1: the standard route decides through ETH.sendSettled; only 'refused' and 'failed' clear the guard, 'unknown' keeps it and never says 'Nothing was sent'", /ETH\.sendSettled\(/.test(std2) && /sr\.outcome === "refused"\) \{ pendingWd\.delete\(k\)/.test(std2) && /sr\.outcome === "failed"\) \{ pendingWd\.delete\(k\)/.test(std2) && /sr\.outcome === "unknown"\) throw new Error\("Could not confirm[^;]*\);/.test(std2) && !/sr\.outcome === "unknown"\) \{[^}]*pendingWd\.delete/.test(std2) && !/sr\.outcome === "unknown"\)[^;]*Nothing was sent/.test(std2));
    t("1144 L-3: the spent map is keyed by address AND coin (no wei in a 6-decimal number)", /const spentKey = \(k, eth\) => k\.toLowerCase\(\) \+ "\|"/.test(app) && !/spent\.(get|set|delete)\((k|w\.stealth\.toLowerCase\(\)|f\.stealth\.toLowerCase\(\)),/.test(app) && !/spent\.(get|delete)\(k\)/.test(app));
    t("1144 L-4: a lost transfer's coin is shown and chosen on the card; with both coins held there is no default and Return/Continue refuse until one is chosen", /lostCoinDefault/.test(app) && /return payHeld && otherHeld \? null/.test(app) && /Coin of this transfer/.test(app) && /const asset = payAsset\(l\);/.test(app));
    t("1144 I-3: unsent ETH withdraw records are cleared only after the guard window; the header comment no longer claims the withdraw routes save the raw bytes", /st === "unsent" && Date\.now\(\) > ethArmedUntil\(r\)/.test(app) && !/The signed bytes are saved by the caller BEFORE the first broadcast and only ever re-sent as they are\./.test(fs.readFileSync(new URL("../web/eth-send.js", import.meta.url), "utf8")));
    t("Return/lost: the return quote and the done text use the coin of the record (a lost transfer: the coin of the payment), not the stablecoin", /asset: h\.asset \|\| assetKey\(h\.st\)/.test(app) && /asset: payAsset\(l\)/.test(app) && /const asset = payAsset\(l\);/.test(app) && /dest: C, asset \}\)/.test(app) && !/payAsset\(l\.f\)/.test(app));
    t("render: ETH payments show the ETH amount (18 decimals, exact) and an ETH Withdraw button only above the transfer's own fee", /fmtEth\(f\.amount \|\| 0n\)/.test(app) && /ETHOK && f\.eth > 0n && !ethDust\(f\)/.test(app) && /openWithdraw\(i, "ETH"\)/.test(app));
    t("the chain read for ETH sends/reads is the plain RPC (the node's own error kept) and never the wallet's provider", /const ethRpc = async \(method, params\) => \{\s*const r = await fetch\(C\.rpc,/.test(app) && !/ethRpc[^;]*wallet\(/.test(app.slice(app.indexOf("const ethRpc"), app.indexOf("const ethApi")))); }
}
// ---- audit 1159 (whole web client)
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const gp = new Function("isHash", "isAddr", app.slice(app.indexOf("const goodPage"), app.indexOf("/** Returns k => rows[]")) + "; return goodPage;")(h => /^0x[0-9a-fA-F]{64}$/.test(h || ""), a => /^0x[0-9a-fA-F]{40}$/.test(a || ""));
  const row = (i, n = 8) => [i, 5, "0x" + "ab".repeat(32), "0x" + "cd".repeat(20), "0x02" + "ee".repeat(32), "0x11", null, 1].slice(0, n), man = { page_size: 4 };
  const full = n => [1, 2, 3, 4].map(i => row(i, n));
  t("1159 I-3: a history page is accepted only as an array of exactly page_size rows of 7 or 8 fields with a tx hash and a stealth address", gp(full(8), man) && gp(full(7), man) && !gp(null, man) && !gp({}, man) && !gp(full(8).slice(0, 3), man) && !gp([...full(8), row(5)], man) && !gp([...full(8).slice(0, 3), [1]], man) && !gp([...full(8).slice(0, 3), row(9).map((x, i) => i === 3 ? "nope" : x)], man) && !gp([...full(8).slice(0, 3), "x"], man));
  t("1159 I-3: a cached page that fails the check is fetched again; a fetched one that fails is an error; scan() tests d.rows is an array BEFORE the for-of", /goodPage\(hit, man\)\) pages\[k\] = hit; else need\.push\(k\)/.test(app) && /if \(!goodPage\(rows, man\)\) throw new Error\("bad history page "/.test(app) && app.indexOf("if (!Array.isArray(d.rows)) throw") > 0 && app.indexOf("if (!Array.isArray(d.rows)) throw") < app.indexOf("for (const r of d.rows)"));
  // M-1: run the page's own check() on forged and genuine rows
  const sc = app.slice(app.indexOf("  const check = (id, block"), app.indexOf("  let since = 0;")), T = "0x" + "a".repeat(40);
  const run = rows => { const mine = [], byStealth = new Map(), K = { legacy: null }, A = "0xacct", isHash = h => /^0x[0-9a-fA-F]{64}$/.test(h || ""), isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), md = { token: T, amount: 9999n * 10n ** 6n, viewTag: 1 }, decodeMetadata = () => md, checkAnnouncement = (k, eph) => ({ stealth: eph }); let n = 0;
    new Function("mine", "byStealth", "K", "A", "isHash", "isAddr", "decodeMetadata", "checkAnnouncement", "n", "foldRow", sc + "; for (const r of ROWS) check(...r); return mine;".replace("ROWS", "arguments[10]"))(mine, byStealth, K, A, isHash, isAddr, decodeMetadata, checkAnnouncement, n, CR.foldRow, rows); return mine; };
  const S1 = "0x" + "1".repeat(40), S2 = "0x" + "2".repeat(40), tx = c => "0x" + c.repeat(64);
  const mine = run([[1, 5, tx("a"), S1, S1, "0x", null, 0], [2, 6, tx("b"), S1, S1, "0x", null, 0], [3, 7, tx("c"), S1, S1, "0x", null, 1], [4, 8, tx("d"), S2, S2, "0x", null, undefined], [5, 9, tx("e"), S2, S2, "0x", null, 1], [6, 9, tx("f"), S2, S2, "0x", null, 1]]);
  t("1159 M-1: a row is verified only when the indexer's 8th field is 1; old 7-field rows and forged ones are not", mine.length === 2 && mine.find(x => x.stealth === S1).v === true && mine.find(x => x.stealth === S2).v === true && run([[1, 5, tx("a"), S1, S1, "0x", null], [2, 5, tx("b"), S2, S2, "0x", null, 0], [3, 5, tx("c"), "0x" + "3".repeat(40), "0x" + "3".repeat(40), "0x", null, true]]).map(x => x.v).join() === "false,false,true");
  t("1159 M-1: rows are collapsed by stealth address; a verified row replaces an unverified duplicate, a later duplicate never replaces a verified one", mine.find(x => x.stealth === S1).tx === tx("c") && mine.find(x => x.stealth === S2).tx === tx("e") && run([[1, 5, tx("a"), S1, S1, "0x", null, 0], [2, 6, tx("b"), S1, S1, "0x", null, 0]]).length === 1);
  t("1159 M-1: /announcements rows pass r.verified, history rows pass r[7]", /r\.payer, r\.verified\)/.test(app) && /r\[6\], r\[7\]\)/.test(app));
  const rd = app.slice(app.indexOf("const ethFirst"), app.indexOf("top.appendChild(el(\"span\", \"amt\", label))"));
  t("1159 M-1: render shows the announced amount only for a verified row; otherwise the on-chain balance with 'unverified' (or 'unverified payment' while unread)", /const label = !f\.v \? \(held \? held \+ " \(unverified\)" : "unverified payment"\) :/.test(rd) && /held = f\.usdc > 0n \? fmtTok\(f\.usdc\)/.test(rd) && /ethFirst = f\.v && f\.token === "ETH"/.test(rd));
  // L-1: ETH goes by the live balance whatever the announcement says
  const ethCode = app.slice(app.indexOf("const ethDust"), app.indexOf("const hitOf")), E = new Function("ETHOK", "ethFeeNow", ethCode + "; return { ethDust, isEmpty };");
  { const e = E(true, 100n), tokAnnounced = { token: "0x" + "a".repeat(40), usdc: 0n, eth: 500n }, dust = { ...tokAnnounced, eth: 100n }; 
    t("1159 L-1: an address announced as USDG that holds ETH above the fee is not empty and ETH is not dust; ETH at or below the fee is empty", !e.isEmpty(tokAnnounced) && !e.ethDust(tokAnnounced) && e.isEmpty(dust) && e.isEmpty({ token: "ETH", usdc: 0n, eth: 0n }) && !E(true, null).isEmpty({ usdc: 0n, eth: 1n }));
    t("1159 L-1: where ETH is off (Base), ETH never counts toward 'not empty'", E(false, 100n).isEmpty(tokAnnounced)); }
  t("1159 L-1: the fee is read from any address holding ETH (not only an ETH-announced one)", /list\.find\(f => f\.eth > 0n\)/.test(app) && !/f\.token === "ETH" && f\.eth > 0n/.test(app));
  // L-2
  t("1159 L-2: an account change empties hops, lost, lostNone, lostDone and redraws; found rows remember their account; Return refuses unless it is the current one; a late lost check adds no card", /changed\) \{ keys = null; found = \[\]; try \{ hops\.clear\(\); lost\.clear\(\); lostNone\.clear\(\); lostDone\.clear\(\); renderHops\(\); \}/.test(app) && /v: v === 1 \|\| v === true, acct: A \}/.test(app) && /if \(!h\.f \|\| h\.f\.acct !== acct\) throw new Error\("These keys were derived for another account/.test(app) && /if \(f\.acct !== acct\) return;/.test(app));
  { const rz = app.slice(app.indexOf("async function returnZec"), app.indexOf("Looking for the ZEC")); t("1159 L-2: the account check in returnZec comes before any key is derived or quote asked", rz.indexOf("h.f.acct !== acct") > 0 && !/mnemonicFor|requestQuote/.test(rz)); }
  // L-3
  { const mk = (url, hash = "0x" + "9".repeat(64)) => hopView({ st: { step: "DONE", chain: "base", dest: "rh", amount: "5000000", outTotal: "5000000", recipient: "0x" + "4".repeat(40), startedAt: 1, doneAt: 2, payoutTx: { hash, url } } }, 3).link;
    const ex = CHAINS.rh.explorer, good = ex + "/tx/0xabc";
    t("1159 L-3: a 1Click explorer link is used only on the destination explorer's origin; any other https link, a lookalike host, javascript: or garbage falls back to the configured explorer + hash", (mk(good) || {}).href === good && (mk("https://evil.example/tx/1") || {}).href === ex + "/tx/0x" + "9".repeat(64) && (mk(ex.replace("https://", "https://x.")) || {}).href === ex + "/tx/0x" + "9".repeat(64) && (mk(ex + ".evil.example/tx/1") || {}).href === ex + "/tx/0x" + "9".repeat(64) && (mk("javascript:alert(1)") || {}).href === ex + "/tx/0x" + "9".repeat(64) && (mk("") || {}).href === ex + "/tx/0x" + "9".repeat(64)); }
  // I-2: framing is closed by response headers (a <meta> CSP cannot carry frame-ancestors)
  { const c = fs.readFileSync(new URL("../ops/nginx-stealth-zec.conf", import.meta.url), "utf8");      // the only conf in the repo that serves app pages (server/deploy/stealth-{rh,base}.conf proxy JSON under /stealth-api/ only)
    t("1159 I-2: the app-page location sends frame-ancestors 'none' and nosniff, in the wasm sub-location too", (c.match(/frame-ancestors 'none'/g) || []).length === 2 && (c.match(/X-Content-Type-Options\s+"nosniff"/g) || []).length === 2); }
}
// audit 1161 M-1 / L-1: the client checks used[stealth] before it asks for anything, and picks a new address when the old one is taken
{ const PA = await import("../web/pay-auth.js"), app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8");
  const S = "0x" + "ab".repeat(20);
  t("1161 M-1: used(address) call data = selector + padded address; selectors equal keccak of the signatures", PA.usedCall(S) === "0xc497da8d" + "0".repeat(24) + "ab".repeat(20) && PA.USED_SELECTOR === hex(keccak(new TextEncoder().encode("used(address)"))).slice(0, 10) && PA.NOT_FRESH_SELECTOR === hex(keccak(new TextEncoder().encode("NotFresh(address)"))).slice(0, 10));
  t("1161 M-1: isUsedAnswer true only for a non-zero word", PA.isUsedAnswer("0x" + "0".repeat(63) + "1") && !PA.isUsedAnswer("0x" + "0".repeat(64)) && !PA.isUsedAnswer("0x") && !PA.isUsedAnswer(null) && !PA.isUsedAnswer("junk"));
  t("1161 M-1: isNotFresh recognises the selector in wallet error data, the name, and the relayer's refusal; not other errors",
    PA.isNotFresh({ message: "execution reverted", data: { data: "0x59246e68" + "0".repeat(64) } }) && PA.isNotFresh(new Error("reverted: NotFresh(0xabc)")) && PA.isNotFresh("stealth address already used: it was paid or blocked by someone else") && PA.isNotFresh({ error: { data: "0x59246E68" + "00" } })
    && !PA.isNotFresh(new Error("user rejected the request")) && !PA.isNotFresh("authorization already used") && !PA.isNotFresh(null) && !PA.isNotFresh({}));
  const gl = app.slice(app.indexOf("async function payGasless"), app.indexOf("// ---- amount: two linked fields"));
  t("1161 M-1: gasless pay checks used[] before the balance read and the signature", gl.indexOf("await requireFresh(d.stealth)") > 0 && gl.indexOf("await requireFresh(d.stealth)") < gl.indexOf("eth_signTypedData_v4"));
  t("1161 M-1: a NotFresh answer from the relayer becomes a notFresh error (no hash is awaited)", /isNotFresh\(j\.error\)\) throw new NotFreshError/.test(gl) && gl.indexOf("isNotFresh(j.error)") < gl.indexOf("if (!r.ok || j.error)"));
  const ps = app.slice(app.indexOf("async function payStealth"), app.indexOf("async function payGasless"));
  t("1161 M-1: own-gas token and ETH payments check used[] first and map a NotFresh revert to notFresh", (ps.match(/await requireFresh\(d\.stealth\)/g) || []).length === 2 && (ps.match(/isNotFresh\(e\) \? new NotFreshError/g) || []).length === 2);
  const dp = app.slice(app.indexOf("async function doPay"), app.indexOf("const doPayOnce"));
  t("1161 M-1: doPay derives a new address per try: gasless up to 2 more times with a 'sign again' message, own gas once after a confirm", /d = deriveForPayment\(m\)/.test(dp) && /tries >= \(token === "TOKEN" && !own \? 2 : 1\)/.test(dp) && /please sign again/.test(dp) && /else if \(!confirm\(msg\)\)/.test(dp));
  t("1161 M-1: only a notFresh error is retried (any other failure is rethrown at once)", /if \(!e \|\| !e\.notFresh \|\|/.test(dp));
  t("1161 L-1: the client refuses to sign when the fee recipient equals the one-time address, before the signature", /feeTo\.toLowerCase\(\) === d\.stealth\.toLowerCase\(\)\) throw/.test(gl) && gl.indexOf("feeTo.toLowerCase() === d.stealth.toLowerCase()") < gl.indexOf("eth_signTypedData_v4"));
}
// 1Click outage: classify, degrade to one short message, never start or sign; input errors keep their text; Standard never touches 1Click
{ const PWq = PWm, resp = (status, body) => async () => ({ ok: status < 400, status, json: async () => { if (body === undefined) throw new Error("not json"); return body; } });
  const req = { amount: "1000000", recipient: "0x" + "11".repeat(20), refundTo: "0x" + "22".repeat(20), originAsset: "a", destinationAsset: "b", dry: true };
  const err = async (fetchFn, f = PWq.requestQuote) => { try { await f({ req, fetchFn }); return null; } catch (e) { return e; } };
  const down = [["521 no body", resp(521)], ["522", resp(522, {})], ["523", resp(523)], ["524", resp(524)], ["500 json", resp(500, { message: "oops" })], ["network failure", async () => { throw new TypeError("Failed to fetch"); }],
    ["timeout", async () => { const e = new Error("signal timed out"); e.name = "TimeoutError"; throw e; }], ["pair not available (400)", resp(400, { message: "Quoting for this pair is not available" })]];
  for (const [n, f] of down) t("1Click outage: " + n + " is classified as service unavailable", PWq.isQuoteUnavailable(await err(f)));
  t("1Click outage: input problems are not an outage", !PWq.isQuoteUnavailable(await err(resp(400, { message: "Amount is too low for the swap, at least 150000" }))) && !PWq.isQuoteUnavailable(await err(resp(400, { message: "recipient is invalid" }))) && !PWq.isQuoteUnavailable(await err(resp(401, {}))) && !PWq.isQuoteUnavailable(null) && !PWq.isQuoteUnavailable(new Error("bad address")));
  let calls = 0; const counted = f => async (...a) => { calls++; return f(...a); };
  for (const [n, f] of down) { const e = await err(counted(f), PWq.previewQuote); t("1Click outage: preview shows the one short message (" + n + ")", !!e && e.message === PWq.QUOTE_DOWN); }
  t("1Click outage: the message is short English and points to Standard", PWq.QUOTE_DOWN === "This route needs an outside swap service that is not answering right now. Standard withdraw still works. Try again in a few minutes.");
  const e1 = await err(resp(400, { message: "Amount is too low for the swap, at least 150000" }), PWq.previewQuote);
  t("1Click outage: preview keeps the readable input message", e1 && e1.message === "Amount is too low for the swap, at least 150000");
  const appSrc = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), pvSrc = appSrc.slice(appSrc.indexOf("async function privateWithdraw"), appSrc.indexOf("// ---- route \"private, fast\"")), fsrc = appSrc.slice(appSrc.indexOf("async function fastWithdraw"), appSrc.indexOf("const w = wd, k = w.stealth.toLowerCase(), plan"));
  t("1Click outage: both preview steps use previewQuote and sit before any hop start or signature (the throw returns to the page handler, the route selector is untouched)",
    !/PW\.requestQuote/.test(pvSrc + fsrc) && (pvSrc.match(/PW\.previewQuote/g) || []).length === 2 && fsrc.includes("PW.previewQuote") && pvSrc.indexOf("PW.previewQuote") < pvSrc.indexOf("await runHop(") && !/wd-route/.test(pvSrc + fsrc));
  t("1Click outage: resume paths still call requestQuote directly (zec-hop and the fast resume are unchanged)", /PW\.requestQuote\(\{ base, fetchFn: fIn/.test(fs.readFileSync(new URL("../web/zec-hop.js", import.meta.url), "utf8")) && !/previewQuote/.test(fs.readFileSync(new URL("../web/zec-hop.js", import.meta.url), "utf8")));
  const stdPart = appSrc.slice(appSrc.indexOf("const now = Math.floor(Date.now() / 1000); const validBefore"), appSrc.indexOf("const doneMsg = \"Done: \"", appSrc.indexOf("const now = Math.floor(Date.now() / 1000); const validBefore")));
  t("Standard route (token and ETH) never calls 1Click", stdPart.length > 500 && !/requestQuote|previewQuote|ONECLICK|runFast|runHop/.test(stdPart) && !/requestQuote|previewQuote|ONECLICK|runFast|runHop/.test(appSrc.slice(appSrc.indexOf("async function ethStandard"), appSrc.indexOf("async function ethStandard") + 3000).split("\nasync function ")[0]));
}
// next-step highlight + route hints (UI only): the real nextStep() runs against a stub DOM
{
  const html = fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8"), app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), css = fs.readFileSync(new URL("../web/loophole.css", import.meta.url), "utf8");
  t("hint elements exist: keys hint text, route hint line", /id="keys-hint">Sign once to create your private keys\. No payment, no gas\.</.test(html) && /id="wd-route-hint"/.test(html));
  t("route hints: Standard / Private fast / Maximum lines", /std: "Link visible on-chain", fast: "Hides the link", max: "Strongest, best above ~\$50"/.test(app) && /\$\("wd-route-hint"\)\.textContent = ROUTE_HINT\[route\(\)\]/.test(app));
  t("pulse css: animation, plus a static outline under prefers-reduced-motion", /\.btn\.next,\.wallet\.next\{animation:nx/.test(css) && /prefers-reduced-motion:reduce\)\{\.btn\.next,\.wallet\.next\{animation:none;outline/.test(css));
  const src = app.slice(app.indexOf("function nextStep()"), app.indexOf("async function connect()"));
  const els = {}; for (const id of ["wbtn", "btn-keys", "copy-link", "keys-hint"]) { const c = new Set(); els[id] = { hidden: false, classList: { toggle: (k, v) => v ? c.add(k) : c.delete(k), has: k => c.has(k) } }; }
  const run = (acct, keys, linkCopied) => { new Function("$", "acct", "keys", "linkCopied", src + "; nextStep();")(id => els[id], acct, keys, linkCopied); return ["wbtn", "btn-keys", "copy-link"].filter(i => els[i].classList.has("next")).join(",") + (els["keys-hint"].hidden ? "|nohint" : "|hint"); };
  t("nextStep: not connected -> connect button pulses", run(null, null, false) === "wbtn|hint");
  t("nextStep: connected, no keys -> Derive my keys pulses, hint shown", run("0xabc", null, false) === "btn-keys|hint");
  t("nextStep: keys derived -> Copy link pulses, keys hint hidden", run("0xabc", {}, false) === "copy-link|nohint");
  t("nextStep: link copied -> nothing pulses", run("0xabc", {}, true) === "|nohint");
}
// Base log scan: window start, rate-limit retry and fail-over of the read RPCs (fail closed)
{ const HZ = await import("../web/zec-hop.js"), ST = "0x" + "ab".repeat(20), TIP = 53_400_000, base = CHAINS.base, prev = HZ.RPC_RETRY; HZ.setRpcRetry({ tries: 3, base: 1 });
  const lim = { ok: true, status: 200, json: async () => ({ error: { code: -32011, message: "request limit reached" } }) }, okR = r => ({ ok: true, status: 200, json: async () => ({ result: r }) });
  const mk = (onCall) => { const calls = []; return { calls, f: async (u, i) => { const b = JSON.parse(i.body); calls.push({ u, m: b.method, p: b.params[0] }); const r = onCall(u, b, calls); return r === undefined && b.method === "eth_blockNumber" ? okR("0x" + TIP.toString(16)) : r; } }; };
  { const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : okR([{}, {}])), n = await HZ.makeCountPriorHops(base, f)(ST), logs = calls.filter(c => c.m === "eth_getLogs");
    t("base scan starts at 31_700_000 and needs <= 12 windows (not ~27 from block 0)", HZ.PAY_FROM_BLOCK.base === 31_700_000 && parseInt(logs[0].p.fromBlock, 16) === 31_700_000 && logs.length <= 12 && logs.length === Math.ceil((TIP - 31_700_000 + 1) / HZ.LOG_SPAN) && n === 2 * logs.length); }
  { const { calls, f } = mk((u, b) => u === base.rpcs[0] ? lim : b.method === "eth_blockNumber" ? undefined : okR([{}])), n = await HZ.makeCountPriorHops(base, f)(ST);
    t("-32011 on endpoint 1 (retried, then fail-over) -> endpoint 2 answers, count is right", n === calls.filter(c => c.m === "eth_getLogs" && c.u === base.rpcs[1]).length && calls.some(c => c.u === base.rpcs[1]) && calls.filter(c => c.u === base.rpcs[0] && c.m === "eth_blockNumber").length === 3); }
  { const { calls, f } = mk(() => lim), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
    t("every endpoint rate limited -> throws (fail closed), each tried 3 times", /request limit reached/.test(e) && calls.length === 6 && calls.filter(c => c.u === base.rpcs[1]).length === 3); }
  for (const bad of [{ code: -32602, message: "Invalid params" }, { code: -32000, message: "execution reverted" }]) { const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : { ok: true, status: 200, json: async () => ({ error: bad }) }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
    t("JSON-RPC error " + bad.code + " is final: no retry, no fail-over", /failed/.test(e) && calls.length === 2 && calls.every(c => c.u === base.rpcs[0])); }
  { let k = 0; const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : ++k === 1 ? { ok: false, status: 503, json: async () => ({}) } : okR([{}])), n = await HZ.makeCountPriorHops(base, f)(ST);
    t("HTTP 503 is retried on the same endpoint and recovers", n >= 1 && calls.every(c => c.u === base.rpcs[0]) && calls.filter(c => c.m === "eth_getLogs").length === Math.ceil((TIP - 31_700_000 + 1) / HZ.LOG_SPAN) + 1); }
  { const { calls, f } = mk(u => { throw new TypeError("fetch failed"); }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
    t("network errors fail over, then throw", /fetch failed/.test(e) && calls.some(c => c.u === base.rpcs[1])); }
  { const rh = CHAINS.rh, { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? okR("0x" + (100_761_230 + 5).toString(16)) : okR(b.method === "eth_getTransactionCount" ? "0x0" : [{}])); await HZ.makeCountPriorHops(rh, f)(ST); const logs = calls.filter(c => c.m === "eth_getLogs");
    t("RH unchanged: one endpoint, scan from 100_761_230", HZ.PAY_FROM_BLOCK.rh === 100_761_230 && rh.rpcs.length === 1 && rh.rpcs[0] === rh.rpc && base.rpcs[0] === base.rpc && parseInt(logs[0].p.fromBlock, 16) === 100_761_230); }
  { const run = async (chain, tip, b0) => { const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? okR("0x" + tip.toString(16)) : okR(b.method === "eth_getTransactionCount" ? "0x0" : [])); await HZ.makeCountPriorHops(chain, f)(ST, b0); return calls.filter(c => c.m === "eth_getLogs").map(c => [parseInt(c.p.fromBlock, 16), parseInt(c.p.toBlock, 16)]); };
    const fresh = await run(base, TIP, TIP - 500), far = await run(base, TIP, 40_000_000), none = await run(base, TIP), bad = await Promise.all([null, -5, 1.5, "40000000", NaN].map(x => run(base, TIP, x))), top = await run(base, TIP, TIP + 9_000).then(() => null, e => e), small = await run(base, TIP, 50);
    t("b0 near the tip: exactly 1 getLogs call, from b0 - 100 (under publicnode's 50k cap)", fresh.length === 1 && fresh[0][0] === TIP - 600 && fresh[0][1] === TIP && fresh[0][1] - fresh[0][0] < 50_000);
    t("b0 far back (40M): windows from 40M - 100, none beyond the tip", far[0][0] === 40_000_000 - 100 && far.length === Math.ceil((TIP - 39_999_900 + 1) / HZ.LOG_SPAN) && far.at(-1)[1] === TIP);
    t("no b0 (or an unusable one): the old start, 31_700_000", none[0][0] === 31_700_000 && bad.every(w => w[0][0] === 31_700_000));
    t("1181 L-3 b0 above the tip: the endpoint is behind a block the indexer has seen -> limited (not clamped to a one-block scan that returns 0); b0 < 100 starts at 0", top && top.limited === true && /behind/.test(top.message) && small[0][0] === 0);
    const rhc = CHAINS.rh, rt = 100_761_230 + 3_000_000, rhb = await run(rhc, rt, rt - 10), rhn = await run(rhc, rt); t("RH: b0 narrows the scan, no b0 keeps the pay-contract start", rhb.length === 1 && rhb[0][0] === rt - 110 && rhn[0][0] === 100_761_230); }
  { const rows = [], by = new Map(), A1 = "0x" + "Ab".repeat(20), r = (block, v, tx) => ({ stealth: A1, block, v, tx }); CR.foldRow(rows, by, r(300, false, "e")); CR.foldRow(rows, by, r(500, true, "l")); CR.foldRow(rows, by, r(900, false, "x")); CR.foldRow(rows, by, { stealth: A1.toLowerCase(), block: 0, v: false });
    t("dedupe keeps the EARLIEST block: an unverified earlier row + a later verified row -> the verified row, b0 = the earlier block (the block-0 row folded last makes it unknown, 1180 M-1)", rows.length === 1 && rows[0].tx === "l" && rows[0].v && rows[0].b0 === null);
    const r2 = [], b2 = new Map(); CR.foldRow(r2, b2, r(700, true, "v")); CR.foldRow(r2, b2, r(200, false, "u")); CR.foldRow(r2, b2, r(0, false, "z"));
    t("dedupe: a verified row first and an earlier unverified one later -> verified kept, b0 = 200; a block-0 row folded after makes b0 unknown (null), never the minimum", r2.length === 1 && r2[0].tx === "v" && r2[0].b0 === null);
    { const f1 = (...bl) => { const R = [], B = new Map(); for (const b of bl) CR.foldRow(R, B, r(b, false, "t" + b)); return R[0].b0; };      // 1180 M-1: unknown is absorbing, in any order
      t("1180 M-1 known + known -> min, either order", f1(500, 300) === 300 && f1(300, 500) === 300 && f1(300, 300, 900) === 300);
      t("1180 M-1 a block-0 row + a later known row -> b0 null (the old code gave the later block)", f1(0, 5000) === null && f1(5000, 0) === null && f1("x", 5000) === null && f1(undefined, 5000) === null && f1(NaN, 5000) === null);
      t("1180 M-1 null stays null through 3 folds in every order", [[0, 100, 200], [100, 0, 200], [100, 200, 0], [200, 100, 0], [0, 0, 100], [100, 0, 0]].every(o => f1(...o) === null));
      const Rv = [], Bv = new Map(); CR.foldRow(Rv, Bv, r(0, false, "u")); CR.foldRow(Rv, Bv, r(900, true, "v")); t("1180 M-1 an unknown row then a verified known one: the verified row is kept, b0 still null", Rv[0].tx === "v" && Rv[0].b0 === null); }
    const r3 = [], b3 = new Map(); CR.foldRow(r3, b3, r(0, true, "k")); t("an unknown block gives b0 null (the scan falls back to the pay-contract start)", r3[0].b0 === null);
    const appSrc = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"); t("app.js passes b0 to every countPriorHops caller and folds scan rows through foldRow", /foldRow\(mine, byStealth, rec\)/.test(appSrc) && (appSrc.match(/\(f\.stealth, f\.b0\)/g) || []).length === 2 && /stealth: f\.stealth, b0: f\.b0/.test(appSrc)); }
  t("CSP connect-src lists every read endpoint", Object.values(CHAINS).every(c => c.rpcs.every(u => fs.readFileSync(new URL("../web/app.html", import.meta.url), "utf8").includes(u))));
  // audit 1180: M-3 one endpoint per count, L-1 shape checks, I-2 error classes
  { const [E1, E2] = base.rpcs, hx = n => "0x" + n.toString(16), cnt = { [E1]: 0, [E2]: 0 };
    const fake = (heads, logs, failAfter = {}) => { const calls = [], f = async (u, i) => { const b = JSON.parse(i.body); calls.push({ u, m: b.method }); const k = calls.filter(c => c.u === u).length;
      if (failAfter[u] && k > failAfter[u]) return lim; return b.method === "eth_blockNumber" ? okR(hx(heads[u])) : okR(logs[u]); }; return { calls, f }; };
    { const { calls, f } = fake({ [E1]: TIP, [E2]: TIP }, { [E1]: [{}, {}, {}], [E2]: [{}] }, { [E1]: 3 }), n = await HZ.makeCountPriorHops(base, f)(ST);
      const m = calls.filter(c => c.u === E2);
      t("1180 M-3 primary fails mid-scan -> the whole count restarts on the backup (head + every window again); nothing of the primary's answers is kept", n === m.filter(c => c.m === "eth_getLogs").length && m[0].m === "eth_blockNumber" && m.filter(c => c.m === "eth_getLogs").length === Math.ceil((TIP - 31_700_000 + 1) / HZ.LOG_SPAN)); }
    { const { calls, f } = fake({ [E1]: TIP, [E2]: TIP - 1 }, { [E1]: [{}], [E2]: [] }), n = await HZ.makeCountPriorHops(base, f)(ST);
      t("1180 M-3 the primary answers everything: the lagging backup is never called", n > 0 && calls.every(c => c.u === E1)); }
    { let k1 = 0; const calls = [], f = async (u, i) => { const b = JSON.parse(i.body); calls.push({ u, m: b.method }); if (u === E1 && b.method === "eth_blockNumber") return okR(hx(++k1 === 1 ? TIP : TIP - 5)); return b.method === "eth_blockNumber" ? okR(hx(TIP)) : okR(u === E1 ? [{}, {}] : [{}]); };
      const n = await HZ.makeCountPriorHops(base, f)(ST), w = Math.ceil((TIP - 31_700_000 + 1) / HZ.LOG_SPAN);
      t("1180 M-3 the pinned endpoint's head goes below the tip it reported -> treated as unavailable, the count restarts on the next endpoint (answers never mixed)", n === w && calls.filter(c => c.u === E2).length === w + 2); }
    { const { calls, f } = fake({ [E1]: TIP, [E2]: TIP }, { [E1]: [{}], [E2]: [{}] }, { [E1]: 1, [E2]: 1 }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
      t("1180 M-3 every endpoint fails (mid-scan) -> throws, no count", /request limit reached/.test(e)); }
    { const calls = [], f = async (u, i) => { const b = JSON.parse(i.body); calls.push({ u, m: b.method }); return okR(b.method === "eth_blockNumber" ? hx(TIP) : b.method === "eth_getTransactionCount" ? "0x2" : [{}]); }, n = await HZ.makeCountPriorHops({ ...CHAINS.rh, rpcs: ["https://a.example", "https://b.example"] }, f)(ST);
      t("1180 M-3 eth_blockNumber, getLogs and eth_getTransactionCount all go to the same endpoint", calls.every(c => c.u === "https://a.example") && calls.some(c => c.m === "eth_getTransactionCount") && n >= 3); } }
  for (const [label, ans] of [["null", null], ["empty string", ""], ["non-hex", "zz"], ["0x only", "0x"], ["number", 5]]) {
    const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? okR(ans) : okR([])), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
    t("1180 L-1 eth_blockNumber answer " + label + " -> error, never tip 0", /block number/.test(e) && !calls.some(c => c.m === "eth_getLogs")); }
  { const { f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : okR(null)), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message); t("1180 L-1 a null eth_getLogs answer throws", /logs answer/.test(e)); }
  for (const st of [502, 504, 503]) { let k = 0; const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : ++k === 1 ? { ok: false, status: st, json: async () => ({}) } : okR([{}])), n = await HZ.makeCountPriorHops(base, f)(ST);
    t("1180 I-2 HTTP " + st + " is retried on the same endpoint and recovers", n >= 1 && calls.every(c => c.u === base.rpcs[0])); }
  { const { calls, f } = mk(() => ({ ok: false, status: 502, json: async () => ({}) })), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message); t("1180 I-2 HTTP 502 everywhere -> retried, failed over, then throws", e !== null && calls.some(c => c.u === base.rpcs[1])); }
  for (const msg of ["query returned more than 10000 results", "block range is too wide", "too many results"]) { const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : { ok: true, status: 200, json: async () => ({ error: { code: -32005, message: msg } }) }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
    t("1180 I-2 -32005 '" + msg + "' is final (no retry, no fail-over)", /failed/.test(e) && calls.length === 2 && calls.every(c => c.u === base.rpcs[0])); }
  { const { calls, f } = mk((u, b) => b.method === "eth_blockNumber" ? undefined : u === base.rpcs[0] ? { ok: true, status: 200, json: async () => ({ error: { code: -32005, message: "rate limit exceeded" } }) } : okR([{}])), n = await HZ.makeCountPriorHops(base, f)(ST); t("1180 I-2 -32005 'rate limit exceeded' is still a rate limit (retry, then fail over)", n >= 1 && calls.some(c => c.u === base.rpcs[1]) && calls.filter(c => c.u === base.rpcs[0] && c.m === "eth_getLogs").length === 3); }
  // audit 1181: L-3 lagging endpoints, I-2 window cap, I-1 production wrapper
  { const [E1, E2] = base.rpcs, hx = n => "0x" + n.toString(16);
    const mkAns = (heads, o = {}) => { const calls = [], f = async (u, i) => { const b = JSON.parse(i.body); calls.push({ u, m: b.method, p: b.params }); const k = calls.filter(c => c.u === u && c.m === "eth_blockNumber").length;
      if (o.fail && o.fail(u, b, k)) return lim; if (b.method === "eth_blockNumber") return okR(hx(typeof heads[u] === "function" ? heads[u](k) : heads[u])); if (b.method === "eth_getTransactionCount") return o.pinnedErr ? { ok: true, status: 200, json: async () => ({ error: { code: -32000, message: "header not found" } }) } : okR("0x1"); return okR([{}]); }; return { calls, f }; };
    { const { calls, f } = mkAns({ [E1]: TIP, [E2]: TIP - 3 }, { fail: (u, b) => u === E1 && b.method === "eth_getLogs" }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
      t("1181 L-3 the endpoint that reported the higher tip is rate limited; the failover endpoint reports a LOWER tip -> its answer is rejected (the highest tip seen is kept), the count throws", /behind another endpoint/.test(e) && !calls.some(c => c.u === E2 && c.m === "eth_getLogs")); }
    { const { calls, f } = mkAns({ [E1]: TIP, [E2]: TIP + 2 }, { fail: (u, b) => u === E1 && b.method === "eth_getLogs" }), n = await HZ.makeCountPriorHops(base, f)(ST);
      t("1181 L-3 ...a failover endpoint with an equal or higher tip is accepted", n > 0 && calls.some(c => c.u === E2 && c.m === "eth_getLogs")); }
    { const { calls, f } = mkAns({ [E1]: TIP, [E2]: TIP }), n = await HZ.makeCountPriorHops({ ...base, eth: { assetId: "x" } }, f)(ST), c = calls.find(c => c.m === "eth_getTransactionCount");
      t("1181 L-3 the transaction count is read AT the pinned tip block, not 'latest'", c && c.p[1] === hx(TIP) && c.p[0] === ST && n > 0); }
    { const { calls, f } = mkAns({ [E1]: TIP, [E2]: TIP }, { pinnedErr: true }), e = await HZ.makeCountPriorHops({ ...base, eth: { assetId: "x" } }, f)(ST).then(() => null, e => e.message);
      t("1181 L-3 a pinned-block error is FINAL: no fallback to 'latest', no failover, the count throws", /failed/.test(e) && !calls.some(c => c.m === "eth_getTransactionCount" && c.p[1] === "latest") && calls.filter(c => c.m === "eth_getTransactionCount").length === 1 && calls.every(c => c.u === E1)); }
    { const { calls, f } = mkAns({ [E1]: 2 ** 52, [E2]: TIP }), n = await HZ.makeCountPriorHops(base, f)(ST);
      t("1181 I-2 an implausible tip (2^52 -> billions of windows) makes no getLogs call, moves to the next endpoint, and does not poison the highest tip", n > 0 && !calls.some(c => c.u === E1 && c.m === "eth_getLogs") && calls.some(c => c.u === E2 && c.m === "eth_getLogs")); }
    { const { calls, f } = mkAns({ [E1]: 2 ** 52, [E2]: 2 ** 52 }), e = await HZ.makeCountPriorHops(base, f)(ST).then(() => null, e => e.message);
      t("1181 I-2 every endpoint implausible -> throws, zero getLogs calls", /implausible/.test(e) && !calls.some(c => c.m === "eth_getLogs")); }
    { const edge = 31_700_000 + HZ.MAX_WINDOWS * HZ.LOG_SPAN, ok1 = mkAns({ [E1]: edge, [E2]: edge }), bad = mkAns({ [E1]: edge + 1, [E2]: edge + 1 });
      const n = await HZ.makeCountPriorHops(base, ok1.f)(ST), e = await HZ.makeCountPriorHops(base, bad.f)(ST).then(() => null, e => e.message);
      t("1181 I-2 exactly MAX_WINDOWS (200) windows is fine, one more is refused", n === ok1.calls.filter(c => c.m === "eth_getLogs").length && HZ.MAX_WINDOWS === 200 && /implausible/.test(e) && !bad.calls.some(c => c.m === "eth_getLogs")); }
    { const { f } = mkAns({ [E1]: TIP, [E2]: TIP }), n1 = await HZ.makeCountPriorHops(base, f)(ST, TIP - 100), n2 = await HZ.makeCountPriorHops(base, f)(ST, TIP);
      t("1181 L-3 a tip equal to b0 is fine (only a lower tip is lagging)", n1 > 0 && n2 > 0); }
    // I-1: the REAL chainRpc wrapper of app.js (extracted), with a fake fetch, feeding rpcOnce
    { const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), a = app.indexOf("const chainRpc = async"), src = app.slice(a, app.indexOf("\n", app.indexOf("throw new Error(\"the chain RPC did not answer\"); };", a)) + 1);
      const mkRpc = answer => { const log = []; const fakeFetch = async (u, init) => { log.push(u); return answer(u, init); }, walletRpc = async () => ({ ok: true, json: async () => ({ result: "0xwallet" }) });
        return { log, chainRpc: new Function("fetch", "timeoutSignal", "walletRpc", src + "; return chainRpc;")(fakeFetch, () => undefined, walletRpc) }; };
      const resp = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body, clone() { return this; } });
      { const { log, chainRpc } = mkRpc((u, i) => { const b = JSON.parse(i.body); return resp(200, b.method === "eth_blockNumber" ? { result: hx(TIP) } : { error: { code: -32005, message: "query returned more than 10000 results" } }); });
        const e = await HZ.makeCountPriorHops(base, chainRpc)(ST).then(() => null, e => e.message);
        t("1181 I-1 through the real chainRpc: a JSON-RPC size error (-32005 'more than') is FINAL on the first endpoint (no retries, no failover), as in the unit tests", /failed/.test(e) && log.length === 2 && log.every(u => u === E1)); }
      { let k = 0; const { log, chainRpc } = mkRpc((u, i) => { const b = JSON.parse(i.body); if (b.method === "eth_blockNumber") return resp(200, { result: hx(TIP) }); return ++k === 1 ? resp(502, {}) : resp(200, { result: [{}] }); });
        const n = await HZ.makeCountPriorHops(base, chainRpc)(ST);
        t("1181 I-1 through the real chainRpc: HTTP 502 is a gateway outage -> retried on the same endpoint and recovers", n >= 1 && log.every(u => u === E1)); }
      { const { log, chainRpc } = mkRpc((u, i) => resp(429, {})), e = await HZ.makeCountPriorHops(base, chainRpc)(ST).then(() => null, e => e.message);
        t("1181 I-1 through the real chainRpc: HTTP 429 everywhere -> retried, failed over to the second endpoint, then throws", e !== null && log.includes(E2) && log.filter(u => u === E1).length === 3); }
      { const { chainRpc } = mkRpc(() => { throw new TypeError("fetch failed"); }); const e = await chainRpc(E1, { method: "POST", body: "{}" }).then(() => null, e => e.message); t("1181 I-1 a network failure is still thrown as 'did not answer'", /did not answer/.test(e)); }
      { const { chainRpc } = mkRpc(() => resp(500, { error: { message: "x" } })); const r = await chainRpc(E1, { method: "POST", body: "{}" }, true); t("1181 I-1 the wallet fallback (domain separator, allowWallet) keeps the old rule: no usable result -> the wallet answers", (await r.json()).result === "0xwallet");
        const rr = await chainRpc(E1, { method: "POST", body: "{}" }); t("1181 I-1 without allowWallet the 500 answer is passed through untouched", rr.status === 500); }
      { const rp = app.slice(app.indexOf("const rpcOne = async"), app.indexOf("\n", app.indexOf("const rpcOne = async")));
        const run1 = ans => new Function("chainRpc", "C", rp + "\n; return rpcOne;")(async () => ans, { rpc: "x" })("m", []);
        t("1181 I-1 rpcOne keeps its rule: a non-ok / error / no-result answer is 'did not answer', a result is returned", await run1(resp(200, { result: "0x1" })) === "0x1" && await run1(resp(500, { result: "0x1" })).then(() => false, e => /did not answer/.test(e.message)) && await run1(resp(200, { error: { message: "e" } })).then(() => false, e => /did not answer/.test(e.message))); } }
  }
  HZ.setRpcRetry(prev); }
// audit 1181 M-1: the lost-funds "checked" mark is per chain and address
{ const app = fs.readFileSync(new URL("../web/app.js", import.meta.url), "utf8"), src = app.slice(app.indexOf("const lost = new Map()"), app.indexOf("const lostNone = new Map()"));
  const mk = key => { const st = {}, ls = { getItem: k => st[k] ?? null, setItem: (k, v) => { st[k] = v; } }; return { st, L: new Function("localStorage", "C", src + "\n; return lostSeen;")(ls, { key }) }; };
  const A = "0x" + "ab".repeat(20), r = mk("rh"), b = mk("base");
  r.L.mark(A); t("1181 M-1 a mark on rh is stored under 'rh|<stealth>'", Object.keys(JSON.parse(r.st["stealth-lost-checked"])).join() === "rh|" + A && r.L.fresh(A));
  b.st["stealth-lost-checked"] = r.st["stealth-lost-checked"]; t("1181 M-1 the mark made on rh does NOT hide the address on base", !b.L.fresh(A));
  b.L.mark(A); r.st["stealth-lost-checked"] = b.st["stealth-lost-checked"]; t("1181 M-1 ...and a mark on base does not hide it on rh (only its own chain's)", Object.keys(JSON.parse(b.st["stealth-lost-checked"])).sort().join() === ["base|" + A, "rh|" + A].sort().join());
  const old = mk("rh"), oldB = mk("base"); old.st["stealth-lost-checked"] = JSON.stringify({ [A]: Date.now() }); oldB.st["stealth-lost-checked"] = old.st["stealth-lost-checked"];
  t("1181 M-1 an old bare-address mark still counts on rh (no re-check after the update) but not on base", old.L.fresh(A) && !oldB.L.fresh(A));
  old.L.unmark(A); t("1181 M-1 unmark on rh clears both forms", !old.L.fresh(A) && Object.keys(JSON.parse(old.st["stealth-lost-checked"])).length === 0); }
console.log(fail ? "FAILED " + fail : "all passed"); process.exit(fail ? 1 : 0);
