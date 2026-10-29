/* Zcash hop tests (web/zec-hop.js). Run: node test_zec_hop.mjs   (no network, no funds: 1Click, the relayer and the Zcash wallet are fakes).
   1. Pure helpers: BIP39 official vectors + @scure/bip39 cross-check, key derivation, quote requests, amount math, state transitions, retry.
   2. The whole machine against a fake world: happy path, resume after a stop at every step, lost relayer answer, out-leg refund, in-leg refund, dry run, too small. */
import fs from "fs"; import path from "path"; import { fileURLToPath } from "url";
import { entropyToMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39"; import { wordlist } from "@scure/bip39/wordlists/english";
import { keccak256, toHex, toBytes, stringToBytes } from "viem";
import * as H from "../web/zec-hop.js"; import { CHAINS, zcash as ZC } from "../web/chains.js"; import { buildQuoteRequest } from "../web/private-withdraw.js";
const WEB = path.join(path.dirname(fileURLToPath(import.meta.url)), "../web");
let fails = 0; const ok = (name, pass, extra = "") => { console.log((pass ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); if (!pass) fails++; };
const words = fs.readFileSync(path.join(WEB, "vendor/bip39-english.txt"), "utf8").trim().split("\n");
const rh = CHAINS.rh, base = CHAINS.base, PRIV = "0x" + "45".repeat(32), STEALTH = "0x" + "ab".repeat(20), T = "t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ", A = "0x" + "11".repeat(20);

// ---------------- 1. pure helpers ----------------
ok("word list = scure english", words.length === 2048 && words.every((w, i) => w === wordlist[i]));
const rep = (b, n) => new Uint8Array(n).fill(b);
for (const [b, m] of [[0x00, "abandon ".repeat(23) + "art"], [0x7f, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"],
  [0x80, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"], [0xff, "zoo ".repeat(23) + "vote"]])
  ok("BIP39 vector 0x" + b.toString(16).padStart(2, "0") + " x32", await H.mnemonicFromEntropy(rep(b, 32), words) === m);
for (let i = 0; i < 20; i++) { const e = crypto.getRandomValues(new Uint8Array(32)); if (await H.mnemonicFromEntropy(e, words) !== entropyToMnemonic(e, wordlist)) { ok("random entropy vs scure", false); break; } }
ok("random entropy vs scure (20)", true);
const ent = H.entropyFor(PRIV), mn = await H.mnemonicFor(PRIV, words);
ok("entropy = keccak256(tag || priv), independent computation", toHex(ent) === keccak256(Uint8Array.from([...stringToBytes(H.HOP_TAG), ...toBytes(PRIV)])));
ok("24 valid words, deterministic", mn.split(" ").length === 24 && validateMnemonic(mn, wordlist) && mn === await H.mnemonicFor(PRIV, words));
ok("golden mnemonic (frozen: changing it would orphan funds)", mn === "youth alone tissue bomb stock old thank speed tissue night ugly exchange lumber salute switch glance peanut among average exhibit parrot stove tool derive" && mn === entropyToMnemonic(ent, wordlist) && toHex(ent) === keccak256(Uint8Array.from([...stringToBytes("stealth-zec-hop/v1"), ...toBytes(PRIV)])));
ok("other key, other counter -> other mnemonic", mn !== await H.mnemonicFor("0x" + "46".repeat(32), words) && mn !== await H.mnemonicFor(PRIV, words, 1) && await H.mnemonicFor(PRIV, words, 1) !== await H.mnemonicFor(PRIV, words, 2));
ok("seed = BIP39 PBKDF2", Buffer.from(await H.mnemonicSeed(mn)).equals(Buffer.from(await mnemonicToSeed(mn))));
ok("word list hash check passes / fails", (await H.loadWords(async () => ({ text: async () => words.join("\n") + "\n" }))).length === 2048 && await H.loadWords(async () => ({ text: async () => "x" })).then(() => false, () => true));

const rin = H.reqIn({ chain: rh, amount: 5_000_000n, tAddr: T, stealth: STEALTH, dry: true, now: 0 }), rout = H.reqOut({ dest: base, amount: 400000n, recipient: A, refundT: T, dry: true, now: 0 });
ok("in request", rin.originAsset === rh.oneClick.assetId && rin.destinationAsset === "nep141:zec.omft.near" && rin.recipient === T && rin.refundTo === STEALTH && rin.amount === "5000000" && rin.dry === true && rin.refundType === "ORIGIN_CHAIN" && rin.recipientType === "DESTINATION_CHAIN");
ok("out request", rout.originAsset === "nep141:zec.omft.near" && rout.destinationAsset === base.oneClick.assetId && rout.recipient === A && rout.refundTo === T);
const same = buildQuoteRequest({ from: rh, to: { oneClick: { assetId: "x" } }, amount: 1n, recipient: A, refundTo: A, dry: true, now: 0 });
ok("same field set as the existing builder", Object.keys(same).join() === Object.keys(rin).join());
const bad = f => { try { f(); return false; } catch { return true; } };
ok("bad addresses refused", bad(() => H.reqIn({ chain: rh, amount: 1n, tAddr: A, stealth: STEALTH })) && bad(() => H.reqIn({ chain: rh, amount: 1n, tAddr: T, stealth: T })) && bad(() => H.reqOut({ dest: base, amount: 1n, recipient: A, refundT: A }))
  && bad(() => H.reqOut({ dest: base, amount: 1n, recipient: T, refundT: T })) && bad(() => H.reqIn({ chain: rh, amount: 0n, tAddr: T, stealth: STEALTH })));
ok("amount math", H.outAmount(500000n) === 480000n && H.outAmount(150000n) === 0n && H.outAmount(ZC.minIn + 20000n) === ZC.minIn && H.outAmount(ZC.minIn + 19999n) === 0n && H.outAmount(500000n, 40000n) === 460000n);
ok("size check", !H.okSize(100000n) && H.okSize(ZC.minIn + 60000n) && !H.okSize(ZC.minIn + 59999n));
ok("delay 2..10 min", H.delayMs(() => 0) === 120000 && H.delayMs(() => 0.999999) < 600000 && H.delayMs(() => 0.999999) > 599000);
ok("birthday is conservative", H.birthdayFromTime(1_000_000, 3_500_000, 1_000_000 + 75 * 10000) < 3_500_000 - 10000 && H.birthdayFromTime(0, 3_500_000, 1e9) === ZC.orchardActivation && H.birthdayFromTime(2e9, 3_500_000, 1e9) <= 3_500_000);
const st0 = H.newState({ stealth: STEALTH.toUpperCase().replace("0X", "0x"), chain: rh, dest: base, recipient: A, amount: 5n, now: 1 });
ok("transitions", H.afterIn("SUCCESS").step === "WAIT_T" && H.afterIn("REFUNDED").step === "FAILED_IN" && H.afterIn("FAILED").step === "FAILED_IN" && H.afterOut(st0, "SUCCESS").step === "DONE"
  && H.afterOut(st0, "REFUNDED").step === "WAIT_T" && H.afterOut(st0, "REFUNDED").attempt === 1 && H.afterOut({ ...st0, attempt: H.MAX_OUT - 1 }, "REFUNDED").step === "FAILED" && H.afterOut(st0, "FAILED").step === "FAILED" && st0.step === "QUOTE_IN");
ok("texts", H.progressText({ step: "WAIT_T" }) === "Private transfer: step 3/7 · keep this tab open · ~20 min" && /unfinished|Resume/.test(H.recoveryText({ step: "SHIELD", err: "x" })) && /back on the stealth/.test(H.recoveryText({ step: "FAILED_IN", result: "REFUNDED" })));
{ let n = 0, slept = []; const v = await H.retry(async () => { if (++n < 3) throw new Error("x"); return 7; }, { sleep: async ms => slept.push(ms) });
  let m = 0; await H.retry(async () => { m++; throw new H.Halt("h"); }, { sleep: async () => {} }).catch(() => {});
  let k = 0; await H.retry(async () => { k++; throw new Error("e"); }, { sleep: async () => {} }).catch(() => {});
  ok("retry: backoff, Halt not retried, gives up", v === 7 && slept.join() === "2000,6000" && m === 1 && k === 4); }

// ---------------- 2. the machine against a fake world ----------------
let off = 0; const realNow = Date.now; Date.now = () => realNow() + off; const vsleep = async ms => { off += ms; };
const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", tOf = s => "t1" + Array.from({ length: 33 }, (_, i) => b58[(s.charCodeAt(i % s.length) * 7 + i * 13) % 58]).join("");
function makeWorld(o = {}) {
  const w = { stealthBal: 100_000_000n, tBal: {}, oBal: {}, pend: {}, swaps: {}, relays: 0, relayBodies: [], nonces: new Set(), quotes: [], broadcasts: 0, sig: 0, created: 0, loseFirstRelay: !!o.loseFirstRelay, failRelay: 0, inOutcome: o.inOutcome || "SUCCESS", outOutcomes: o.outOutcomes || ["SUCCESS"], ...o };
  w.fetch = async (url, init = {}) => {
    const u = String(url), body = init.body ? JSON.parse(init.body) : null, J = (code, j) => ({ ok: code < 400, status: code, json: async () => j });
    if (u.endsWith("/v0/quote")) {
      w.quotes.push(body); const isIn = body.originAsset !== ZC.assetId, amt = BigInt(body.amount), out = isIn ? amt * 100n : amt * 10n;
      const q = { amountIn: body.amount, amountOut: out.toString(), minAmountOut: (out * 99n / 100n).toString(), timeEstimate: 60, deadline: body.deadline };
      if (!body.dry) { q.depositAddress = isIn ? "0x" + (w.quotes.length.toString(16).padStart(40, "0")) : tOf("dep" + w.quotes.length); w.swaps[q.depositAddress] = { isIn, paid: false, body, amt, out, shown: false }; }
      return J(200, { quote: q, quoteRequest: body });
    }
    if (u.includes("/v0/status")) {
      const a = decodeURIComponent(u.split("depositAddress=")[1]), s = w.swaps[a]; if (!s) return J(404, { message: "not found" });
      if (!s.paid) return J(200, { status: "PENDING_DEPOSIT" });
      const fin = s.isIn ? w.inOutcome : (w.outOutcomes[Math.min(w.outsDone || 0, w.outOutcomes.length - 1)]);
      if (!s.shown) { s.shown = true; if (s.isIn) { if (fin === "SUCCESS") w.tBal[s.body.recipient] = (w.tBal[s.body.recipient] || 0n) + s.out; else w.stealthBal += s.amt; } else { w.outsDone = (w.outsDone || 0) + 1; if (fin === "SUCCESS") w.delivered = (w.delivered || 0n) + s.out; else w.tBal[s.body.refundTo] = (w.tBal[s.body.refundTo] || 0n) + s.amt - 5000n; } }
      return J(200, { status: fin });
    }
    if (u.endsWith("/v0/deposit/submit")) { w.swaps[body.depositAddress].submitted = body.txHash; return J(200, {}); }
    if (u.endsWith("/relay")) {
      if (w.failRelay > 0) { w.failRelay--; return J(500, { error: "relayer down" }); }
      if (w.nonces.has(body.nonce)) return J(400, { error: "authorization already used" });
      w.nonces.add(body.nonce); w.relays++; w.relayBodies.push(body); const s = w.swaps[body.to]; s.paid = true; w.stealthBal -= BigInt(body.value);
      if (w.loseFirstRelay) { w.loseFirstRelay = false; return J(502, { error: "bad gateway" }); }
      return J(200, { hash: "0x" + "cd".repeat(32) });
    }
    throw new Error("unexpected fetch " + u);
  };
  w.Zjs = {
    WebWallet: class {
      constructor(net, url, a, b, db) { this.url = url; this.d = db ? JSON.parse(Buffer.from(db).toString()) : { accts: [], addr: {} }; if (url !== ZC.lightwalletd) throw new Error("wrong lightwalletd " + url); }
      async get_latest_block() { return 3_500_000n; } async sync() {} async db_to_bytes() { return new Uint8Array(Buffer.from(JSON.stringify(this.d))); }
      async create_account(name, m, i, bd) { if (bd !== 3_499_990) throw new Error("birthday " + bd); w.created++; const id = this.d.accts.length + 1; this.d.accts.push(id); this.d.addr[id] = tOf(m.slice(0, 20) + i); return id; }
      async get_current_address_transparent(id) { return this.d.addr[id]; }
      async get_wallet_summary() { return { account_balances: this.d.accts.map(id => [id, { unshielded_balance: Number(w.tBal[this.d.addr[id]] || 0n), orchard_balance: Number(w.oBal[this.d.addr[id]] || 0n), pending_change: Number(w.pend[this.d.addr[id]] || 0n), pending_spendable: 0 }]) }; }
      async pczt_shield(id) { return { id, a: this.d.addr[id] }; } async pczt_prove(p) { return p; }
      async pczt_send(p) { w.sig++; const v = w.tBal[p.a]; w.tBal[p.a] = 0n; w.pend[p.a] = v - 15000n; w.pendLater = (w.pendLater || []).concat([[p.a, v - 15000n]]); }
      async propose_transfer(id, to, v) { const a = this.d.addr[id]; if ((w.oBal[a] || 0n) < v + 15000n) throw new Error("insufficient"); return { a, to, v }; }
      async create_proposed_transactions(p, m, i) { if (m.split(" ").length !== 24 || tOf(m.slice(0, 20) + i) !== p.a) throw new Error("wrong key"); w.pr = p; return Uint8Array.from({ length: 32 }, (_, k) => k + 1); }
      async send_authorized_transactions(raw) { w.broadcasts++; if (raw.length !== 32) throw new Error("bad txids"); w.oBal[w.pr.a] -= w.pr.v + 15000n; w.swaps[w.pr.to].paid = true; }
    },
    pczt_sign: async (net, p, usk, fp) => { if (!(usk.seed.length === 64 && fp.seed.length === 64)) throw new Error("bad key material"); return p; },
    UnifiedSpendingKey: class { constructor(n, seed, i) { this.seed = seed; this.i = i; } }, SeedFingerprint: class { constructor(seed) { this.seed = seed; } },
  };
  // one confirmation after the shield: pending becomes spendable at the next sync of any wallet (fake: first call after pczt_send)
  const sum = w.Zjs.WebWallet.prototype.get_wallet_summary; w.Zjs.WebWallet.prototype.get_wallet_summary = async function () { for (const [a, v] of w.pendLater || []) { w.oBal[a] = (w.oBal[a] || 0n) + v; w.pend[a] = 0n; } w.pendLater = []; return sum.call(this); };
  return w;
}
const mkCtx = (w, store, o = {}) => ({ store, stealth: STEALTH, priv: PRIV, chain: rh, dest: base, recipient: A, amount: 5_000_000n, api: "http://relay", words, Zjs: w.Zjs, fetchFn: w.fetch, sleep: vsleep, rand: () => 0.5,
  waitReceipt: async () => ({ ok: true }), balance: async () => w.stealthBal, randomNonce: () => "0x" + (w.nonceN = (w.nonceN || 0) + 1).toString(16).padStart(64, "0"), ...o });
const latest = async s => (await H.findHop(s, STEALTH)).rec;

{ const w = makeWorld(), s = H.memStore(), c = mkCtx(w, s), t0 = Date.now(); const st = await H.startHop(c); const rec = await latest(s);
  ok("happy path: DONE", st.step === "DONE" && !st.err, st.step + " " + st.err);
  ok("one relay of exactly the quoted amount, signed by the stealth key to the deposit address", w.relays === 1 && w.relayBodies[0].value === "5000000" && w.relayBodies[0].from === STEALTH && Object.keys(w.swaps).includes(w.relayBodies[0].to));
  ok("two real quotes: USDG->ZEC to the t-address, ZEC->USDG to the recipient", w.quotes.filter(q => !q.dry).length === 2 && w.quotes[0].recipient === rec.st.tIn && w.quotes[0].refundTo === STEALTH && w.quotes[1].recipient === A && w.quotes[1].refundTo !== rec.st.tIn && /^t1/.test(w.quotes[1].refundTo));
  ok("out amount = shielded - fee reserve, delivered", w.delivered > 0n && BigInt(w.quotes[1].amount) === 500000000n - 15000n - 20000n, w.quotes[1].amount);
  ok("random delay 2..10 min elapsed", off >= 120000 && off < 20 * 60_000 + 600000, off + " ms virtual");
  ok("hop wallet saved, accounts 0.." + H.MAX_OUT + " with distinct t-addresses", w.created === 4 && rec.db && new Set(rec.st.accts.map(id => JSON.parse(Buffer.from(rec.db).toString()).addr[id])).size === 4 && rec.st.birthday === 3_499_990);
  ok("no mnemonic/private key in the saved state", !JSON.stringify(rec.st).includes(mn) && !JSON.stringify(rec.st).includes(PRIV.slice(2)));
  ok("tx hash of the ZEC send recorded and submitted (reversed txid)", rec.st.outTx === Array.from({ length: 32 }, (_, k) => (32 - k).toString(16).padStart(2, "0")).join("") && w.swaps[rec.st.outQuote.depositAddress].submitted === rec.st.outTx);
  ok("a finished hop does not block the next: new counter, new mnemonic", (await H.startHop(mkCtx(makeWorld(), s, { stopAt: "WAIT_T", dry: true }))).n === 1); }

for (const step of H.STEPS.slice(1)) {          // stop cleanly before every step, then resume with a brand-new wallet object and ctx
  const w = makeWorld(), s = H.memStore(); off = 0;
  const a = await H.startHop(mkCtx(w, s, { stopAt: step })); const relaysBefore = w.relays;
  const b = await H.runHop(mkCtx(w, s));
  ok("resume from " + step, a.step === step && b.step === "DONE" && w.relays === 1 && w.broadcasts === 1 && w.sig === 1 && w.created === 4 && w.quotes.filter(q => !q.dry).length === 2, `stopped ${a.step} relays-before ${relaysBefore} -> ${b.step} ${b.err || ""}`);
}
{ const w = makeWorld({ loseFirstRelay: true }), s = H.memStore(); const st = await H.startHop(mkCtx(w, s));       // relayer executed it but the answer was lost: the retry must not pay twice
  ok("lost relayer answer: paid once", st.step === "DONE" && w.relays === 1 && w.relayBodies.length === 1, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); w.failRelay = 99; const a = await H.startHop(mkCtx(w, s)); const rec = await latest(s);
  ok("relayer down: halted at DEPOSIT_IN with the signed authorization saved", a.step === "DEPOSIT_IN" && a.err === "relayer down" && rec.st.auth && rec.st.auth.nonce && w.relays === 0);
  const nonce = rec.st.auth.nonce; w.failRelay = 0; const b = await H.runHop(mkCtx(w, s));
  ok("resume re-sends the SAME authorization", b.step === "DONE" && w.relayBodies[0].nonce === nonce && w.relays === 1); }
{ const w = makeWorld({ outOutcomes: ["REFUNDED", "SUCCESS"] }), s = H.memStore(); const st = await H.startHop(mkCtx(w, s)); const rec = await latest(s);
  ok("out refund: ZEC back to a fresh t-address, shielded again, second attempt succeeds", st.step === "DONE" && rec.st.attempt === 1 && w.sig === 2 && w.quotes.filter(q => !q.dry && q.originAsset === ZC.assetId).length === 2, `${st.step} ${st.err || ""}`);
  const refunds = w.quotes.filter(q => q.originAsset === ZC.assetId).map(q => q.refundTo), txs = new Set(Object.keys(w.swaps).filter(a => !w.swaps[a].isIn).map(a => w.swaps[a].body.refundTo));
  ok("refund addresses are all different and differ from the in t-address", new Set([...refunds, rec.st.tIn]).size === 3 && txs.size === 2); }
{ const w = makeWorld({ outOutcomes: ["REFUNDED"] }), s = H.memStore(); const st = await H.startHop(mkCtx(w, s));
  ok("refunded every time: FAILED after " + H.MAX_OUT + " attempts, state kept", st.step === "FAILED" && st.result === "REFUNDED" && st.attempt === H.MAX_OUT - 1 && /hop wallet/.test(H.recoveryText(st))); }
{ const w = makeWorld({ inOutcome: "REFUNDED" }), s = H.memStore(); const st = await H.startHop(mkCtx(w, s));
  ok("in-leg refund: FAILED_IN, stealth got its money back, no ZEC steps", st.step === "FAILED_IN" && w.stealthBal === 100_000_000n && w.sig === 0 && w.broadcasts === 0); }
{ const w = makeWorld(), s = H.memStore(); const st = await H.startHop(mkCtx(w, s, { dry: true, stopAt: "WAIT_T" })); const rec = await latest(s);
  ok("dry hop reaches WAIT_T with a valid t-address, never relays", st.step === "WAIT_T" && /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(rec.st.tIn) && w.relays === 0 && w.quotes.every(q => q.dry) && w.quotes.length === 1);
  const again = await H.runHop(mkCtx(w, s, { dry: true })); ok("a dry hop cannot go further", again.step === "WAIT_T" && /dry/.test(again.err) && w.relays === 0 && w.sig === 0); }
{ const w = makeWorld(), s = H.memStore(); const st = await H.startHop(mkCtx(w, s, { amount: 1_000n })); ok("too small: halted before any relay", st.step === "QUOTE_IN" && /too small/.test(st.err) && w.relays === 0 && !(await latest(s)).st.inQuote); }
{ const w = makeWorld(), s = H.memStore(); await H.startHop(mkCtx(w, s, { stopAt: "SHIELD" }));
  ok("a second hop from the same address is refused while one is unfinished", await H.startHop(mkCtx(w, s)).then(() => false, e => /unfinished/.test(e.message))); }
{ const w = makeWorld(), s = H.memStore(); w.stealthBal = 0n; await H.startHop(mkCtx(w, s, { stopAt: "DEPOSIT_IN" })); const rec = await latest(s); rec.st.auth = { validBefore: 1, nonce: "0x01" }; await s.put(STEALTH + "#0", rec);
  const st = await H.runHop(mkCtx(w, s)); ok("expired auth + stealth already debited: no second signature/relay", w.relays === 0 && st.step === "DEPOSIT_IN", st.err || st.step); }
Date.now = realNow;
console.log(fails ? fails + " FAILED" : "all passed"); process.exit(fails ? 1 : 0);
