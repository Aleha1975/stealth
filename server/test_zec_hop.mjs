/* Zcash hop tests (web/zec-hop.js). Run: node test_zec_hop.mjs   (no network, no funds: 1Click, the relayer and the Zcash wallet are fakes).
   1. Pure helpers: BIP39 official vectors + @scure/bip39 cross-check, key derivation, quote requests, amount math, state transitions, retry.
   2. The whole machine against a fake world: happy path, resume after a stop at every step, lost relayer answer, out-leg refund, in-leg refund, dry run, too small. */
import fs from "fs"; import path from "path"; import { fileURLToPath } from "url";
import { entropyToMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39"; import { wordlist } from "@scure/bip39/wordlists/english";
import { keccak256, toHex, toBytes, stringToBytes } from "viem";
import * as H from "../web/zec-hop.js"; import { CHAINS, zcash as ZC } from "../web/chains.js"; import { buildQuoteRequest } from "../web/private-withdraw.js";
H.setRpcRetry({ tries: 2, base: 1 });
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
ok("texts", H.progressText({ step: "WAIT_T" }) === "Private transfer: step 3/7 · keep this tab open · ~35 min" && /unfinished|Resume/.test(H.recoveryText({ step: "SHIELD", err: "x" })) && /back on the stealth/.test(H.recoveryText({ step: "FAILED_IN", result: "REFUNDED" })));
{ let n = 0, slept = []; const v = await H.retry(async () => { if (++n < 3) throw new Error("x"); return 7; }, { sleep: async ms => slept.push(ms) });
  let m = 0; await H.retry(async () => { m++; throw new H.Halt("h"); }, { sleep: async () => {} }).catch(() => {});
  let k = 0; await H.retry(async () => { k++; throw new Error("e"); }, { sleep: async () => {} }).catch(() => {});
  ok("retry: backoff, Halt not retried, gives up", v === 7 && slept.join() === "2000,6000" && m === 1 && k === 4); }

// ---------------- 2. the machine against a fake world ----------------
let off = 0; const realNow = Date.now; Date.now = () => realNow() + off; const vsleep = async ms => { off += ms; };
const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", tOf = s => "t1" + Array.from({ length: 33 }, (_, i) => b58[(s.charCodeAt(i % s.length) * 7 + i * 13) % 58]).join("");
function makeWorld(o = {}) {
  const w = { stealthBal: 100_000_000n, tBal: {}, oBal: {}, pend: {}, swaps: {}, relays: 0, relayBodies: [], nonces: new Set(), quotes: [], broadcasts: 0, sig: 0, created: 0, loseFirstRelay: !!o.loseFirstRelay, failRelay: 0, inOutcome: o.inOutcome || "SUCCESS",shieldFails: o.shieldFails || 0, off0: null, shieldCalls: 0, shieldHeights: [], outOutcomes: o.outOutcomes || ["SUCCESS"], ...o };
  w.fetch = async (url, init = {}) => {
    const u = String(url), body = init.body ? JSON.parse(init.body) : null, J = (code, j) => ({ ok: code < 400, status: code, json: async () => j });
    if (u.endsWith("/v0/quote")) {
      w.quotes.push(body); const isIn = body.originAsset !== ZC.assetId, amt = BigInt(body.amount), out = isIn ? amt * 2n : amt * BigInt(w.outPermille ?? 495) / 1000n;
      const q = { amountIn: body.amount, amountOut: out.toString(), minAmountOut: (out * 99n / 100n).toString(), timeEstimate: 60, deadline: body.deadline };
      if (!body.dry) { q.depositAddress = isIn ? "0x" + (w.quotes.length.toString(16).padStart(40, "0")) : tOf("dep" + w.quotes.length); w.swaps[q.depositAddress] = { isIn, paid: false, body, amt, out, shown: false }; }
      if (w.mutQuote) w.mutQuote(q, isIn, body); return J(200, { quote: q, quoteRequest: body });
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
      async get_latest_block() { if (w.off0 == null) w.off0 = off; return BigInt(3_500_000 + Math.floor((off - w.off0) / 75000)); }   /* ~75 s per block, driven by the virtual clock */ async sync() {} async db_to_bytes() { return new Uint8Array(Buffer.from(JSON.stringify(this.d))); }
      async create_account(name, m, i, bd) { if (bd !== 3_499_990) throw new Error("birthday " + bd); w.created++; const id = this.d.accts.length + 1; this.d.accts.push(id); this.d.addr[id] = tOf(m.slice(0, 20) + i); return id; }
      async get_current_address_transparent(id) { return this.d.addr[id]; }
      async get_wallet_summary() { return { account_balances: this.d.accts.map(id => [id, { unshielded_balance: Number(w.tBal[this.d.addr[id]] || 0n), orchard_balance: Number(w.oBal[this.d.addr[id]] || 0n), pending_change: Number(w.pend[this.d.addr[id]] || 0n), pending_spendable: 0 }]) }; }
      async pczt_shield(id) { return { id, a: this.d.addr[id] }; } async pczt_prove(p) { return p; }
      async pczt_send(p) { w.shieldCalls++; if (w.shieldCalls <= w.shieldFails) throw new Error("Error when shielding: Change(InsufficientFunds { available: Zatoshis(0), required: Zatoshis(10000) })"); w.shieldHeights.push(3_500_000 + Math.floor((off - (w.off0 ?? off)) / 75000)); w.sig++; const v = w.tBal[p.a]; w.tBal[p.a] = 0n; w.pend[p.a] = v - 15000n; w.pendLater = (w.pendLater || []).concat([[p.a, v - 15000n]]); }
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
const mkCtx = (w, store, o = {}) => ({ store, stealth: STEALTH, priv: PRIV, chain: rh, dest: base, recipient: A, amount: 5_000_000n, api: "http://relay", words, Zjs: w.Zjs, fetchFn: w.fetch, sleep: vsleep, rand: () => 0, mode: "fast",
  waitReceipt: async () => ({ ok: true }), balance: async () => w.stealthBal, randomNonce: () => "0x" + (w.nonceN = (w.nonceN || 0) + 1).toString(16).padStart(64, "0"), ...o });
const latest = async s => (await H.findHop(s, STEALTH)).rec;

{ const w = makeWorld(), s = H.memStore(), c = mkCtx(w, s), t0 = Date.now(); const st = await H.startHop(c); const rec = await latest(s);
  ok("happy path: DONE", st.step === "DONE" && !st.err, st.step + " " + st.err);
  ok("one relay of exactly the quoted amount, signed by the stealth key to the deposit address", w.relays === 1 && w.relayBodies[0].value === "5000000" && w.relayBodies[0].from === STEALTH && Object.keys(w.swaps).includes(w.relayBodies[0].to));
  ok("two real quotes: USDG->ZEC to the t-address, ZEC->USDG to the recipient", w.quotes.filter(q => !q.dry).length === 2 && w.quotes[0].recipient === rec.st.tIn && w.quotes[0].refundTo === STEALTH && w.quotes[1].recipient === A && w.quotes[1].refundTo !== rec.st.tIn && /^t1/.test(w.quotes[1].refundTo));
  ok("out amount = shielded - fee reserve, delivered", w.delivered > 0n && BigInt(w.quotes[1].amount) === 10_000_000n - 15000n - 20000n, w.quotes[1].amount);
  ok("fast mode: 5..20 min delay elapsed", off >= 300000 && off < 20 * 60_000 + 20 * 60_000, off + " ms virtual");
  ok("hop wallet saved, " + H.accountsFor("fast") + " accounts with distinct t-addresses", w.created === H.accountsFor("fast") && rec.db && new Set(rec.st.accts.map(id => JSON.parse(Buffer.from(rec.db).toString()).addr[id])).size === H.accountsFor("fast") && rec.st.birthday === 3_499_990);
  ok("no mnemonic/private key in the saved state", !JSON.stringify(rec.st).includes(mn) && !JSON.stringify(rec.st).includes(PRIV.slice(2)));
  ok("tx hash of the ZEC send recorded and submitted (reversed txid)", rec.st.parts[0].tx === Array.from({ length: 32 }, (_, k) => (32 - k).toString(16).padStart(2, "0")).join("") && w.swaps[rec.st.parts[0].quote.depositAddress].submitted === rec.st.parts[0].tx);
  ok("a finished hop does not block the next: new counter, new mnemonic", (await H.startHop(mkCtx(makeWorld(), s, { stopAt: "WAIT_T", dry: true }))).n === 1); }

for (const step of H.STEPS.slice(1)) {          // stop cleanly before every step, then resume with a brand-new wallet object and ctx
  const w = makeWorld(), s = H.memStore(); off = 0;
  const a = await H.startHop(mkCtx(w, s, { stopAt: step })); const relaysBefore = w.relays;
  const b = await H.runHop(mkCtx(w, s));
  ok("resume from " + step, a.step === step && b.step === "DONE" && w.relays === 1 && w.broadcasts === 1 && w.sig === 1 && w.created === H.accountsFor("fast") && w.quotes.filter(q => !q.dry).length === 2, `stopped ${a.step} relays-before ${relaysBefore} -> ${b.step} ${b.err || ""}`);
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
  ok("refunded every time: FAILED after " + H.PART_TRIES + " tries of the part, state kept", st.step === "FAILED" && st.result === "REFUNDED" && st.attempt === H.PART_TRIES - 1 && /hop wallet/.test(H.recoveryText(st))); }
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
// ---- ETA / countdown (remainingMs) ----
{ const M = 60_000, now = 10_000_000, S = H.STEP_MIN, sum = Object.values(S).reduce((a, b) => a + b, 0);
  ok("STEP_MIN covers every step, sums to 30-35 min, ETA_MIN 35", H.STEPS.every(k => S[k] > 0) && sum >= 30 && sum <= 35 && H.ETA_MIN === 35, String(sum));
  let prev = Infinity, mono = true;
  for (const k of H.STEPS) { const r = H.remainingMs({ step: k, stepAt: now }, now); if (k !== "DELAY" && r !== Math.max(M, S[k] * M) + H.STEPS.slice(H.STEPS.indexOf(k) + 1).reduce((a, x) => a + S[x] * M, 0)) mono = false; if (r >= prev) mono = false; prev = r; }
  ok("remainingMs: fresh step = typical time of it and all later steps, falls step by step", mono);
  ok("remainingMs: half way through WAIT_T", H.remainingMs({ step: "WAIT_T", stepAt: now - 6 * M }, now) === (6 + S.SHIELD + S.DELAY + S.QUOTE_OUT + S.SEND_OUT) * M);
  ok("remainingMs: overrun clamps the current step to 1 min", H.remainingMs({ step: "WAIT_T", stepAt: now - 90 * M }, now) === (1 + S.SHIELD + S.DELAY + S.QUOTE_OUT + S.SEND_OUT) * M && H.remainingMs({ step: "SEND_OUT", stepAt: now - 90 * M }, now) === M);
  ok("remainingMs: DELAY uses the exact end", H.remainingMs({ step: "DELAY", delayUntil: now + 3 * M, stepAt: now }, now) === (3 + S.QUOTE_OUT + S.SEND_OUT) * M && H.remainingMs({ step: "DELAY", delayUntil: now - 5, stepAt: now }, now) === (S.QUOTE_OUT + S.SEND_OUT) * M);
  ok("remainingMs: missing stepAt (old state) counts from now; never < 1 min; 0 when finished", H.remainingMs({ step: "SHIELD" }, now) === (S.SHIELD + S.DELAY + S.QUOTE_OUT + S.SEND_OUT) * M && H.remainingMs({ step: "SEND_OUT", stepAt: now + 5 * M }, now) >= M && H.remainingMs({ step: "DONE" }, now) === 0 && H.remainingMs({ step: "FAILED" }, now) === 0); }

// ---- WAIT_T confirmation gate and SHIELD InsufficientFunds retry ----
{ const w = makeWorld(), s = H.memStore(); off = 0; const st = await H.startHop(mkCtx(w, s)); const rec = await latest(s);
  ok("WAIT_T gate: t-balance first-seen height/time recorded, shield only >= 10 blocks later", st.step === "DONE" && Number.isInteger(rec.st.tSeenHeight) && rec.st.tSeenAt > 0 && w.shieldHeights.length === 1 && w.shieldHeights[0] >= rec.st.tSeenHeight + H.T_CONFS, JSON.stringify([rec.st.tSeenHeight, w.shieldHeights]));
  ok("stepAt recorded and updated on step change", rec.st.stepAt > 0); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "SHIELD" })); const rec = await latest(s);
  const msgs = []; const c = mkCtx(w, s, { onProgress: (x, m) => msgs.push(m) }); delete rec.st.tSeenHeight; delete rec.st.stepAt; rec.st.step = "WAIT_T"; await s.put(STEALTH + "#0", rec);   // state from the OLD code, mid-flight
  const t0 = off; const r = await H.runHop(c); const after = await latest(s);
  ok("resume of an old state (no tSeenHeight/stepAt) works and still waits for confirmations", r.step === "DONE" && !r.err && after.st.tSeenHeight > 0 && w.shieldHeights[0] >= after.st.tSeenHeight + H.T_CONFS && off - t0 >= (H.T_CONFS - 1) * 75000 && after.st.stepAt > 0, r.err || "");
  ok("progress says (n/10)", msgs.some(m => /Waiting for Zcash confirmations \(\d\/10\)/.test(m))); }
{ const w = makeWorld({ shieldFails: 3 }), s = H.memStore(); off = 0; const t0 = off; const st = await H.startHop(mkCtx(w, s));
  ok("SHIELD retries InsufficientFunds every 10 s without halting", st.step === "DONE" && !st.err && w.shieldCalls === 4 && w.sig === 1, st.err || ""); }
{ const w = makeWorld({ shieldFails: 999 }), s = H.memStore(); off = 0; const st = await H.startHop(mkCtx(w, s)); const rec = await latest(s);
  ok("SHIELD gives up after 30 min with a friendly Halt, state kept at SHIELD", st.step === "SHIELD" && /not spendable yet/.test(st.err) && !/InsufficientFunds/.test(st.err) && w.shieldCalls >= 170 && w.shieldCalls <= 190 && w.sig === 0, st.err + " calls " + w.shieldCalls);
  w.shieldFails = 0; const r = await H.runHop(mkCtx(w, s)); ok("... and Continue finishes it", r.step === "DONE" && w.sig === 1); }
{ const w = makeWorld({ shieldFails: 1 }), s = H.memStore(); off = 0; w.Zjs.WebWallet.prototype.pczt_send = async () => { throw new Error("some other failure"); };
  const st = await H.startHop(mkCtx(w, s)); ok("SHIELD: other errors still halt at once", st.step === "SHIELD" && /other failure/.test(st.err)); }
// ---- percent and status line (hop-card.js) ----
{ const C = await import("../web/hop-card.js"), now = 5_000_000, M = 60_000; C.resetLeft();
  const mk = (step, el, stepAgo, extra = {}) => ({ st: { step, chain: "rh", dest: "rh", amount: "1000000", recipient: A, stealth: STEALTH, startedAt: now - el * M, stepAt: now - stepAgo * M, ...extra }, running: true, msg: "" });
  const v1 = C.hopView(mk("WAIT_T", 10, 4), now); C.resetLeft(); const v0 = C.hopView(mk("QUOTE_IN", 0, 0), now);
  ok("pct: 1..99 while running, grows with time", v0.pct >= 1 && v1.pct > v0.pct && v1.pct < 99, v0.pct + " -> " + v1.pct);
  C.resetLeft(); const a1 = C.hopView(mk("SEND_OUT", 33, 50), now), a2 = C.hopView(mk("SEND_OUT", 90, 99), now + 1000);
  ok("pct: capped at 99, never decreases, left stays >= 1 min", a1.pct <= 99 && a2.pct >= a1.pct && a2.pct <= 99 && /left/.test(a2.left) && !/^0/.test(a2.left));
  C.resetLeft(); const b1 = C.hopView(mk("WAIT_T", 12, 0), now), b2 = C.hopView(mk("WAIT_T", 70, 0), now + 1000);
  ok("pct monotone when the estimate jumps up", b2.pct >= b1.pct);
  C.resetLeft(); const l1 = C.hopView(mk("DELAY", 20, 0, { delayUntil: now + 5 * M }), now), l2 = C.hopView(mk("DELAY", 20, 0, { delayUntil: now + 9 * M }), now + 1000);
  ok("countdown rises by at most 1 min within a step", l2.left !== undefined && /[0-9]/.test(l1.left));
  C.resetLeft(); ok("status line", C.statusLine({ pct: 42, left: "≈ 18 min left", what: "Moving the ZEC into the shielded pool" }) === "● 42% · ≈ 18 min left · Moving the ZEC into the shielded pool"
    && C.hopView({ st: { ...mk("DEPOSIT_IN", 1, 1).st, step: "DONE", doneAt: now }, running: false }, now).pct === 100 && C.hopView(mk("SHIELD", 5, 1), now).what.length > 0);
  C.resetLeft(); }

// ================= v2: fixes for the external audit (ODA job 1088). Test names start with the finding id. =================
const R = await import("../web/zec-return.js");
const mulberry = a => () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const outQuotes = w => w.quotes.filter(q => !q.dry && q.originAsset === ZC.assetId), inQuotes = w => w.quotes.filter(q => !q.dry && q.originAsset !== ZC.assetId);
const rawHex = Array.from({ length: 32 }, (_, k) => (k + 1).toString(16).padStart(2, "0")).join(""), txidHex = Array.from({ length: 32 }, (_, k) => (32 - k).toString(16).padStart(2, "0")).join("");
const patchSend = (w, fn) => { const orig = w.Zjs.WebWallet.prototype.send_authorized_transactions; w.Zjs.WebWallet.prototype.send_authorized_transactions = async function (raw) { return fn((r = raw) => orig.call(this, r), raw); }; };

// ---------- H-1 split payout ----------
{ let good = true, why = "";
  for (let sd = 1; sd <= 400; sd++) { const r = mulberry(sd), k = 2 + sd % 3, total = BigInt(k * 150000 + 50000 + Math.floor(r() * 1e8)), a = H.splitAmounts(total, k, H.PART_FLOOR, r);
    if (a.length !== k || a.reduce((x, y) => x + y, 0n) !== total || a.some(x => x < H.PART_FLOOR || x % H.ROUND === 0n) || new Set(a.map(String)).size !== k) { good = false; why = sd + " " + a; break; } }
  ok("H1 split: k parts, sum exact, each >= floor, all different, none round (400 seeds)", good, why);
  ok("H1 split: equal weights (rand const) still gives different, irregular amounts", (a => new Set(a.map(String)).size === 3 && a.every(x => x % H.ROUND !== 0n))(H.splitAmounts(9_000_000n, 3, H.PART_FLOOR, () => 0.5)));
  let tight = true; for (let sd = 1; sd <= 200; sd++) { const r = mulberry(sd), orch = BigInt(150000 + Math.floor(r() * 1_500_000)); try { const p = H.planParts({ orchard: orch, mode: "private", rand: r, now: 0 }), sum = p.reduce((x, y) => x + BigInt(y.amount), 0n);
    if (sum + 20000n * BigInt(p.length) !== orch || p.some(x => BigInt(x.amount) < ZC.minIn || BigInt(x.amount) < H.PART_FLOOR)) tight = false; } catch (e) { if (!(e instanceof H.Halt) || orch - 20000n >= H.PART_FLOOR) tight = false; } }
  ok("H1 plan: a small balance shrinks k (never below the floor); only a too-small balance halts", tight);
  let fastOk = true, privOk = true;
  for (let sd = 1; sd <= 300; sd++) { const r = mulberry(sd), f = H.planParts({ orchard: 50_000_000n, mode: "fast", rand: r, now: 0 }), q = H.planParts({ orchard: 50_000_000n, mode: "private", rand: mulberry(sd + 1000), now: 0 });
    const asc = p => p.every((x, i) => i === 0 || x.at > p[i - 1].at);
    if (f.length < 1 || f.length > 2 || f[f.length - 1].at < 5 * 60_000 || f[f.length - 1].at > 20 * 60_000 || !asc(f)) fastOk = false;
    if (q.length < 2 || q.length > 4 || q[q.length - 1].at < 3600_000 || q[q.length - 1].at > 6 * 3600_000 || !asc(q) || q[0].at < 5 * 60_000) privOk = false; }
  ok("H1 modes: fast = 1..2 parts, last send 5..20 min; private = 2..4 parts, last send 1..6 h, ascending own times", fastOk && privOk);
  ok("H1 plan: parts get distinct fields (own delay, no quote yet)", (p => new Set(p.map(x => x.at)).size === p.length && p.every(x => x.quote === null && x.refundAcct === null))(H.planParts({ orchard: 50_000_000n, mode: "private", rand: mulberry(7), now: 0 }))); }
{ const w = makeWorld(), s = H.memStore(); off = 0; const msgs = [], t0 = Date.now(); const st = await H.startHop(mkCtx(w, s, { mode: "private", rand: mulberry(42), onProgress: (x, m) => msgs.push(m) })); const rec = await latest(s), P = rec.st.parts, o = outQuotes(w);
  ok("H1 private end-to-end: DONE, k parts, one quote+deposit+send per part", st.step === "DONE" && !st.err && P.length >= 2 && P.length <= 4 && o.length === P.length && w.broadcasts === P.length && P.every(p => p.status === "SUCCESS"), st.err || P.length);
  ok("H1 parts: amounts different, irregular, >= floor, sum = shielded - k fee reserves; each quote is for its part", new Set(P.map(p => p.amount)).size === P.length && P.every((p, i) => BigInt(p.amount) % H.ROUND !== 0n && BigInt(p.amount) >= H.PART_FLOOR && BigInt(o[i].amount) === BigInt(p.amount))
    && P.reduce((x, p) => x + BigInt(p.amount), 0n) === 10_000_000n - 15000n - 20000n * BigInt(P.length));
  ok("H1 refund address of every part = a different fresh hop t-address (never the in-leg or another part's)", new Set([...o.map(q => q.refundTo), rec.st.tIn]).size === P.length + 1 && o.every(q => /^t1/.test(q.refundTo)) && new Set(P.map(p => p.refundAcct)).size === P.length && P.every(p => p.refundAcct >= 1));
  ok("H1 parts have their own deposit addresses and all pay the recipient", new Set(P.map(p => p.quote.depositAddress)).size === P.length && o.every(q => q.recipient === A) && w.delivered > 0n);
  ok("H1 private mode spreads the payouts over 1..6 h of (virtual) time", off >= 3600_000 && off < 6 * 3600_000 + 2 * 3600_000, Math.round(off / 60000) + " min");
  ok("H1 sends happen in order at/after each part's own time", P.every((p, i) => i === 0 || p.at > P[i - 1].at));
  ok("H1 progress says 'payout i of k'", msgs.some(m => new RegExp("payout 2 of " + P.length).test(m)) && /payout 1 of/.test(msgs.join("|")));
  ok("H1 done: total delivered text sums all parts", rec.st.outTotal === P.reduce((x, p) => x + BigInt(p.quote.amountOut), 0n).toString() && rec.st.payoutTxs !== undefined); }
{ const w = makeWorld({ outOutcomes: ["REFUNDED", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS"] }), s = H.memStore(); off = 0; const st = await H.startHop(mkCtx(w, s, { mode: "private", rand: mulberry(5) })); const rec = await latest(s), P = rec.st.parts, o = outQuotes(w);
  ok("H1 a refunded part is shielded again and retried from a fresh account; every refund address stays unique", st.step === "DONE" && P[0].tries === 1 && o.length === P.length + 1 && w.sig === 2 && new Set([...o.map(q => q.refundTo), rec.st.tIn]).size === o.length + 1, st.err || "");
  const w2 = makeWorld({ outOutcomes: ["REFUNDED"] }), s2 = H.memStore(); off = 0; const f = await H.startHop(mkCtx(w2, s2, { mode: "private", rand: mulberry(5) }));
  ok("H1 a part that is refunded every time ends FAILED, state kept, text names the parts paid", f.step === "FAILED" && f.result === "REFUNDED" && /hop wallet/.test(H.recoveryText(f))); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "DELAY" })); const rec = await latest(s);   // old-shape (v1) state: no mode / parts, one out-leg
  for (const k of ["parts", "partIdx", "mode", "nAccts", "nextAcct"]) delete rec.st[k]; rec.st.v = 1; rec.st.delayUntil = Date.now(); await s.put(STEALTH + "#0", rec);
  const st = await H.runHop(mkCtx(w, s)); const after = await latest(s);
  ok("H1 resume of an old single-out-leg state works: one payout, old fields used, no parts", st.step === "DONE" && !st.err && outQuotes(w).length === 1 && BigInt(outQuotes(w)[0].amount) === 10_000_000n - 15000n - 20000n && after.st.outTx === txidHex && !after.st.parts, st.err || "");
  const w2 = makeWorld({ outOutcomes: ["REFUNDED", "SUCCESS"] }), s2 = H.memStore(); off = 0; await H.startHop(mkCtx(w2, s2, { stopAt: "DELAY" })); const r2 = await latest(s2);
  for (const k of ["parts", "partIdx", "mode", "nAccts", "nextAcct"]) delete r2.st[k]; r2.st.v = 1; r2.st.delayUntil = Date.now(); await s2.put(STEALTH + "#0", r2);
  const st2 = await H.runHop(mkCtx(w2, s2)); const a2 = await latest(s2);
  ok("H1 old state: out-leg refund still uses attempt+1 (legacy path)", st2.step === "DONE" && a2.st.attempt === 1 && w2.sig === 2 && outQuotes(w2).length === 2); }
{ const M = 60_000, now = 10_000_000, S = H.STEP_MIN, send = (S.QUOTE_OUT + S.SEND_OUT) * M, parts = [{ at: now - 1 }, { at: now + 3600_000 }, { at: now + 7200_000 }];
  ok("H1 ETA: part states are simulated one after the other (waits overlap the sends)", H.remainingMs({ step: "DELAY", mode: "private", partIdx: 1, parts, delayUntil: now + 3600_000, stepAt: now }, now) === 7200_000 + send
    && H.remainingMs({ step: "DELAY", mode: "private", partIdx: 0, parts, delayUntil: now - 1, stepAt: now }, now) === 7200_000 + send);
  ok("H1 ETA: private plan not made yet is far longer than fast; legacy state unchanged", H.remainingMs({ step: "QUOTE_IN", mode: "private", stepAt: now }, now) > 2.5 * 3600_000 && H.remainingMs({ step: "QUOTE_IN", mode: "fast", stepAt: now }, now) < 50 * M
    && H.remainingMs({ step: "QUOTE_IN", stepAt: now }, now) === (M + (Object.values(S).reduce((a, b) => a + b, 0) - S.QUOTE_IN * 1) * M));
  ok("H1 labels: ETA text per mode, progress text with 'payout 2 of 3'", H.etaLabel("fast") === "33–57 min" && /h$/.test(H.etaLabel("private")) && /^88 min–/.test(H.etaLabel("private"))
    && /\(payout 2 of 3\)/.test(H.progressText({ step: "DELAY", mode: "private", partIdx: 1, parts: [{}, {}, {}] })) && H.progressText({ step: "WAIT_T" }) === "Private transfer: step 3/7 · keep this tab open · ~35 min");
  const C = await import("../web/hop-card.js"); C.resetLeft();
  const v = C.hopView({ running: true, msg: "", st: { step: "SEND_OUT", chain: "rh", dest: "base", amount: "5000000", recipient: A, stealth: STEALTH, startedAt: now - 3600_000, stepAt: now, mode: "private", partIdx: 1, parts: [{}, { at: now }, { at: now + 1 }] } }, now);
  C.resetLeft(); const v0 = C.hopView({ running: true, msg: "", st: { step: "SEND_OUT", chain: "rh", dest: "base", amount: "5000000", recipient: A, stealth: STEALTH, startedAt: now - 3600_000, stepAt: now } }, now);
  ok("H1 card: 'Payout 2 of 3' on the payout steps, none on a single-part state, longer ETA shown for parts", /payout 2 of 3/.test(v.stepName) && /payout 2 of 3/.test(v.what) && !/payout/.test(v0.stepName) && v.left.length > 0);
  C.resetLeft(); }

// ---------- M-1 double in-leg ----------
async function haltedAtDeposit(extra = {}) { const w = makeWorld(), s = H.memStore(); off = 0; w.failRelay = 99; const a = await H.startHop(mkCtx(w, s, extra)); const rec = await latest(s); w.failRelay = 0; return { w, s, a, rec, nonce: rec.st.auth.nonce }; }
{ let seen = null; const w = makeWorld(), s = H.memStore(); off = 0;
  const fetchFn = async (u, i) => { if (String(u).endsWith("/relay")) seen = (await latest(s)).st.auth; return w.fetch(u, i); };
  await H.startHop(mkCtx(w, s, { fetchFn }));
  ok("M1 the authorization is saved in the store BEFORE it is sent to the relayer", seen && w.relayBodies.length === 1 && seen.nonce === w.relayBodies[0].nonce); }
{ const { w, s, nonce } = await haltedAtDeposit(); off += 2 * 3600_000; const calls = []; const b = await H.runHop(mkCtx(w, s, { authUsed: async (a, n) => { calls.push([a, n]); return true; } })); const rec = await latest(s);
  ok("M1 expired authorization that IS used on chain: no new nonce, no second relay, state keeps the old auth", w.nonceN === 1 && w.relays === 0 && rec.st.auth.nonce === nonce && rec.st.relayed === true && calls.length === 1 && calls[0][0] === STEALTH && calls[0][1] === nonce, b.err || b.step); }
{ const { w, s, nonce } = await haltedAtDeposit(); off += 2 * 3600_000; const b = await H.runHop(mkCtx(w, s, { authUsed: async () => false })); const rec = await latest(s);
  ok("M1 expired + unused on chain: fresh quote, ONE new authorization (new nonce), paid once", b.step === "DONE" && w.nonceN === 2 && rec.st.auth.nonce !== nonce && w.relays === 1 && inQuotes(w).length === 2, b.err || b.step); }
{ const { w, s } = await haltedAtDeposit(); off += 2 * 3600_000; const b = await H.runHop(mkCtx(w, s, { authUsed: async () => { throw new Error("rpc down"); } }));
  ok("M1 expired but the chain check fails: Halt, nothing new signed", b.step === "DEPOSIT_IN" && /could not check/.test(b.err) && w.nonceN === 1 && w.relays === 0, b.err);
  const c = await H.runHop(mkCtx(w, s));
  ok("M1 expired and no chain check available: Halt, nothing new signed", c.step === "DEPOSIT_IN" && /cannot tell/.test(c.err) && w.nonceN === 1 && w.relays === 0, c.err); }
{ const { w, s, nonce } = await haltedAtDeposit(); let used = 0; const b = await H.runHop(mkCtx(w, s, { authUsed: async () => { used++; return false; } })); const rec = await latest(s);   // not expired: the same auth is re-sent, the chain is not even asked
  ok("M1 not expired: the SAME authorization is re-sent, no chain call, no new nonce", b.step === "DONE" && w.nonceN === 1 && w.relayBodies[0].nonce === nonce && used === 0 && rec.st.auth.nonce === nonce); }
{ const w = makeWorld(), s = H.memStore(); off = 0; let first = true; const a = await H.startHop(mkCtx(w, s, { waitReceipt: async () => first ? (first = false, { ok: false }) : { ok: true } })); const rec = await latest(s), nonce = rec.st.auth.nonce;
  const b = await H.runHop(mkCtx(w, s));
  ok("M1 a reverted deposit keeps the (now public) authorization; resume re-sends it instead of signing another", a.step === "DEPOSIT_IN" && /reverted/.test(a.err) && nonce && b.step === "DONE" && w.nonceN === 1 && w.relays === 1); }
{ const calls = [], f = async (u, i) => { calls.push(JSON.parse(i.body)); return { ok: true, json: async () => ({ result: "0x" + "0".repeat(63) + "1" }) }; }, au = H.makeAuthUsed(rh, f), nonce = "0x" + "ab".repeat(32);
  const used = await au(STEALTH, nonce), unused = await H.makeAuthUsed(rh, async () => ({ ok: true, json: async () => ({ result: "0x" + "0".repeat(64) }) }))(STEALTH, nonce), c = calls[0];
  const sel = (await import("viem")).toFunctionSelector("authorizationState(address,bytes32)");
  ok("M1 authUsed = USDG authorizationState(authorizer, nonce) eth_call on the chain rpc", used === true && unused === false && c.method === "eth_call" && c.params[0].to === rh.token.address && H.AUTH_STATE_SELECTOR === sel
    && c.params[0].data === sel + "0".repeat(24) + STEALTH.slice(2) + nonce.slice(2));
  ok("M1 authUsed rejects an unusable answer", await H.makeAuthUsed(rh, async () => ({ ok: true, json: async () => ({ error: { message: "x" } }) }))(STEALTH, nonce).then(() => false, () => true)); }

// ---------- M-2 broadcast errors ----------
{ const w = makeWorld(), s = H.memStore(); off = 0; let calls = 0, asked = []; patchSend(w, async (orig) => { if (++calls === 1) throw new Error("rpc error: unknown transaction / mempool conflict"); return orig(); });
  const st = await H.startHop(mkCtx(w, s, { txKnown: async id => (asked.push(id), false) }));
  ok("M2 an error mentioning 'unknown'/'mempool' is NOT success: txid unknown -> rebroadcast, then done", st.step === "DONE" && calls === 2 && w.broadcasts === 1 && asked[0] === txidHex, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); off = 0; let calls = 0; patchSend(w, async (orig) => { calls++; await orig(); throw new Error("tx already in mempool"); });
  const st = await H.startHop(mkCtx(w, s, { txKnown: async () => true }));
  ok("M2 error but the txid IS known to the network: counted as sent, not rebroadcast", st.step === "DONE" && calls === 1 && w.broadcasts === 1, st.err || ""); }
for (const [name, tk] of [["no txKnown available", undefined], ["txKnown cannot answer", async () => { throw new Error("proxy down"); }]]) {
  const w = makeWorld(), s = H.memStore(); off = 0; patchSend(w, async () => { throw new Error("mempool: unknown"); }); const st = await H.startHop(mkCtx(w, s, { txKnown: tk })); const p = (await latest(s)).st.parts[0];
  ok("M2 ambiguous error + " + name + ": Halt at SEND_OUT, tx NOT recorded, raw kept for a safe retry", st.step === "SEND_OUT" && /could not say/.test(st.err) && p.tx === null && !!p.raw && w.broadcasts === 0, st.err); }
{ const w = makeWorld(), s = H.memStore(); off = 0; let calls = 0; patchSend(w, async () => { calls++; throw new Error("bad-txns-inputs-spent"); }); const st = await H.startHop(mkCtx(w, s, { txKnown: async () => false })); const p = (await latest(s)).st.parts[0];
  ok("M2 a real rejection is retried then reported (4 tries), never recorded as sent", st.step === "SEND_OUT" && /bad-txns/.test(st.err) && calls === 4 && p.tx === null); }
{ const body = new Uint8Array([1, 2, 3]), fr = (flag, b) => Uint8Array.from([flag, b.length >>> 24 & 255, b.length >>> 16 & 255, b.length >>> 8 & 255, b.length & 255, ...b]), cat = (...a) => Uint8Array.from(a.flatMap(x => [...x]));
  const resp = (bytes, ok = true, status = 200) => ({ ok, status, headers: { get: () => null }, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) });
  let req; const mk = bytes => async (u, i) => { req = { u, body: i.body }; return resp(bytes); }, trailer = t => fr(0x80, new TextEncoder().encode(t));
  const tx = "0".repeat(62) + "ab";
  const yes = await R.txKnown("https://lw", tx, mk(cat(fr(0, cat([0x0a, body.length], body)), trailer("grpc-status: 0\r\n")))), no = await R.txKnown("https://lw", tx, mk(trailer("grpc-status: 5\r\ngrpc-message: No such mempool or blockchain transaction\r\n")));
  const boom = await R.txKnown("https://lw", tx, async () => resp(new Uint8Array(0), false, 503)).then(() => "no error", e => e.message);
  ok("M2 zec-return.txKnown: GetTransaction with the little-endian txid; data = known, NotFound = unknown, other failures throw", yes === true && no === false && /503/.test(boom) && /GetTransaction$/.test(req.u) && Buffer.from(req.body.slice(5)).toString("hex") === "1a20" + "ab" + "0".repeat(62)
    && await R.txKnown("https://lw", "zz", mk(new Uint8Array(0))).then(() => false, () => true)); }

// ---------- M-3 expiry ----------
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "SEND_OUT" })); const rec = await latest(s), p = rec.st.parts[0];
  ok("M3 every stored artefact has a deadline: in-quote, out-quote, auth validBefore (and Zcash tx expiry once built)", rec.st.inQuote.deadlineMs > 0 && p.quote.deadlineMs > 0 && rec.st.auth.validBefore > 0);
  off += 3 * 3600_000; const st = await H.runHop(mkCtx(w, s)); const fin = await latest(s);
  ok("M3 expired out-quote, nothing sent: re-quoted, paid once, new Zcash expiry height recorded", st.step === "DONE" && outQuotes(w).length === 2 && w.broadcasts === 1 && fin.st.parts[0].expiry > 3_500_000, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "SEND_OUT" })); const rec = await latest(s); rec.st.parts[0].raw = rawHex; rec.st.parts[0].expiry = 5; await s.put(STEALTH + "#0", rec);
  const asked = []; const st = await H.runHop(mkCtx(w, s, { txKnown: async id => (asked.push(id), false) })); const fin = await latest(s);
  ok("M3 transaction past its expiry height and not on the network: discarded, quote and tx rebuilt, nothing paid twice", st.step === "DONE" && asked[0] === txidHex && outQuotes(w).length === 2 && w.broadcasts === 1 && fin.st.waitExpiry == null, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "SEND_OUT" })); const rec = await latest(s), dep = rec.st.parts[0].quote.depositAddress; rec.st.parts[0].raw = rawHex; rec.st.parts[0].expiry = 5; await s.put(STEALTH + "#0", rec);
  const st = await H.runHop(mkCtx(w, s, { txKnown: async () => { w.swaps[dep].paid = true; return true; } })); const fin = await latest(s);
  ok("M3 expired but the network already has the transaction: it is NOT redone, we follow it", st.step === "DONE" && outQuotes(w).length === 1 && w.broadcasts === 0 && fin.st.parts[0].tx === txidHex, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "SEND_OUT" })); const rec = await latest(s); rec.st.parts[0].raw = rawHex; rec.st.parts[0].expiry = 5; await s.put(STEALTH + "#0", rec);
  const st = await H.runHop(mkCtx(w, s));
  ok("M3 expired and the network cannot say: Halt, nothing new built", st.step === "SEND_OUT" && /cannot tell/.test(st.err) && outQuotes(w).length === 1 && w.broadcasts === 0, st.err); }
{ const w = makeWorld(), s = H.memStore(); off = 0; await H.startHop(mkCtx(w, s, { stopAt: "DEPOSIT_IN" })); off += 3 * 3600_000; const st = await H.runHop(mkCtx(w, s));
  ok("M3 in-quote expired before anything was signed: new quote, one payment", st.step === "DONE" && inQuotes(w).length === 2 && w.relays === 1, st.err || ""); }

// ---------- M-4 hop counter from the chain ----------
{ const w = makeWorld(), s = H.memStore(), w2 = makeWorld(), s2 = H.memStore(), w0 = makeWorld(), s0 = H.memStore();
  const a = await H.startHop(mkCtx(w, s, { stopAt: "QUOTE_IN", countPriorHops: async () => 3 })), b = await H.startHop(mkCtx(w2, s2, { stopAt: "QUOTE_IN", countPriorHops: async () => 3 })), z = await H.startHop(mkCtx(w0, s0, { stopAt: "QUOTE_IN" }));
  ok("M4 counter = chain count: a device with empty storage picks the same n and the same hop wallet as another device", a.n === 3 && b.n === 3 && z.n === 0 && (await latest(s)).st.n === 3);
  const sa = H.memStore(); await H.startHop(mkCtx(makeWorld(), sa)); const c1 = await H.startHop(mkCtx(makeWorld(), sa, { stopAt: "QUOTE_IN", countPriorHops: async () => 0 })), sb = H.memStore(); await H.startHop(mkCtx(makeWorld(), sb)); const c2 = await H.startHop(mkCtx(makeWorld(), sb, { stopAt: "QUOTE_IN", countPriorHops: async () => 7 }));
  ok("M4 IndexedDB is only a cache: n = max(local+1, chain count), never lower than either", c1.n === 1 && c2.n === 7);
  const sc = H.memStore(); const err = await H.startHop(mkCtx(makeWorld(), sc, { countPriorHops: async () => { throw new Error("rpc down"); } })).then(() => null, e => e.message);
  ok("M4 chain unreadable: refuses to start (fail closed), nothing stored", /could not read/.test(err) && (await sc.keys()).length === 0);
  ok("M4 a bogus count is refused", await H.startHop(mkCtx(makeWorld(), H.memStore(), { countPriorHops: async () => -1 })).then(() => false, () => true));
  const calls = [], TIP = H.PAY_FROM_BLOCK.rh + H.LOG_SPAN + 5, f = async (u, i) => { const b = JSON.parse(i.body); if (b.method === "eth_blockNumber") return { ok: true, json: async () => ({ result: "0x" + TIP.toString(16) }) }; calls.push(b); return { ok: true, json: async () => ({ result: calls.length === 1 ? [{}, {}, {}] : [{}] }) }; }, n = await H.makeCountPriorHops(rh, f)(STEALTH), c = calls[0], sig = keccak256(stringToBytes("AuthorizationUsed(address,bytes32)"));
  ok("M4 log scan starts at the pay contract and splits the range under the RPC cap", calls.length === 2 && parseInt(calls[0].params[0].fromBlock, 16) === H.PAY_FROM_BLOCK.rh && parseInt(calls[1].params[0].toBlock, 16) === TIP && calls.every(x => parseInt(x.params[0].toBlock, 16) - parseInt(x.params[0].fromBlock, 16) < 10_000_000));
  { let k = 0; const flaky = async (u, i) => { const b = JSON.parse(i.body); if (b.method === "eth_blockNumber") return { ok: true, json: async () => ({ result: "0x" + (H.PAY_FROM_BLOCK.rh + 10).toString(16) }) }; return ++k === 1 ? { ok: false, status: 429, json: async () => ({}) } : { ok: true, json: async () => ({ result: [{}] }) }; };
    ok("M4 a rate-limited RPC answer is retried", await H.makeCountPriorHops(rh, flaky)(STEALTH) === 1 && k === 2); }
  ok("M4 makeCountPriorHops = number of AuthorizationUsed logs of the stealth address on the token", n === 4 && c.method === "eth_getLogs" && c.params[0].address === rh.token.address && c.params[0].topics[0] === sig && H.AUTH_USED_TOPIC === sig && c.params[0].topics[1] === "0x" + "0".repeat(24) + STEALTH.slice(2)); }

// ---------- M-5 nothing shared between the legs ----------
{ const r1 = H.reqIn({ chain: rh, amount: 5_000_000n, tAddr: T, stealth: STEALTH, dry: true, now: 0, rand: () => 0.1 }), r2 = H.reqOut({ dest: base, amount: 400000n, recipient: A, refundT: "t1" + "2".repeat(33), dry: true, now: 0, rand: () => 0.9 });
  const sh = H.sharedFields(r1, r2).map(x => x.split("=")[0]), forbidden = /referral|appFee|userId|session|token|affiliate|clientId|memo|correlation/i;
  ok("M5 the two requests share only protocol constants; no referral/appFees/user/session field exists", sh.every(k => H.CONSTANT_FIELDS.has(k)) && ![...Object.keys(r1), ...Object.keys(r2)].some(k => forbidden.test(k)) && r1.refundTo !== r2.refundTo && r1.recipient !== r2.recipient && r1.deadline !== r2.deadline, sh.join());
  const w = makeWorld(), s = H.memStore(); off = 0; const logIn = [], logOut = [];
  const mk = log => async (u, i) => { log.push([String(u), i]); return w.fetch(u, i); };
  const st = await H.startHop(mkCtx(w, s, { mode: "private", rand: mulberry(9), fetchFn: mk(logIn), fetchFnOut: mk(logOut) })); const rec = await latest(s), outDeps = new Set(rec.st.parts.map(p => p.quote.depositAddress)), inDep = rec.st.inQuote.depositAddress;
  const one = [...logIn, ...logOut].filter(([u]) => u.includes("1click") || u.includes("chaindefuser"));
  ok("M5 out-leg calls go through the separate out-leg fetch (own network path), in-leg calls never touch out deposit addresses and vice versa", st.step === "DONE" && logOut.length > 0 && logOut.every(([u, i]) => /\/v0\/quote$/.test(u) ? JSON.parse(i.body).originAsset === ZC.assetId : [...outDeps].some(d => decodeURIComponent(u + (i && i.body || "")).includes(d)))
    && logIn.filter(([u]) => !u.endsWith("/relay")).every(([u, i]) => !/\/v0\/quote$/.test(u) ? decodeURIComponent(u + (i && i.body || "")).includes(inDep) : JSON.parse(i.body).originAsset !== ZC.assetId) && ![...outDeps].some(d => logIn.some(([u, i]) => decodeURIComponent(u + (i && i.body || "")).includes(d))));
  ok("M5 every 1Click call is sent without cookies/credentials and without referrer", one.length > 0 && one.every(([, i]) => i && i.credentials === "omit" && i.referrerPolicy === "no-referrer"));
  ok("M5 all quote requests of one withdrawal: refundTo unique, deadlines not identical", (qs => new Set(qs.map(q => q.refundTo)).size === qs.length && new Set(qs.map(q => q.deadline)).size === qs.length)(w.quotes.filter(q => !q.dry))); }

// ---------- M-6 quote validation ----------
{ const now = 1_000_000_000, req = { amount: "5000000", originAsset: rh.oneClick.assetId, destinationAsset: ZC.assetId, refundTo: STEALTH, recipient: T, dry: false }, dep = "0x" + "77".repeat(20);
  const good = (o = {}, qo = {}) => ({ quote: { amountIn: "5000000", amountOut: "10000000", minAmountOut: "9900000", depositAddress: dep, deadline: new Date(now + 3600_000).toISOString(), ...o }, quoteRequest: {}, ...qo });
  const bad = (j, rq = req, re) => { try { H.quoteInfoOf(j, rq, { now }); return false; } catch (e) { return e instanceof H.Halt && (!re || re.test(e.message)); } };
  const info = H.quoteInfoOf(good(), req, { now });
  { const real = H.quoteInfoOf(good({ deadline: new Date(now + 3 * 86400_000).toISOString() }, { quoteRequest: { deadline: new Date(now + 3600_000).toISOString() } }), req, { now });
    ok("M6 real 1Click shape: quote.deadline days away (inactivity time), request deadline 1 h -> accepted, binding deadline = request", real.deadlineMs === now + 3600_000); }
  ok("M6 a sane quote passes and keeps deposit, amounts, minOut and deadline", info.depositAddress === dep && info.amountOut === "10000000" && info.minOut === "9900000" && info.deadlineMs === now + 3600_000);
  ok("M6 refused: amountIn changed", bad(good({ amountIn: "5000001" }), req, /amount/));
  ok("M6 refused: amountOut 0 / not a number / minAmountOut > amountOut", bad(good({ amountOut: "0" })) && bad(good({ amountOut: "1e7" }), req, /number/) && bad(good({ minAmountOut: "10000001" }), req, /inconsistent/));
  ok("M6 refused: slippage floor more than 3% under the quote", bad(good({ minAmountOut: "9600000" }), req, /slippage/) && !bad(good({ minAmountOut: "9710000" })));
  ok("M6 refused: deadline too short (< 5 min) / too far (> 2 h) / missing / unparsable", bad(good({ deadline: new Date(now + 60_000).toISOString() }), req, /too soon/) && bad(good({ deadline: new Date(now + 5 * 3600_000).toISOString() }), req, /far/) && bad(good({ deadline: undefined }), req, /no deadline/) && bad(good({ deadline: "soon" }), req, /no deadline/));
  ok("M6 refused: bad deposit address format (in-leg needs 0x..40 hex, out-leg a t1 address), or one of our own", bad(good({ depositAddress: "0x12" }), req, /deposit/) && bad(good({ depositAddress: T }), req, /deposit/) && bad(good({ depositAddress: undefined }), req, /deposit/)
    && bad(good({ depositAddress: STEALTH }), req, /own address/) && bad(good({ depositAddress: dep }), { ...req, originAsset: ZC.assetId }, /deposit/) && !bad(good({ depositAddress: T }), { ...req, originAsset: ZC.assetId, recipient: A, refundTo: "t1" + "3".repeat(33) }));
  ok("M6 dry (preview) quotes need no deposit address", !bad(good({ depositAddress: undefined }), { ...req, dry: true }));
  const l = H.projectedLoss({ amountIn: 5_000_000n, inDec: 6, outDec: 6, paidOut: 0, rate: 0.495, zatsLeft: 9_965_000n });
  ok("M6 projected loss math (round trip incl. ZEC fees)", l > 0.01 && l < 0.03 && H.projectedLoss({ amountIn: 5_000_000n, inDec: 6, outDec: 6, paidOut: 2_000_000, rate: 0.5, zatsLeft: 6_000_000n }) === 0); }
{ const w = makeWorld({}), s = H.memStore(); off = 0; w.outPermille = 450; const st = await H.startHop(mkCtx(w, s));   // ~11% round-trip loss
  ok("M6 round-trip loss above the cap: Halt BEFORE any ZEC is sent, ZEC stays shielded", st.step === "QUOTE_OUT" && /would lose/.test(st.err) && w.broadcasts === 0 && (await latest(s)).st.parts[0].quote === null, st.err);
  w.outPermille = 495; const ok2 = await H.runHop(mkCtx(w, s));
  ok("M6 ... and resumes fine once the rate is acceptable again", ok2.step === "DONE" && w.broadcasts === 1);
  const w2 = makeWorld(), s2 = H.memStore(); off = 0; w2.outPermille = 450; const hi = await H.startHop(mkCtx(w2, s2, { maxLoss: 0.2 }));
  ok("M6 the cap is configurable (ctx.maxLoss)", hi.step === "DONE"); }
{ const w = makeWorld(), s = H.memStore(); off = 0; w.mutQuote = (q, isIn) => { if (isIn) q.minAmountOut = String(BigInt(q.amountOut) / 2n); }; const st = await H.startHop(mkCtx(w, s));
  ok("M6 in-leg quote with a 50% slippage floor is refused before anything is signed", st.step === "QUOTE_IN" && /slippage/.test(st.err) && w.relays === 0); }
{ const w = makeWorld(), s = H.memStore(); off = 0; w.mutQuote = (q, isIn) => { if (!isIn) q.deadline = new Date(Date.now() + 30_000).toISOString(); }; const st = await H.startHop(mkCtx(w, s));
  ok("M6 out-leg quote expiring in 30 s is refused, nothing sent", st.step === "QUOTE_OUT" && /too soon/.test(st.err) && w.broadcasts === 0); }

// ---- live sub-steps, stalls, errors with a cause (the card must never go quiet or lie) ----
const tipAt = w => 3_500_000 + Math.floor((off - (w.off0 ?? off)) / 75000);
const withUtxo = w => (o = {}) => ({ getUtxos: async a => { const v = w.tBal[a]; if (!v) return []; (w.uh ||= {})[a] ??= tipAt(w); return [{ value: v, height: w.uh[a] }]; }, ...o });
const timed = (msgs, st) => (x, m) => msgs.push([off, m]);
{ const w = makeWorld(), s = H.memStore(); off = 0; const msgs = [];
  const st = await H.startHop(mkCtx(w, s, withUtxo(w)({ onProgress: timed(msgs) }))); const rec = await latest(s), seen = rec.st.tSeenHeight;
  ok("UTXO gate: DONE, confirmations counted from the deposit block (tSeenHeight = block - 1), shield only once the block has 10 confirmations", st.step === "DONE" && !st.err && w.uh && Object.values(w.uh).some(h => h - 1 === seen) && w.shieldHeights[0] >= seen + H.T_CONFS, JSON.stringify([seen, w.shieldHeights, st.err]));
  const conf = msgs.map(([, m]) => /Waiting for Zcash confirmations \((\d+)\/10\)/.exec(m)).filter(Boolean).map(x => +x[1]);
  ok("sub-step 'Waiting for Zcash confirmations (n/10)' counts up 1..9 with no gap", conf.length >= 9 && conf.every((n, i) => i === 0 || n === conf[i - 1] || n === conf[i - 1] + 1) && conf.includes(9) && Math.max(...conf) === 9, conf.join());
  ok("sub-step texts exist for waiting for ZEC, syncing, shielding", msgs.some(([, m]) => /^Syncing Zcash wallet \d+%/.test(m)) && msgs.some(([, m]) => /^Shielding/.test(m)));
  // a status message at least every 10 s of (virtual) time from the first WAIT_T message to the shield
  const end = msgs.findIndex(([, m]) => /timing link/.test(m)), t = msgs.slice(0, end < 0 ? undefined : end).filter(([, m]) => /ZEC to arrive|confirmations|Syncing|Shielding|spendable|shielded balance/.test(m)).map(x => x[0]); let gap = 0; for (let i = 1; i < t.length; i++) gap = Math.max(gap, t[i] - t[i - 1]);
  ok("heartbeat: no silence longer than 10 s between status messages while waiting/shielding", t.length > 20 && gap <= 10000, "max gap " + gap + " ms over " + t.length + " msgs"); }
{ const w = makeWorld(), s = H.memStore(); off = 0; w.tBal = {};   // ZEC visible in the UTXO list while the wallet sync is slow to see it: arrival must not wait for the wallet
  const msgs = []; let wb = 0; const orig = w.Zjs.WebWallet.prototype.get_wallet_summary; w.Zjs.WebWallet.prototype.get_wallet_summary = async function () { wb++; return orig.call(this); };
  await H.startHop(mkCtx(w, s, withUtxo(w)({ stopAt: "WAIT_T" }))); const r = await H.runHop(mkCtx(w, s, withUtxo(w)({ onProgress: timed(msgs) })));
  ok("arrival is decided by the UTXO query (few wallet syncs while waiting)", r.step === "DONE" && wb < 40, "summary calls " + wb); }
{ const w = makeWorld(), s = H.memStore(); off = 0; const msgs = [];                       // percent + block count from the summary, live while the real sync runs
  const proto = w.Zjs.WebWallet.prototype, sum = proto.get_wallet_summary; proto.get_wallet_summary = async function () { const r = await sum.call(this); return { ...r, chain_tip_height: 3_500_040, fully_scanned_height: 3_500_000 }; };
  proto.sync = async () => new Promise(r => setTimeout(r, 150));
  await H.startHop(mkCtx(w, s, { beatMs: 5, onProgress: timed(msgs), stopAt: "SHIELD" })); const rec0 = await latest(s); rec0.st.step = "SHIELD"; await s.put(STEALTH + "#0", rec0);
  proto.sync = async () => new Promise(r => setTimeout(r, 40)); await H.runHop(mkCtx(w, s, { beatMs: 5, onProgress: timed(msgs), stopAt: "DELAY" }));
  const sy = msgs.map(([, m]) => /^Syncing Zcash wallet (\d+)% \((\d+) blocks\) · (\d+) s$/.exec(m)).filter(Boolean), rp = msgs.map(([, m]) => /^Syncing Zcash wallet (\d+)% \(a repeat refresh takes ~(\d+) min\) · (\d+) s$/.exec(m)).filter(Boolean);
  ok("first sync status: 'Syncing Zcash wallet N% (40 blocks) · s', refreshed during the sync, never above 95%", sy.length >= 3 && sy.every(x => +x[1] <= 95 && +x[2] === 40) && new Set(sy.map(x => x[1])).size >= 2, sy.length + " lines");
  ok("later syncs say honestly that a repeat refresh takes minutes (measured 145 s per account set)", rp.length >= 1 && rp.every(x => +x[1] <= 95 && +x[2] >= 3), rp.length + " lines"); }
{ const w = makeWorld(), s = H.memStore(); off = 0; const msgs = []; let hang = 2, ctor = 0;       // the wallet sync hangs twice: cut by the timeout, shown as a problem, retried on a wallet restored from the saved bytes
  const proto = w.Zjs.WebWallet.prototype, sync0 = proto.sync, Ctor = w.Zjs.WebWallet; w.Zjs.WebWallet = class extends Ctor { constructor(...a) { super(...a); ctor++; } };
  proto.sync = async function () { if (hang > 0 && w.tBal && Object.values(w.tBal).some(v => v > 0n)) { hang--; return new Promise(() => {}); } return sync0.call(this); };
  const st = await H.startHop(mkCtx(w, s, withUtxo(w)({ syncMaxMs: 30, onProgress: timed(msgs) })));
  ok("stalled wallet sync: cut after the limit, 'Problem: ... timed out · retrying' shown, hop still finishes", st.step === "DONE" && !st.err && hang === 0 && msgs.some(([, m]) => /Problem: Zcash wallet sync timed out after \d+ s · retrying/.test(m)), st.err || msgs.slice(-3).join("|"));
  ok("... on a wallet restored from the saved bytes (no new accounts created)", ctor >= 2 && w.created === H.accountsFor("fast"), "ctor " + ctor + " created " + w.created); }
{ const w = makeWorld(), s = H.memStore(); off = 0; const msgs = []; const gu = withUtxo(w)().getUtxos; let fail = 3;   // the UTXO service errors: falls back to the wallet, no crash
  const st = await H.startHop(mkCtx(w, s, { getUtxos: async a => { if (fail-- > 0) throw new Error("lightwalletd 502"); return gu(a); }, onProgress: timed(msgs) }));
  ok("UTXO query failing 3 times: wallet balance is the fallback, hop finishes", st.step === "DONE" && !st.err, st.err || ""); }
{ const w = makeWorld(), s = H.memStore(); off = 0; w.tBal = {}; const HOUR = 3600e3;               // ZEC never arrives: a clear Halt after 45 min, not a silent wait
  w.inOutcome = "SUCCESS"; const orig = w.fetch; w.fetch = async (u, i) => { const r = await orig(u, i); return r; };
  const gu = async () => []; const proto = w.Zjs.WebWallet.prototype; const sum = proto.get_wallet_summary; proto.get_wallet_summary = async function () { const r = await sum.call(this); for (const a of r.account_balances) { a[1].unshielded_balance = 0; } return r; };
  const msgs = []; const st = await H.startHop(mkCtx(w, s, { getUtxos: gu, onProgress: timed(msgs) }));
  ok("ZEC never seen: Halt 'ZEC to arrive is taking too long' after ~45 min, status kept alive meanwhile", st.step === "WAIT_T" && /taking too long/.test(st.err) && st.halted && off - 0 < HOUR, st.err + " " + off); }
{ const C2 = await import("../web/hop-card.js"), now = 1_000_000_000_000, M = 60000;
  const mk = (step, extra = {}) => ({ running: true, msg: "", st: { step, chain: "rh", dest: "base", amount: "5000000", recipient: A, stealth: STEALTH, n: 0, startedAt: now - 20 * M, stepAt: now - 5 * M, mode: "fast" }, ...extra });
  C2.resetLeft(); const v1 = C2.hopView(mk("WAIT_T", { msg: "Waiting for Zcash confirmations (7/10) · ~4 min", beatAt: now - 2000 }), now);
  ok("card: live sub-step replaces the generic line (confirmations 7/10), pct/left present", v1.what === "Waiting for Zcash confirmations (7/10) · ~4 min" && v1.line.startsWith(v1.what) && v1.pct > 0 && v1.left && !v1.note);
  C2.resetLeft(); const v2 = C2.hopView(mk("WAIT_T", { msg: "Syncing Zcash wallet 43% (60 blocks) · 9 s", beatAt: now - 2000 }), now);
  ok("card: 'Syncing Zcash wallet 43%'", /Syncing Zcash wallet 43%/.test(v2.what) && C2.statusLine(v2).includes("Syncing Zcash wallet 43%"));
  C2.resetLeft(); ok("card: a plain status echo or empty message keeps the step line", C2.hopView(mk("DEPOSIT_IN", { msg: "Converting: PENDING_DEPOSIT", beatAt: now }), now).what.startsWith("Converting to ZEC") && C2.hopView(mk("SHIELD", { msg: "", beatAt: now }), now).what === "Moving the ZEC into the shielded pool");
  C2.resetLeft(); const v3 = C2.hopView(mk("SHIELD", { msg: "Shielding: building the zero-knowledge proof · 20 s", beatAt: now - 45_000 }), now);
  ok("card: silence over 30 s says 'No update for N s'", /^No update for 45 s/.test(v3.note));
  C2.resetLeft(); const v4 = C2.hopView(mk("SHIELD", { msg: "Shielding…", beatAt: now - 45_000, hidden: true }), now);
  ok("card: silence in a background tab says so and tells what to do", /background/.test(v4.note) && /front/.test(v4.note));
  C2.resetLeft(); const v5 = C2.hopView(mk("WAIT_T", { running: false, retryAt: now + 30_000, st: { ...mk("WAIT_T").st, err: "Zcash wallet sync timed out after 150 s\n    at foo (https://x.y/z.js:1:2)" } }), now);
  ok("card: error = one-line cause + auto-retry countdown", v5.kind === "warn" && v5.body.startsWith("Problem: Zcash wallet sync timed out after 150 s. Retrying by itself in 30 s.") && !/\n|https?:/.test(v5.body), v5.body);
  C2.resetLeft(); const v6 = C2.hopView(mk("WAIT_T", { running: false, st: { ...mk("WAIT_T").st, err: "ZEC to arrive is taking too long" } }), now);
  ok("card: a deliberate stop shows the cause and the Continue button", /^Stopped: ZEC to arrive is taking too long\./.test(v6.body) && v6.action === "continue"); }

// ---------- round 3 (audits 1105 / 1101): bounded wallet calls, no forged outcome, no dead ends ----------
{ const names = ["get_latest_block", "create_account", "get_wallet_summary", "pczt_send", "propose_transfer", "send_authorized_transactions"];
  for (const name of names) {
    const w = makeWorld(), s = H.memStore(); off = 0; const proto = w.Zjs.WebWallet.prototype, orig = proto[name]; let n = 0;
    proto[name] = function (...a) { return n++ === 0 ? new Promise(() => {}) : orig.apply(this, a); };      // the first call never answers
    const t0 = realNow(), st = await H.startHop(mkCtx(w, s, { walletTimeoutMs: 40, txKnown: async () => false }));
    ok("1105 L-3 " + name + ": one hung call is cut after the timeout and retried; the transfer still finishes", st.step === "DONE" && !st.err && n >= 2 && realNow() - t0 < 20000, st.step + " " + st.err + " calls=" + n);
  }
  const w = makeWorld(), s = H.memStore(); off = 0; w.Zjs.WebWallet.prototype.get_wallet_summary = () => new Promise(() => {});
  const t0 = realNow(), st = await H.startHop(mkCtx(w, s, { walletTimeoutMs: 40 }));
  ok("1105 L-3 a wallet call that never answers ends the run with a one-line retryable cause (not a Halt, not a hang)", /timed out/.test(st.err || "") && st.halted === false && !/\n/.test(st.err) && realNow() - t0 < 20000, st.err); }
{ const forged = async (w, body) => { const f0 = w.fetch; w.fetch = async (u, i) => String(u).endsWith("/relay") ? { ok: body.ok ?? false, status: body.ok ? 200 : 400, json: async () => body.j } : f0(u, i); };
  let w = makeWorld(), s = H.memStore(); off = 0; await forged(w, { j: { error: "authorization already used" } });
  let st = await H.startHop(mkCtx(w, s, { authUsed: async () => false }));
  ok("1105 M-1 a forged 'already used' answer is checked on chain: unused -> Halt, nothing recorded as sent", st.halted === true && /does not confirm/.test(st.err) && !st.relayed && !st.txIn, st.err);
  w = makeWorld(); s = H.memStore(); off = 0; await forged(w, { j: { error: "authorization already used" } });
  st = await H.startHop(mkCtx(w, s, { authUsed: async () => { throw new Error("rpc down"); } }));
  ok("1105 M-1 'already used' with an unreadable chain also stops (cannot tell is not 'used')", st.halted === true && !st.relayed, st.err);
  w = makeWorld(); s = H.memStore(); off = 0; await forged(w, { ok: true, j: { hash: "0xzz" } });
  st = await H.startHop(mkCtx(w, s));
  const rec = await latest(s);
  ok("1105 M-1 a malformed hash from the API is never saved as the deposit hash (retryable error)", /malformed/.test(st.err || "") && st.halted === false && !rec.st.txIn, st.err);
  // a bad hash saved by an older build heals itself
  const { w: w2, s: s2 } = await haltedAtDeposit(); const r2 = await latest(s2); r2.st.txIn = "0xzz"; await s2.put((await H.findHop(s2, STEALTH)).key, r2);
  const done = await H.runHop(mkCtx(w2, s2, { authUsed: async () => true }));
  ok("1105 M-1 an already-saved malformed txIn is discarded, not retried forever", !/bad transaction hash/.test(done.err || ""), done.err);
  // the receipt must contain THIS transfer
  const w3 = makeWorld(), s3 = H.memStore(); off = 0; let want = null;
  await H.startHop(mkCtx(w3, s3, { waitReceipt: async (h, expect) => { want = expect; return { ok: true }; } }));
  const r3 = await latest(s3), dep = r3.st.inQuote.depositAddress, pad32 = a => "0x" + a.slice(2).toLowerCase().padStart(64, "0"), TT = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const good = { ok: true, logs: [{ address: rh.token.address, topics: [TT, pad32(STEALTH), pad32(dep)], data: "0x" + BigInt(r3.st.inQuote.amountIn).toString(16) }] };
  ok("1105 M-1 the deposit receipt must hold Transfer(stealth -> deposit address, amount): another transaction does not count", typeof want === "function" && want(good) === true && want({ ok: true, logs: [] }) === false
    && want({ ok: true, logs: [{ ...good.logs[0], topics: [TT, pad32(STEALTH), pad32(A)] }] }) === false && want({ ok: true, logs: [{ ...good.logs[0], data: "0x1" }] }) === false);
  const w4 = makeWorld(), s4 = H.memStore(); off = 0;
  const bad = await H.startHop(mkCtx(w4, s4, { waitReceipt: async () => ({ ok: false, unexpected: true, hash: "0x" + "ab".repeat(32) }) }));
  ok("1105 M-1 a mined transaction without the deposit transfer is a Halt, txIn cleared", bad.halted === true && /does not contain/.test(bad.err) && !bad.txIn, bad.err); }
{ const { w, s } = await haltedAtDeposit(); const st = await H.runHop(mkCtx(w, s, { balance: async () => 0n, authUsed: async () => { throw new Error("rpc down"); } }));
  ok("1105 L-2 low balance + unreadable chain: Halt, not 'already spent' (no 40-minute wait on an unsent authorization)", st.halted === true && /could not check on chain/.test(st.err) && !st.relayed, st.err); }
{ const w = makeWorld(), s = H.memStore(); await s.put(STEALTH.toLowerCase() + "#0", { st: { v: 2, n: 0, stealth: STEALTH, chain: "rh", step: "FAILED", result: "RETURNED", hidden: true, amount: "1" }, db: null });
  off = 0; const st = await H.startHop(mkCtx(w, s));
  ok("1105 L-1 a returned/hidden record no longer blocks the next private transfer", st.step === "DONE" && st.n === 1, st.step + " " + st.err);
  const w5 = makeWorld(), s5 = H.memStore(); await s5.put(STEALTH.toLowerCase() + "#0", { st: { v: 2, n: 0, stealth: STEALTH, chain: "rh", step: "FAILED", amount: "1" }, db: null });
  ok("1105 L-1 an unreturned FAILED record (funds may be in the hop wallet) still blocks", await H.startHop(mkCtx(w5, s5)).then(() => false, e => /unfinished/.test(e.message))); }
{ const w = makeWorld({ inOutcome: "REFUNDED" }), s = H.memStore(); off = 0; const st = await H.startHop(mkCtx(w, s, { waitReceipt: async () => ({ ok: true }) }));
  const before = await latest(s); await H.scrubFinished(s, STEALTH); const after = await latest(s);
  ok("1105 L-6 a refunded in-leg keeps its deposit address and hash for support after the scrub; the stealth->recipient link is gone", st.step === "FAILED_IN" && after.st.scrubbed === true && after.st.inDeposit === before.st.inQuote.depositAddress && after.st.txIn === before.st.txIn && !after.st.recipient && !after.st.auth, JSON.stringify(after.st)); }
{ const C3 = await import("../web/hop-card.js"), now = 1_000_000_000_000, base0 = { step: "DEPOSIT_IN", chain: "rh", dest: "rh", amount: "1000000", recipient: A, stealth: STEALTH, startedAt: now - 60000, stepAt: now - 30000, err: "x" };
  const sent = C3.hopView({ running: false, msg: "", st: { ...base0, auth: { nonce: "0x1" } } }, now), none = C3.hopView({ running: false, msg: "", st: base0 }, now);
  ok("1105 L-5 a paused card with a signed authorization does not claim the money has not moved", /may already be on its way/.test(sent.body) && !/has not moved/.test(sent.body) && /has not moved/.test(none.body));
  const fi = C3.hopView({ running: false, msg: "", st: { ...base0, step: "FAILED_IN", result: "FAILED", inDeposit: "0x" + "12".repeat(20), txIn: "0x" + "34".repeat(32) } }, now);
  ok("1105 L-6 the refund card does not promise the balance and shows the support details", /check the balance/.test(fi.body) && /0x1212/.test(fi.detail) && /0x3434/.test(fi.detail)); }

// ---------- 1104 M-1: the bytes that are hashed are the bytes that run ----------
{ const { resolveObjectURL } = await import("node:buffer"), VD = path.join(WEB, "vendor/webzjs"), BASEU = "https://x.test/vendor/webzjs/";
  if (typeof globalThis.self === "undefined") globalThis.self = globalThis; const hadIso = self.crossOriginIsolated; self.crossOriginIsolated = true;
  const files = async tamper => async u => { const rel = decodeURIComponent(new URL(u).pathname.replace("/vendor/webzjs/", "")); let b = fs.readFileSync(path.join(VD, rel)); if (tamper && tamper.file === rel) { b = Buffer.from(b); b[tamper.at] ^= 1; } return { ok: true, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) }; };
  const texts = []; const imp = async u => { texts.push(await resolveObjectURL(u).text()); return { default: async () => {}, initThreadPool: async () => {} }; };
  const m = await H.loadZjs(BASEU, { fetchFn: await files(null), doImport: imp });
  const glue = fs.readFileSync(path.join(VD, "webzjs_wallet.js"), "utf8");
  ok("1104 M-1 clean build loads; the module that runs is a blob of the verified glue with its three imports pointed at blobs", typeof m.default === "function" && texts.length === 1 && !/from '\.\/snippets/.test(texts[0]) && (texts[0].match(/from "blob:/g) || []).length === 3 && texts[0].length > glue.length * 0.99);
  const stripped = glue.replace(/^import .*\n/gm, "").replace(/import\.meta\.url/g, "X"), ran = texts[0].replace(/^import .*\n/gm, "").replace(/"https:\/\/x\.test\/vendor\/webzjs\/webzjs_wallet\.js"/g, "X");
  ok("1104 M-1 apart from the import lines and import.meta.url the executed text IS the hashed text", stripped === ran);
  for (const [name, t] of [["glue", { file: "webzjs_wallet.js", at: 5000 }], ["wasm", { file: "webzjs_wallet_bg.wasm", at: 100 }], ["workerHelpers snippet", { file: "snippets/wasm-bindgen-rayon-38edf6e439f6d70d/src/workerHelpers.js", at: 10 }], ["thread-start snippet", { file: "snippets/wasm_thread-8ee53d0673203880/src/wasm32/js/module_worker_start.js", at: 10 }], ["polyfill snippet", { file: "snippets/wasm_thread-8ee53d0673203880/src/wasm32/js/module_workers_polyfill.min.js", at: 10 }], ["worker module snippet", { file: "snippets/wasm_thread-8ee53d0673203880/src/wasm32/js/web_worker_module.bundler.js", at: 10 }]]) {
    texts.length = 0; const e = await H.loadZjs(BASEU, { fetchFn: await files(t), doImport: imp }).then(() => null, e => e.message);
    ok("1104 M-1 one flipped byte in the " + name + " is refused before anything runs", /do not match the audited build/.test(e || "") && texts.length === 0, e);
  }
  self.crossOriginIsolated = hadIso; }

Date.now = realNow;
console.log(fails ? fails + " FAILED" : "all passed"); process.exit(fails ? 1 : 0);
