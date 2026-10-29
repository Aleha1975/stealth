/* Hidden Zcash hop for the private withdraw: stealth USDG -> (NEAR Intents) -> ZEC t-addr of a throw-away wallet -> shield -> random delay -> Orchard -> (NEAR Intents) -> recipient.
   One resumable state machine per withdrawal, persisted in IndexedDB together with the wallet bytes. Pure helpers first, IO below.
   Keys: the hop wallet's BIP39 mnemonic = f(stealthPriv, n) (see entropyFor), so every coin is recoverable from keys the user already has.
   Accounts 0..MAX_OUT of that wallet: account i holds the funds of out-attempt i, account i+1's t-address is that attempt's refund address (no address is used twice).
   Nothing here touches the DOM. Injected: fetchFn, sleep, store, loadZjs (WebZjs), words, waitReceipt, balance, rand, onProgress. */
import { keccak, unhex, hex } from "./stealth-crypto.js";
import * as PW from "./private-withdraw.js";
import { zcash as ZC } from "./chains.js";

export const STEPS = ["QUOTE_IN", "DEPOSIT_IN", "WAIT_T", "SHIELD", "DELAY", "QUOTE_OUT", "SEND_OUT"];
export const DONE_STEPS = new Set(["DONE", "FAILED_IN", "FAILED"]);
export const HOP_TAG = "stealth-zec-hop/v1", MAX_OUT = 3, PENDING = "PENDING_DEPOSIT", ETA_MIN = 20;
export const WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
export const SHIELD_FEE = 15000n, DRY_T = "t1ZeyyQnfsDVuLZNDGxsNbwpcseoFVkz5sJ";   // DRY_T: any valid t-address, used only in dry (preview) quotes
const RESERVE = 20000n, MIN_SHIELD = 20000n;       // zatoshi: kept back for the out fee (ZIP-317 ~15000) / dust threshold / shield fee
export class Halt extends Error {}                                      // stop and show: no automatic retry, the user can resume
const enc = s => new TextEncoder().encode(s), isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), isT = a => /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(a || "");
const sha256 = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const sleepMs = ms => new Promise(r => setTimeout(r, ms));

// ---------------------------------------------------------------- pure helpers
/** 32 bytes = keccak256(tag || stealthPriv). n > 0 (a second hop from the same address, e.g. after a partial withdraw) uses tag + ":" + n, so no mnemonic is ever reused. */
export const entropyFor = (priv, n = 0) => keccak(Uint8Array.from([...enc(HOP_TAG + (n ? ":" + n : "")), ...unhex(priv)])).slice(0, 32);
/** BIP39 (English) 24 words from 32 bytes of entropy: 256 bits + first 8 bits of sha256 = 264 bits = 24 x 11. */
export async function mnemonicFromEntropy(ent, words) {
  if (ent.length !== 32 || words.length !== 2048) throw new Error("need 32 bytes and the 2048-word list");
  let bits = ""; for (const b of [...ent, (await sha256(ent))[0]]) bits += b.toString(2).padStart(8, "0");
  return Array.from({ length: 24 }, (_, i) => words[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]).join(" ");
}
export const mnemonicFor = async (priv, words, n = 0) => mnemonicFromEntropy(entropyFor(priv, n), words);
/** BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, no passphrase): only needed to sign the shield PCZT. */
export async function mnemonicSeed(m) {
  const k = await crypto.subtle.importKey("raw", enc(m.normalize("NFKD")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt: enc("mnemonic"), iterations: 2048 }, k, 512));
}
export async function loadWords(fetchFn = fetch, url = new URL("./vendor/bip39-english.txt", import.meta.url)) {
  const t = await (await fetchFn(url)).text();
  if (hex(await sha256(enc(t))).slice(2) !== WORDLIST_SHA256) throw new Error("the BIP39 word list does not match its pinned hash");
  return t.trim().split("\n");
}
const reqOf = ({ originAsset, destAsset, amount, recipient, refundTo, dry, now = Date.now() }) => {
  if (!(amount > 0n)) throw new Error("bad amount");
  return { dry: !!dry, swapType: "EXACT_INPUT", slippageTolerance: 100, originAsset, depositType: "ORIGIN_CHAIN", destinationAsset: destAsset, amount: amount.toString(), refundTo,
    refundType: "ORIGIN_CHAIN", recipient, recipientType: "DESTINATION_CHAIN", deadline: new Date(now + 3600_000).toISOString(), confidentiality: "public" };
};
/** In-leg: chain stablecoin -> ZEC paid to the hop's t-address; refund goes back to the stealth address. */
export function reqIn({ chain, amount, tAddr, stealth, dry, now }) {
  if (!chain.oneClick || !isT(tAddr) || !isAddr(stealth)) throw new Error("bad address");
  return reqOf({ originAsset: chain.oneClick.assetId, destAsset: ZC.assetId, amount, recipient: tAddr, refundTo: stealth, dry, now });
}
/** Out-leg: ZEC -> stablecoin on `dest` to the final recipient; a ZEC-origin refund must be a Zcash t-address (a fresh one of the hop wallet). */
export function reqOut({ dest, amount, recipient, refundT, dry, now }) {
  if (!dest.oneClick || !isAddr(recipient) || !isT(refundT)) throw new Error("bad address");
  return reqOf({ originAsset: ZC.assetId, destAsset: dest.oneClick.assetId, amount, recipient, refundTo: refundT, dry, now });
}
export const outAmount = (orchard, reserve = RESERVE) => (orchard - reserve >= ZC.minIn ? orchard - reserve : 0n);
export const okSize = zatsOut => zatsOut >= ZC.minIn + SHIELD_FEE + RESERVE + 25000n;     // the ZEC we will get must survive the shield fee, the out reserve and still reach the 1Click minimum
export const delayMs = (rand = Math.random) => Math.floor((2 + 8 * rand()) * 60_000);       // 2..10 min
/** Conservative (too early) Zcash height for a unix time: assumes 60 s blocks (real ~75 s) and 500 blocks of slack. */
export const birthdayFromTime = (tSec, tip, nowSec = Date.now() / 1000) => Math.max(ZC.orchardActivation, tip - Math.ceil(Math.max(0, nowSec - tSec) / 60) - 500);
export const newState = ({ stealth, chain, dest, recipient, amount, dry, n = 0, now = Date.now() }) => ({ v: 1, n, stealth: stealth.toLowerCase(), chain: chain.key, dest: dest.key, recipient, amount: amount.toString(),
  dry: !!dry, step: "QUOTE_IN", attempt: 0, reserve: RESERVE.toString(), startedAt: now, err: null });
export const afterIn = status => (status === "SUCCESS" ? { step: "WAIT_T" } : { step: "FAILED_IN", result: status });
export const afterOut = (st, status) => status === "SUCCESS" ? { step: "DONE" }
  : status === "REFUNDED" && st.attempt + 1 < MAX_OUT ? { step: "WAIT_T", attempt: st.attempt + 1, outQuote: null, outRaw: null, outTx: null }   // ZEC came back to account attempt+1's t-address: shield and send again
  : { step: "FAILED", result: status };
export const progressText = st => DONE_STEPS.has(st.step) ? (st.step === "DONE" ? "Private transfer done" : "Private transfer stopped") : "Private transfer: step " + (STEPS.indexOf(st.step) + 1) + "/" + STEPS.length + " · keep this tab open · ~" + ETA_MIN + " min";
export function recoveryText(st) {
  if (st.step === "DONE") return "Done.";
  if (st.step === "FAILED_IN") return "The first swap ended as " + st.result + ". The money is back on the stealth address (minus the refund fee).";
  if (st.step === "FAILED") return "The last swap ended as " + st.result + (st.outQuote ? " (deposit address " + st.outQuote.depositAddress + ")" : "") + ". Any ZEC left is in the hop wallet, which you can rebuild from this payment's key.";
  return (st.err ? st.err + ". " : "") + "Nothing is lost: press Resume to continue from step " + (STEPS.indexOf(st.step) + 1) + "/" + STEPS.length + ".";
}
export async function retry(fn, { tries = 4, base = 2000, sleep = sleepMs } = {}) {
  for (let i = 1; ; i++) try { return await fn(); } catch (e) { if (e instanceof Halt || i >= tries) throw e; await sleep(base * 3 ** (i - 1)); }
}

// ---------------------------------------------------------------- storage: key = "<stealth>#<n>", value = { st, db } (db = wallet bytes)
export function idbStore(name = "stealth-zec-hop") {
  let dbp; const open = () => dbp ||= new Promise((res, rej) => { const r = indexedDB.open(name, 1); r.onupgradeneeded = () => r.result.createObjectStore("hops"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  const run = (mode, f) => open().then(db => new Promise((res, rej) => { const t = db.transaction("hops", mode), q = f(t.objectStore("hops")); t.oncomplete = () => res(q.result); t.onerror = () => rej(t.error); }));
  return { get: k => run("readonly", s => s.get(k)), put: (k, v) => run("readwrite", s => s.put(v, k)), keys: () => run("readonly", s => s.getAllKeys()) };
}
export const memStore = () => { const m = new Map(); return { get: async k => m.get(k) && structuredClone(m.get(k)), put: async (k, v) => void m.set(k, structuredClone(v)), keys: async () => [...m.keys()] }; };
/** Latest hop record of a stealth address, or null. */
export async function findHop(store, stealth) {
  const p = stealth.toLowerCase() + "#", ks = (await store.keys()).filter(k => k.startsWith(p)).sort((a, b) => Number(a.slice(p.length)) - Number(b.slice(p.length)));
  return ks.length ? { key: ks[ks.length - 1], rec: await store.get(ks[ks.length - 1]) } : null;
}
export async function startHop(ctx) {
  const old = await findHop(ctx.store, ctx.stealth);
  if (old && !["DONE", "FAILED_IN"].includes(old.rec.st.step)) throw new Error("an earlier private transfer from this address is unfinished: resume it first");
  const n = old ? old.rec.st.n + 1 : 0, st = newState({ ...ctx, n });
  await ctx.store.put(ctx.stealth.toLowerCase() + "#" + n, { st, db: null });
  return runHop(ctx);
}
export async function loadZjs(base = new URL("./vendor/webzjs/", import.meta.url)) {
  if (!self.crossOriginIsolated) throw new Error("this page is not cross-origin isolated (COOP/COEP), so the Zcash wallet cannot run here");
  const m = await import(new URL("webzjs_wallet.js", base)); await m.default(); await m.initThreadPool(Math.min(4, navigator.hardwareConcurrency || 2)); return m;
}
let zjsP; export const sharedZjs = () => zjsP ||= loadZjs().catch(e => { zjsP = null; throw e; });

// ---------------------------------------------------------------- the machine
/** ctx: { store, stealth, priv, chain, dest, recipient, amount, dry, stopAt, api, words, loadZjs, fetchFn, sleep, rand, base, waitReceipt(hash)->{ok}, balance()->BigInt, randomNonce(), onProgress(st,msg) }
 *  Returns the state. st.err set = halted (resume = call runHop again); DONE_STEPS = finished. */
export async function runHop(ctx) {
  const { store, fetchFn = fetch, sleep = sleepMs, base = PW.ONECLICK } = ctx, found = await findHop(store, ctx.stealth);
  if (!found) throw new Error("no private transfer to resume"); const { key, rec } = found, st = rec.st;
  const mn = await mnemonicFor(ctx.priv, ctx.words, st.n || 0), say = m => ctx.onProgress && ctx.onProgress(st, m), save = () => store.put(key, rec);
  const go = async (step, patch = {}) => { Object.assign(st, patch, { step }); await save(); };
  let W = null, Z = null;
  const wallet = async () => {                                   // restore from the saved bytes, or create accounts 0..MAX_OUT at the stored birthday (re-creating gives the same addresses)
    if (W) return W; Z = ctx.Zjs || (ctx.Zjs = await ctx.loadZjs());
    W = new Z.WebWallet(ZC.network, ZC.lightwalletd, 1, 1, rec.db || null);
    if (!rec.db) {
      if (st.birthday == null) { st.birthday = Number(await retry(() => W.get_latest_block())) - 10; await save(); }
      st.accts = []; for (let i = 0; i <= MAX_OUT; i++) st.accts.push(await W.create_account("hop" + i, mn, i, st.birthday));
      rec.db = await W.db_to_bytes(); await save();
    }
    return W;
  };
  const saveWallet = async () => { rec.db = await W.db_to_bytes(); await save(); };
  const bal = async i => {                                       // sync, then the balances of account i
    const w = await wallet(); await retry(() => w.sync());
    const e = ((await w.get_wallet_summary()).account_balances.find(x => x[0] === st.accts[i]) || [0, {}])[1];
    return { t: BigInt(e.unshielded_balance || 0), o: BigInt(e.orchard_balance || 0), p: BigInt(e.pending_change || 0) + BigInt(e.pending_spendable || 0) };
  };
  const taddr = async i => (await wallet()).get_current_address_transparent(st.accts[i]);
  const until = async (what, ms, fn, every = 20000) => { const t0 = Date.now(); for (;;) { if (await fn()) return; if (Date.now() - t0 > ms) throw new Halt(what + " is taking too long"); say("Waiting for " + what + "…"); await sleep(every); } };
  const status = async a => { const r = await fetchFn(base + "/v0/status?depositAddress=" + encodeURIComponent(a), { cache: "no-store" }).catch(() => null); return r && r.ok ? (await r.json().catch(() => ({}))).status || PENDING : PENDING; };
  const poll = async (a, label, ms) => { try { return await PW.pollStatus({ base, depositAddress: a, fetchFn, sleep, intervalMs: 4000, timeoutMs: ms, onUpdate: s => say(label + ": " + s.status) }); } catch (e) { throw new Halt(e.message); } };
  const quoteInfo = j => ({ depositAddress: j.quote.depositAddress || null, amountIn: j.quote.amountIn, amountOut: j.quote.amountOut, minOut: j.quote.minAmountOut || j.quote.amountOut,
    deadlineMs: Date.parse(j.quote.deadline || (j.quoteRequest || {}).deadline) || Date.now() + 3000_000 });
  const relay = async () => {
    if (st.dry) throw new Error("dry run never calls the relayer");
    const r = await fetchFn(ctx.api + "/relay", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(st.auth) }), d = await r.json().catch(() => ({}));
    if (r.ok && d.hash) return d.hash;
    if (/already used/.test(d.error || "")) return null;         // this very authorization was sent before: the transfer exists
    throw new Error(d.error || "relayer error");
  };
  const H = {
    async QUOTE_IN() {
      if (!st.inQuote) {
        const tIn = await taddr(0), j = await PW.requestQuote({ base, fetchFn, req: reqIn({ chain: ctx.chain, amount: BigInt(st.amount), tAddr: tIn, stealth: st.stealth, dry: st.dry }) });
        if (!okSize(BigInt(j.quote.amountOut))) throw new Halt("too small for the Zcash route: it would deliver only " + j.quote.amountOut + " zatoshi; nothing was sent");
        st.tIn = tIn; st.inQuote = quoteInfo(j); await save();
      }
      await go("DEPOSIT_IN");
    },
    async DEPOSIT_IN() {
      if (st.dry) return go("WAIT_T");                           // dry hops never sign or relay
      const q = st.inQuote;
      if (!st.relayed) {
        if ((await status(q.depositAddress)) === PENDING) {      // not seen by 1Click yet
          if (!st.auth && Date.now() > q.deadlineMs - 120_000) return go("QUOTE_IN", { inQuote: null });      // quote nearly expired and nothing signed: start over
          const spent = st.auth && !st.txIn && ctx.balance && (await ctx.balance()) < BigInt(q.amountIn);       // authorization used but the answer got lost
          if (!spent) {
            if (!st.auth || (!st.txIn && st.auth.validBefore * 1000 < Date.now() + 120_000)) {
              st.auth = PW.signTransferAuth({ chain: ctx.chain, priv: ctx.priv, from: st.stealth, to: q.depositAddress, value: BigInt(q.amountIn), validBefore: Math.floor(Date.now() / 1000) + 3600, nonce: ctx.randomNonce() });
              await save();                                      // recorded BEFORE it can leave the device
            }
            if (!st.txIn) { say("Sending through the relayer…"); st.txIn = await relay(); await save(); }
            if (st.txIn) {
              if (!(await ctx.waitReceipt(st.txIn)).ok) { st.auth = st.txIn = null; await save(); throw new Halt("the deposit transfer reverted; nothing moved"); }
              await PW.submitDeposit({ base, txHash: st.txIn, depositAddress: q.depositAddress, fetchFn }).catch(() => {});
            }
          }
        }
        st.relayed = true; await save();
      }
      const fin = await poll(q.depositAddress, "Swap to ZEC", 40 * 60_000); await go(afterIn(fin.status).step, afterIn(fin.status));
    },
    async WAIT_T() {
      const need = st.attempt ? MIN_SHIELD : BigInt(st.inQuote.minOut) * 9n / 10n;
      await until("ZEC to arrive", 45 * 60_000, async () => { const b = await bal(st.attempt); return b.t >= need || b.o >= ZC.minIn; });
      await go("SHIELD");
    },
    async SHIELD() {
      const i = st.attempt, b = await bal(i);
      if (b.t >= MIN_SHIELD) {                                   // the transparent coins are still there: shield (once sent they are no longer spendable, so a resume skips this)
        say("Shielding…"); const w = await wallet(), seed = await mnemonicSeed(mn);
        let p = await w.pczt_shield(st.accts[i]);
        p = await Z.pczt_sign(ZC.network, p, new Z.UnifiedSpendingKey(ZC.network, seed, i), new Z.SeedFingerprint(seed));
        await w.pczt_send(await w.pczt_prove(p, null)); await saveWallet();
      }
      await until("the shielded balance (1 confirmation)", 40 * 60_000, async () => { const x = await bal(i); await saveWallet(); return x.o >= ZC.minIn && x.p === 0n && x.t < MIN_SHIELD; }, 15000);
      await go("DELAY", { delayUntil: Date.now() + delayMs(ctx.rand) });
    },
    async DELAY() {
      while (Date.now() < st.delayUntil) { say("Waiting " + Math.ceil((st.delayUntil - Date.now()) / 1000) + " s to break the timing link…"); await sleep(Math.min(5000, st.delayUntil - Date.now())); }
      await go("QUOTE_OUT");
    },
    async QUOTE_OUT() {
      if (st.outQuote && (st.outRaw || Date.now() < st.outQuote.deadlineMs - 120_000)) return go("SEND_OUT");
      const b = await bal(st.attempt), amount = outAmount(b.o, BigInt(st.reserve));
      if (!amount) throw new Halt("only " + b.o + " zatoshi are shielded, below the 1Click minimum; they stay in the hop wallet");
      const j = await PW.requestQuote({ base, fetchFn, okDeposit: isT, req: reqOut({ dest: ctx.dest, amount, recipient: st.recipient, refundT: await taddr(st.attempt + 1) }) });
      await go("SEND_OUT", { outQuote: quoteInfo(j), outTx: null, outRaw: null });
    },
    async SEND_OUT() {
      const oq = st.outQuote;
      if (!st.outTx && (await status(oq.depositAddress)) === PENDING) {
        const w = await wallet();
        if (!st.outRaw) {
          let proposal; try { proposal = await w.propose_transfer(st.accts[st.attempt], oq.depositAddress, BigInt(oq.amountIn)); }
          catch (e) { await go("QUOTE_OUT", { outQuote: null, reserve: (BigInt(st.reserve) * 2n).toString() }); throw new Halt("the Zcash fee did not fit; resume to try with a bigger reserve (" + e.message + ")"); }
          st.outRaw = hex(await w.create_proposed_transactions(proposal, mn, st.attempt)).slice(2); await saveWallet();      // txid(s) recorded and the wallet saved BEFORE broadcasting
        }
        try { await w.send_authorized_transactions(unhex(st.outRaw)); } catch (e) { if (!/already|duplicate|known|mempool/i.test(String(e))) throw e; }
        st.outTx = hex(unhex(st.outRaw).slice(0, 32).reverse()).slice(2); await save();
        await PW.submitDeposit({ base, txHash: st.outTx, depositAddress: oq.depositAddress, fetchFn }).catch(() => {});
      }
      const fin = await poll(oq.depositAddress, "Swap from ZEC", 90 * 60_000), a = afterOut(st, fin.status); await go(a.step, a);
    },
  };
  for (st.err = null; !DONE_STEPS.has(st.step) && st.step !== ctx.stopAt;) {
    if (st.dry && !["QUOTE_IN", "DEPOSIT_IN"].includes(st.step)) { st.err = "dry run stops here"; break; }
    try { await retry(() => H[st.step](), { sleep }); } catch (e) { st.err = e.message || String(e); break; }
  }
  await save(); say(st.err || progressText(st)); return st;
}

/** Funds left in the hop wallet: per account t-address and balances. Works from the saved wallet, or from the keys alone (fallback birthday from the payment's block time). */
export async function hopSummary(ctx, rec = null) {
  const Zj = ctx.Zjs || await ctx.loadZjs(), mn = await mnemonicFor(ctx.priv, ctx.words, rec ? rec.st.n || 0 : ctx.n || 0), w = new Zj.WebWallet(ZC.network, ZC.lightwalletd, 1, 1, rec && rec.db || null);
  let ids = rec && rec.st.accts;
  if (!ids) { const bd = rec && rec.st.birthday != null ? rec.st.birthday : birthdayFromTime(ctx.blockTimeSec, Number(await w.get_latest_block())); ids = []; for (let i = 0; i <= MAX_OUT; i++) ids.push(await w.create_account("hop" + i, mn, i, bd)); }
  await w.sync(); const s = await w.get_wallet_summary();
  return Promise.all(ids.map(async (id, i) => { const e = (s.account_balances.find(x => x[0] === id) || [0, {}])[1]; return { account: i, t: await w.get_current_address_transparent(id), transparent: BigInt(e.unshielded_balance || 0), orchard: BigInt(e.orchard_balance || 0) }; }));
}
