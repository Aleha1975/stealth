import { keysFromSignature, keyRequestTypedData, metaAddress, parseMeta, deriveForPayment, checkAnnouncement, decodeMetadata, hex, unhex, keccak, signDigest, randomBytes32 } from "./stealth-crypto.js";
import { postRelay } from "./relay-post.js";
import { paymentNonce, receiveTypedData, splitSig, payAmounts as calcAmounts, feeWithinCap } from "./pay-auth.js";
import { CHAINS, pickChain, chainOfMeta, addChainParams } from "./chains.js";
import * as PW from "./private-withdraw.js";
import { hopCard, hopView, statusLine } from "./hop-card.js";
import { getBalances, fetchBatch, authorizationUsed, waitFinal, hasTransfer, hasPaid, hasAuthUsed, recentLogs, timeoutSignal, TRANSFER_TOPIC, PAID_TOPIC, AUTH_USED_TOPIC, ETH_TOKEN } from "./chain-read.js";

const C = pickChain(), TOK = C.token, SYM = TOK.symbol, NAT = C.native.symbol;
const USDC = TOK.address, STEALTHPAY = C.stealthPay, CHAIN_HEX = C.chainHex, API = C.api || "/stealth-api";
const TUNIT = 10 ** TOK.decimals, NUNIT = 10 ** C.native.decimals;
const fmtTok = v => (Number(v) / TUNIT).toFixed(2);
const $ = id => document.getElementById(id);
$("sp-addr").textContent = STEALTHPAY || "not deployed on " + C.name + " yet";
document.querySelectorAll(".chain-name").forEach(e => e.textContent = C.name);
document.querySelectorAll(".tok-sym").forEach(e => e.textContent = SYM);
{ const o = document.querySelectorAll("#token option"); if (o[0]) { o[0].value = "TOKEN"; o[0].textContent = SYM; } if (o[1]) { o[1].value = "NATIVE"; o[1].textContent = NAT; } }
document.title = "Loophole · " + C.name;
$("to-meta").placeholder = "st:" + C.key + ":0x… or a pay link";
const say = (id, msg, cls) => { const e = $(id); e.textContent = msg; e.className = "hint" + (cls ? " " + cls : ""); };
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a || ""), isHash = h => /^0x[0-9a-fA-F]{64}$/.test(h || "");
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
let acct = null, keys = null, found = [];
// one run at a time per button (a double click used to start two wallet prompts / two payments)
const once = fn => { let on = false; return async (...a) => { if (on) return; on = true; try { return await fn(...a); } finally { on = false; } }; };
const hitOf = f => checkAnnouncement(f.legacy && keys && keys.legacy ? keys.legacy : keys, f.eph, null);
const sel = sig => hex(keccak(new TextEncoder().encode(sig)).slice(0, 4));
const pad = v => (typeof v === "bigint" ? v.toString(16) : String(v).replace(/^0x/, "")).padStart(64, "0");
const padAddr = a => a.toLowerCase().replace(/^0x/, "").padStart(64, "0");

// ---- tabs and deep link
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach(x => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".pane").forEach(p => p.hidden = p.id !== "pane-" + b.dataset.pane);
}));
const q = new URLSearchParams(location.search);
if (q.get("to")) { $("to-meta").value = q.get("to"); document.querySelector('[data-pane="pay"]').click(); }
else if (["receive", "payments", "pay"].includes(q.get("tab"))) document.querySelector('[data-pane="' + q.get("tab") + '"]').click();

// ---- wallet (payer path only talks to the wallet's own provider; reads go through our API)
async function api(path) { const r = await fetch(API + path, { cache: "no-store", signal: timeoutSignal(30000) }); const d = await r.json(); if (!r.ok || d.error) throw new Error(d.error || ("api " + r.status)); return d; }
async function wallet(method, params) { return window.ethereum.request({ method, params }); }
function setAcct(a) {
  const changed = acct && (a || "").toLowerCase() !== acct;
  acct = a ? a.toLowerCase() : null;
  $("wbtn").textContent = acct ? acct.slice(0, 6) + "…" + acct.slice(-4) : "Connect wallet"; $("wbtn").classList.toggle("on", !!acct);
  if (changed) { keys = null; found = []; $("recv-out").hidden = true; $("pay-list").textContent = ""; $("withdraw").hidden = true; say("recv-hint", "Account changed: derive the keys again for this account.", "warn"); }
}
async function connect() {
  if (!window.ethereum) { say("recv-hint", "No wallet found. Open this page inside MetaMask.", "bad"); return null; }
  const a = await wallet("eth_requestAccounts", []); setAcct(a[0]); return acct;
}
// already connected: open the wallet's account picker so another account can be chosen
async function switchAccount() {
  if (!window.ethereum) return connect();
  let perm;
  try { perm = await wallet("wallet_requestPermissions", [{ eth_accounts: {} }]); }
  catch (e) { if (e && e.code === 4001) return acct; say("recv-hint", "Switch the account in your wallet; the page follows it.", "warn"); return acct; }
  // the picker's answer lists the chosen accounts; eth_accounts may still put the previous one first
  const chosen = (perm || []).flatMap(p => (p.caveats || []).flatMap(c => Array.isArray(c.value) ? c.value : []));
  const a = chosen.length ? chosen : await wallet("eth_accounts", []); setAcct(a && a[0]); return acct;
}
// wallets do not always emit accountsChanged (e.g. switching to an account not yet connected to this site): re-check on focus and every few seconds
// follow only a change of the wallet's own first account, so a choice made in the picker is not undone
let lastWalletAcct;
function syncAcct() { if (window.ethereum && document.visibilityState === "visible") wallet("eth_accounts", []).then(a => { const x = a && a[0] ? a[0].toLowerCase() : null; if (lastWalletAcct !== undefined && x !== lastWalletAcct) setAcct(x); lastWalletAcct = x; }).catch(() => {}); }
window.addEventListener("focus", syncAcct); document.addEventListener("visibilitychange", syncAcct); setInterval(syncAcct, 3000);
async function ensureChain() {
  const cur = async () => String(await wallet("eth_chainId", [])).toLowerCase();
  if ((await cur()) !== CHAIN_HEX) {
    try { await wallet("wallet_switchEthereumChain", [{ chainId: CHAIN_HEX }]); }
    catch (e) {
      if (e && (e.code === 4902 || e.code === -32603 || /unrecognized|not added|unknown chain/i.test(e.message || ""))) await wallet("wallet_addEthereumChain", [addChainParams(C)]);
      else throw e;
    }
  }
  if ((await cur()) !== CHAIN_HEX) throw new Error("switch your wallet to " + C.name);
}
$("wbtn").addEventListener("click", () => (acct ? switchAccount() : connect()).catch(e => say("recv-hint", e.message || String(e), "bad")));
if (window.ethereum) {
  wallet("eth_accounts", []).then(a => { if (a && a.length) setAcct(a[0]); }).catch(() => {});
  window.ethereum.on && window.ethereum.on("accountsChanged", a => setAcct(a && a[0]));
}

// ---- receive: keys from one typed-data signature, verified to come from this account
$("btn-keys").addEventListener("click", once(async () => {
  try {
    if (!acct && !(await connect())) return;
    // audit 1086/1098 M-1 (accepted risk): this signature IS the master key of every stealth address of this account on every chain; any site that obtains the same signature can spend and see everything.
    say("recv-hint", "WARNING: this signature is the master key to your stealth funds. Sign it ONLY while the address bar shows " + location.host + ". Never sign it for any other site or message that asks for it. Sign the request in your wallet…", "warn");
    const sig = await wallet("eth_signTypedData_v4", [acct, keyRequestTypedData(acct)]);
    const k1 = keysFromSignature(sig, acct);                       // not active until every check below has passed (1098 L-2)
    const meta = metaAddress(k1, C.key);
    // remember the public meta-address per account: if a later derivation differs, say so before a link is shared
    let prev = null; try { prev = localStorage.getItem("stealth.meta." + acct); } catch {}
    if (!prev) {                                         // audit 1086 M-3: first derivation on this browser: ask once more; a wallet that signs with random nonces gives other keys each time, and its meta-address could never be re-derived
      say("recv-hint", "First time on this browser: sign the same request once more to prove your wallet gives the same keys every time…");
      let again; try { again = keysFromSignature(await wallet("eth_signTypedData_v4", [acct, keyRequestTypedData(acct)]), acct); } catch (e) { throw new Error("The second signature was not given or not valid (" + ((e && e.message) || e) + "). The keys were NOT activated: they could not be proven to be reproducible. Try again."); }
      if (metaAddress(again, C.key) !== meta) throw new Error("Your wallet gave a different signature the second time (randomised signing). Keys derived from it could not be recovered later, so none were made. Use a standard key-based wallet such as MetaMask.");
    }
    let legacyOnly = false;
    if (prev && prev !== meta) {
      // 1098 L-1: a wallet that signs with high-s: the stored meta-address came from the old (raw) keys; the new canonical keys stay active and the old ones are scanned too
      if (k1.legacy && metaAddress(k1.legacy, C.key) === prev) legacyOnly = true;
      else throw new Error("Refused: these keys differ from the ones this account derived before on this device (stored meta-address " + prev.slice(0, 18) + "…). Nothing was activated and the stored value was kept. Payments sent to the old link are reachable only with the old keys: check that you picked the same wallet account. To start over on purpose, clear this site's data in the browser.");
    }
    keys = k1;
    if (!prev) try { localStorage.setItem("stealth.meta." + acct, meta); } catch {}
    $("meta").textContent = meta; $("paylink").textContent = location.origin + location.pathname.replace(/[^/]*$/, "") + "app.html?" + (C.key === pickChain("").key ? "" : "chain=" + C.key + "&") + "to=" + meta;
    $("recv-out").hidden = false;
    if (legacyOnly) say("recv-hint", "Your wallet's signatures are non-canonical (high-s). Older payments made to your previous link are found with the legacy keys (scan and withdraw only); do not share the new link until you have moved those funds. WARNING: the key signature is the master key; sign it only on " + location.host + ".", "warn");
    else say("recv-hint", "Keys derived in this browser. They are not stored anywhere. Remember: the key signature is the master key; sign it only on " + location.host + ".", "ok");
    $("scan-note").textContent = "Ready to scan " + C.name + " for payments to your keys.";
  } catch (e) { say("recv-hint", e.message || String(e), "bad"); }
}));
$("copy-link").addEventListener("click", () => navigator.clipboard.writeText($("paylink").textContent).then(() => say("recv-hint", "Link copied.", "ok")));
$("copy-meta").addEventListener("click", () => navigator.clipboard.writeText($("meta").textContent).then(() => say("recv-hint", "Meta-address copied.", "ok")));

// ---- history page cache (IndexedDB, key chain|page|manifest.version). Works without storage: every call is wrapped.
function idb() {
  return new Promise(res => { try { const q = indexedDB.open("stealth-pages", 1); q.onupgradeneeded = () => q.result.createObjectStore("p"); q.onsuccess = () => res(q.result); q.onerror = () => res(null); q.onblocked = () => res(null); } catch { res(null); } });
}
const idbGet = (db, key) => new Promise(res => { try { const q = db.transaction("p").objectStore("p").get(key); q.onsuccess = () => res(q.result || null); q.onerror = () => res(null); } catch { res(null); } });
const idbPut = (db, key, val) => new Promise(res => { try { const t = db.transaction("p", "readwrite"); t.objectStore("p").put(val, key); t.oncomplete = () => res(); t.onerror = () => res(); t.onabort = () => res(); } catch { res(); } });
/** Returns k => rows[] for pages 0..full_pages-1; fetches only pages missing from the local cache (6 at a time). */
async function getPages(man) {
  const db = await idb(), pages = new Array(man.full_pages), key = k => C.key + "|" + k + "|" + man.version;
  const need = [];
  for (let k = 0; k < man.full_pages; k++) { const hit = db ? await idbGet(db, key(k)) : null; if (Array.isArray(hit)) pages[k] = hit; else need.push(k); }
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++; if (i >= need.length) return; const k = need[i];
      const r = await fetch(API + "/pages/p" + String(k).padStart(6, "0") + ".json?v=" + man.version);
      if (!r.ok) throw new Error("history page " + k + " unavailable (" + r.status + ")");
      const rows = await r.json(); if (!Array.isArray(rows)) throw new Error("bad history page " + k);
      pages[k] = rows; if (db) await idbPut(db, key(k), rows);
      if (i % 8 === 0) say("pay-hint", "Downloading history " + (man.full_pages - need.length + i + 1) + "/" + man.full_pages + "…");
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, need.length) }, worker));
  return k => pages[k];
}
// ---- payments: scan announcements (indexed by us), check each with the viewing key, balances via our API
// After a withdraw the indexer's balance cache (~15 s) can still show the old amount: cap it by what we know is left.
const pendingWd = new Map();   // stealth -> until (ms): a withdrawal was handed to the relayer and is not confirmed yet (1101 L-2)
const spent = new Map();   // stealth -> { left, until }
async function scan() {
  if (!keys) { say("pay-hint", "Derive your keys first (Receive tab).", "bad"); return; }
  const head = await api("/head");
  if (head.lag != null && head.lag > 50) say("pay-hint", "Index is " + head.lag + " blocks behind the chain; very recent payments may not show yet.", "warn");
  else say("pay-hint", "Reading announcements on " + C.name + "…");
  const K = keys, mine = []; let n = 0;                      // 1101 I-2: this run works on its own list and its own keys; a changed account discards it
  const check = (id, block, tx, stealth, eph, meta, payer) => {
    n++;
    if (!eph || !isHash(tx) || !isAddr(stealth)) return;
    const md = decodeMetadata(meta) || {};
    for (const [k, legacy] of K.legacy ? [[K, false], [K.legacy, true]] : [[K, false]]) {       // 1098 L-1: legacy (raw high-s) keys are scanned too
      const hit = checkAnnouncement(k, eph, md.viewTag);          // view-tag filter first, full check only on a tag match
      if (!hit || hit.stealth.toLowerCase() !== stealth.toLowerCase()) continue;
      mine.push({ stealth: hit.stealth, tx, block: Number(block) || 0, token: md.token, amount: md.amount, payer: isAddr(payer) ? payer : null, eph, legacy }); return;
    }
  };
  let since = 0;
  // 1) immutable history pages (static files, cached forever locally); 2) only the tail from the indexer. Old indexers (no manifest) -> paged API.
  let man = null;
  try { const r = await fetch(API + "/pages/manifest.json", { cache: "no-cache" }); if (r.ok) { const m = await r.json(); if (m && m.chain === C.key && m.page_size === 1024 && Number.isInteger(m.full_pages) && m.full_pages >= 0 && m.full_pages <= 100000 && Number.isInteger(m.tail_since_id)) man = m; } } catch {}
  if (man) {
    const rowsOf = await getPages(man);
    for (let k = 0; k < man.full_pages; k++) {
      for (const r of rowsOf(k)) check(r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
      if (k % 20 === 19) say("pay-hint", n + " announcements checked…");
    }
    since = man.tail_since_id;
  }
  for (let loops = 0; ; loops++) {
    if (loops > 5000) throw new Error("The index returned an implausible number of announcements; stopping.");     // 1098 I-3
    const d = await api("/announcements?since=" + since + "&limit=2000");
    for (const r of d.rows) { if (r.scheme === 1) check(r.id, r.block, r.tx, r.stealth, r.eph, r.meta, r.payer); }
    if (n % 2000 === 0 && n) say("pay-hint", n + " announcements checked…");
    if (!Array.isArray(d.rows) || !d.rows.length || d.next === since) break; since = d.next;
  }
  if (keys !== K) return;                                    // the account changed while scanning: nothing of this run is shown
  found = mine; render(); showResume().catch(() => {});      // 1101 M-1: the payments are listed BEFORE any balance is read; a failing RPC can no longer hide them
  const unread = await refreshBalances(true);
  const msg = n + " announcements scanned, " + found.length + " are yours." + (found.some(f => f.legacy) ? " Some are under your legacy keys (withdraw only)." : "") + (unread ? " Balances of " + unread + " could not be read from the chain right now; scan again to retry." : "");
  if (head.lag != null && head.lag > 50) say("pay-hint", msg + " Index is " + head.lag + " blocks behind.", "warn"); else say("pay-hint", msg, unread ? "warn" : "ok");
}
// audit 1098 M-2: balances are read from the chain RPC (batched), never from our indexer, so the operator cannot learn which stealth addresses belong to one user
// Best effort and in pages (1101 M-1): one failing page leaves its rows as "not read" (usdc = null) instead of failing the whole scan. -> number of rows left unread
async function refreshBalances(redraw = true) {
  if (!found.length) return 0;
  const list = found, PAGE = 50, pages = []; for (let i = 0; i < list.length; i += PAGE) pages.push(list.slice(i, i + PAGE));
  let unread = 0, next = 0;
  const worker = async () => { for (;;) {
    const part = pages[next++]; if (!part) return;
    let b = null; for (let t = 0; t < 2 && !b; t++) { try { b = await getBalances(rpcBatch, USDC, part.map(f => f.stealth)); } catch { if (t === 0) await new Promise(z => setTimeout(z, 1500)); } }
    for (const f of part) { const x = b && b.get(f.stealth.toLowerCase());
      if (!x) { if (f.usdc === undefined) f.usdc = null; unread++; continue; }
      f.usdc = x.usdc; f.eth = x.eth; const sp = spent.get(f.stealth.toLowerCase()); if (sp && Date.now() < sp.until && f.usdc > sp.left) f.usdc = sp.left; }
  } };
  await Promise.all(Array.from({ length: Math.min(3, pages.length) }, worker));
  if (redraw && list === found) render();
  return unread;
}
// ---- private transfers in flight or unfinished: stealth -> { f, hit, st, msg, running, extra }; drawn as cards at the top of My payments
const autoTries = new Map(), hops = new Map(), TERMINAL = ["DONE", "FAILED_IN", "FAILED"];
const activeHop = f => { const h = hops.get(f.stealth.toLowerCase()); return h && !TERMINAL.includes(h.st.step) ? h : null; };
function renderHops() {
  const box = $("hop-resume"); box.textContent = "";
  for (const [k, h] of hops) box.appendChild(hopCard(h, { onContinue: b => { b.disabled = true; runHop(h.f, h.hit, null).catch(e => say("pay-hint", e.message || String(e), "bad")); },
    onFunds: b => { b.disabled = true; runHop(h.f, h.hit, null).catch(e => say("pay-hint", e.message || String(e), "bad")); }, onDismiss: () => { hops.delete(k); renderHops(); },
    onReturn: (b, card) => { b.disabled = true; returnZec(h, card).catch(e => { b.disabled = false; say("pay-hint", e.message || String(e), "bad"); }); } }));
  box.hidden = !hops.size;
}
// 1105 L-4: every writer of a hop record outside the machine takes the machine's own Web Lock (non-blocking). If the hop is running (or another writer is) the write is skipped, never interleaved.
const underHopLock = (stealth, fn) => navigator.locks ? navigator.locks.request("zec-hop:" + stealth.toLowerCase(), { ifAvailable: true }, l => l ? fn() : undefined) : fn();
// ZEC stuck on the hop t-address (shielding is refused since NU6.3): sign a plain transparent tx here and swap it back to the connected wallet
async function returnZec(h, card) {
  const [HM, ZR] = await Promise.all([hopMod(), import("./zec-return.js")]), { zcash: ZC } = await import("./chains.js");
  if (!acct) throw new Error("Connect your wallet first.");
  const line = el("div", "hop-line", "Looking for the ZEC…"); card.appendChild(line); const step = t => { line.textContent = t; };
  const seed = await HM.mnemonicSeed(await HM.mnemonicFor(h.hit.stealthPriv, await HM.loadWords(), h.st.n || 0));
  let key = null, utxos = [], unspendable = false;
  for (let a = 0; a < 4 && !utxos.length; a++) for (let i = 0; i < 3 && !utxos.length; i++) {
    key = ZR.deriveT(seed, ZR.tPath(a, i)); const raw = await ZR.getUtxos(ZC.lightwalletd, key.addr); utxos = ZR.sweepSet(raw);
    if (!utxos.length && (raw.length || raw.truncated)) unspendable = true;      // 1103 M-1: dust only, or a list too long to read to the end: that is NOT "empty"
  }
  if (!utxos.length && unspendable) { step("This address holds only tiny outputs (below the network fee) or more outputs than can be read at once. Nothing was removed and nothing can be swept from them yet. Try again later."); return; }
  if (!utxos.length) {                                   // the server lists nothing: that is an ANSWER of an untrusted server, not proof (1100 M-1). Never hide on one answer.
    step("Checking the shielded balance…");
    const r = await HM.findHop(HM.idbStore(), h.f.stealth), left = await HM.hopSummary(await hopCtx(HM, h.f, h.hit, null), r && r.rec);
    if (left.some(x => x.transparent + x.orchard > 0n)) throw new Error("ZEC is still in the shielded pool. Press Continue transfer.");
    const v = await noteEmptyFor(HM, h, true);
    if (v.hide) { await hideHop(HM, h); step("Nothing left here, confirmed by repeated checks. Removed."); return; }
    step("The server says there is nothing here (" + ((v.obs && v.obs.count) || 1) + "/" + ZR.EMPTY_N + " checks, spread over at least 30 minutes). Not removed: rechecking. Press Return money again later."); return;
  }
  noteEmptyFor(HM, h, false).catch(() => {});
  const total = utxos.reduce((s, u) => s + u.value, 0n), amount = total - ZR.sweepFee(utxos.length);
  { // 1103 L-1: an earlier press recorded its sweep BEFORE broadcasting. If that transaction is on the network, carry on with it instead of building a conflicting second one.
    const prev = await HM.findHop(HM.idbStore(), h.f.stealth).then(r => r && r.rec.st.sweep).catch(() => null);
    if (prev && /^[0-9a-f]{64}$/i.test(prev.txid || "") && /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(prev.deposit || "") && Date.now() - (prev.at || 0) < 6 * 3600_000) {
      let on = null; try { on = await ZR.txKnown(ZC.lightwalletd, prev.txid); } catch {}
      if (on === true) return await finishSweep(HM, h, step, { txid: prev.txid, deposit: prev.deposit, amountOut: prev.amountOut });
      if (on === undefined || on === null) throw new Error("Cannot tell whether your earlier return transaction (" + prev.txid.slice(0, 12) + "…) went out. Not sending another yet: press Return money again in a minute.");
    }
  }
  step("Getting a quote…");
  const j = await PW.requestQuote({ req: HM.reqOut({ dest: C, amount, recipient: acct, refundT: key.addr }), okDeposit: a => /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(a || "") });
  step("Sending " + (Number(amount) / 1e8) + " ZEC…");
  const sw = ZR.buildSweep({ utxos, key, to: j.quote.depositAddress, tip: await ZR.getTip(ZC.lightwalletd) });
  if (sw.amount !== BigInt(j.quote.amountIn)) throw new Error("amount mismatch; refusing");
  const intent = { txid: sw.txid, deposit: j.quote.depositAddress, amountOut: j.quote.amountOut, at: Date.now() };
  const saved = await underHopLock(h.f.stealth, async () => { const rr = await HM.findHop(HM.idbStore(), h.f.stealth); if (!rr) return false; rr.rec.st = { ...rr.rec.st, sweep: intent }; await HM.idbStore().put(rr.key, rr.rec); return true; }).catch(() => false);
  if (!saved) throw new Error("Could not record the return before sending it (the transfer may be running in another tab). Nothing was sent; try again in a minute.");        // recorded BEFORE broadcasting
  await ZR.sendAndConfirm(ZC.lightwalletd, sw.raw, undefined, sw.txid);        // 1100 L-2: the node must hand our exact bytes back before this counts as sent
  await finishSweep(HM, h, step, intent);
}
async function finishSweep(HM, h, step, sw) {
  let note = ""; await PW.submitDeposit({ txHash: sw.txid, depositAddress: sw.deposit }).catch(e => { note = " (could not notify NEAR Intents: " + ((e && e.message) || e) + ")"; });
  if (note) step("Sent" + note);
  const fin = await PW.pollStatus({ depositAddress: sw.deposit, timeoutMs: 60 * 60_000, intervalMs: 10_000, onUpdate: s => step("Returning · " + s.status.toLowerCase().replace(/_/g, " ") + " · usually 10–20 min" + note) });
  step(fin.status === "SUCCESS" ? "Done: ≈ " + (Number(sw.amountOut) / 1e6).toFixed(2) + " " + SYM + " sent to your wallet." : "Swap ended as " + fin.status + ". The ZEC is back on the hop address; press Return money again.");
  if (fin.status === "SUCCESS") await hideHop(HM, h);
}
// A transfer from the first version (before Ironwood) could never shield, so its ZEC only ever sat on the hop t-addresses:
// once those are empty (returned) the record is history and shows nothing. Later versions are never hidden this way.
async function staleV1(HM, r, hit) {
  if (r.rec.st.v === 2) return { hide: false };
  try {
    const ZR = await import("./zec-return.js"), { zcash: ZC } = await import("./chains.js");
    const seed = await HM.mnemonicSeed(await HM.mnemonicFor(hit.stealthPriv, await HM.loadWords(), r.rec.st.n || 0));
    let empty = true;
    for (let a = 0; a < 4 && empty; a++) for (let i = 0; i < 3 && empty; i++) if ((await ZR.getUtxos(ZC.lightwalletd, ZR.deriveT(seed, ZR.tPath(a, i)).addr)).length) empty = false;
    // 1100 M-1: one "empty" answer proves nothing (lagging, restarting or lying server); only repeated answers over 30+ minutes hide the card
    const v = ZR.noteEmpty(r.rec.st.emptyObs, empty); r.rec.st = { ...r.rec.st, emptyObs: v.obs }; await underHopLock(r.rec.st.stealth, async () => { const cur = await HM.findHop(HM.idbStore(), r.rec.st.stealth); if (cur) { cur.rec.st = { ...cur.rec.st, emptyObs: v.obs }; await HM.idbStore().put(cur.key, cur.rec); } });
    return v;
  } catch { return { hide: false }; }
}
// record one observation of "the server lists no UTXOs" (or reset it); the verdict says whether it is now safe to hide the hop
async function noteEmptyFor(HM, h, empty) {
  const ZR = await import("./zec-return.js"), store = HM.idbStore();
  const out = await underHopLock(h.f.stealth, async () => {
    const r = await HM.findHop(store, h.f.stealth); if (!r) return { hide: false, obs: null };
    const v = ZR.noteEmpty(r.rec.st.emptyObs, empty); if (JSON.stringify(v.obs) !== JSON.stringify(r.rec.st.emptyObs || null)) { r.rec.st = { ...r.rec.st, emptyObs: v.obs }; await store.put(r.key, r.rec); }
    return v; });
  return out || { hide: false, obs: null };           // the hop is running elsewhere: no observation counts
}
// a finished or returned transfer leaves no card behind (the record stays in IndexedDB, flagged)
async function hideHop(HM, h) {
  const store = HM.idbStore();
  await underHopLock(h.f.stealth, async () => { const r = await HM.findHop(store, h.f.stealth); if (r) { r.rec.st = { ...r.rec.st, step: "FAILED", result: "RETURNED", hidden: true }; await store.put(r.key, r.rec); } });
  hops.delete(h.f.stealth.toLowerCase()); renderHops(); render();
}
setInterval(() => { const r = [...hops.values()].filter(h => h.running); if (!r.length && $("pay-hint").textContent.startsWith("●")) say("pay-hint", ""); if (r.length) { renderHops(); const v = hopView(r[0]); if (v.kind === "run" && v.what && $("pay-hint").textContent.startsWith("●")) say("pay-hint", statusLine(v), "ok"); } }, 1000);
function render() {
  const list = $("pay-list"); list.textContent = "";
  if (!found.length) { list.appendChild(el("p", "note", "Nothing found yet. Payments appear a few seconds after they land.")); return; }
  found.forEach((f, i) => {
    const row = el("div", "pay"); const top = el("div", "row"); top.style.justifyContent = "space-between";
    const label = f.token === "ETH" ? (Number(f.amount) / NUNIT).toFixed(5) + " " + NAT : f.token && f.token.toLowerCase() === USDC.toLowerCase() ? fmtTok(f.amount) + " " + SYM : "payment";
    top.appendChild(el("span", "amt", label)); top.appendChild(el("span", "mono", f.stealth.slice(0, 8) + "…" + f.stealth.slice(-4)));
    row.appendChild(top);
    const hp = activeHop(f);
    const small = el("small", null, "block " + f.block + " · " + (hp ? fmtTok(BigInt(hp.st.amount)) + " " + SYM + " · in private transfer" : (f.usdc === undefined ? "reading balance…" : f.usdc === null ? "balance not read (scan again)" : "now holds " + fmtTok(f.usdc) + " " + SYM) + (f.eth ? " + " + (Number(f.eth) / NUNIT).toFixed(5) + " " + NAT : "")) + " · ");
    const a = el("a", null, "tx"); a.href = C.explorer + "/tx/" + f.tx; a.target = "_blank"; a.rel = "noopener noreferrer"; small.appendChild(a); row.appendChild(small);
    if (!hp && f.usdc > 0n) { const d = el("div"); d.style.marginTop = "8px"; const b = el("button", "btn ghost", "Withdraw " + SYM); b.type = "button"; b.addEventListener("click", () => openWithdraw(i)); d.appendChild(b); row.appendChild(d); }
    list.appendChild(row);
  });
}
$("btn-scan").addEventListener("click", once(() => scan().catch(e => say("pay-hint", e.message || String(e), "bad"))));

// ---- withdraw the stablecoin gaslessly: EIP-3009 authorization signed by the stealth key, submitted by the relayer
let wd = null;
function openWithdraw(i) {
  if (activeHop(found[i])) { $("withdraw").hidden = true; say("pay-hint", "This payment has a transfer in progress: use the card above.", "warn"); return; }
  wd = found[i]; $("wd-from").textContent = wd.stealth; $("wd-to").value = ""; $("wd-amt").value = ""; $("withdraw").hidden = false;
  // Private = the hidden Zcash hop (web/zec-hop.js): offered only on a cross-origin isolated page, on chains with 1Click, and only if the module loads; then it is on by default
  const mine = wd; $("wd-priv-wrap").hidden = true; $("wd-private").checked = false; $("wd-priv-opts").hidden = true; pvReset();
  const dest = $("wd-dest"); dest.textContent = "";
  for (const k of [C.key]) {   /* one payout chain for now: the same chain */ const c = CHAINS[k]; if (c && c.oneClick && !Array.from(dest.options).some(o => o.value === c.key)) { const o = el("option", null, c.name + " (" + c.token.symbol + ")" + (c.key === C.key ? " · same chain" : "")); o.value = c.key; dest.appendChild(o); } }
  if (self.crossOriginIsolated && C.privateWithdraw && C.oneClick && !wd.legacy) hopMod().then(() => { if (wd !== mine) return; $("wd-priv-wrap").hidden = false; $("wd-private").checked = true; $("wd-priv-opts").hidden = false; pvReset(); }).catch(() => {});
}
// ---- private withdraw: preview (two dry quotes) first, then a second click starts the hop. Any input change drops the preview.
let pv = null, HOPM = null;
const hopMod = () => HOPM || (HOPM = import("./zec-hop.js"));
function pvReset() { pv = null; $("wd-quote").hidden = true; $("btn-wd").textContent = $("wd-private").checked ? "Preview" : "Send without gas"; }
$("wd-private").addEventListener("change", () => { $("wd-priv-opts").hidden = !$("wd-private").checked; pvReset(); });
["wd-to", "wd-amt", "wd-dest", "wd-mode"].forEach(id => { $(id).addEventListener("input", pvReset); $(id).addEventListener("change", pvReset); });
// chain reads for the hop go through the connected wallet's own RPC (the page CSP allows no direct RPC); same JSON-RPC shape as fetch, so zec-hop.js stays injectable
const walletRpc = async (_u, init) => { const { method, params } = JSON.parse(init.body); try { if (method !== "eth_chainId" && String(await wallet("eth_chainId", [])).toLowerCase() !== CHAIN_HEX) throw new Error("your wallet is on another network than " + C.name); const result = await wallet(method, params); return { ok: true, json: async () => ({ result }) }; } catch (e) { return { ok: true, json: async () => ({ error: { message: String((e && e.message) || e) } }) }; } };
// chain reads for the hop: the chain's public RPC directly (CORS open, listed in the page CSP), the wallet's RPC as a fallback
// 1101 L-3/L-5: reads that name a stealth address NEVER fall back to the wallet's provider (it already knows the account and IP); only `allowWallet` calls (the token's domain separator) may. All reads time out.
const chainRpc = async (u, init, allowWallet = false) => { try { const r = await fetch(u, { ...init, signal: init.signal || timeoutSignal() }); if (r.ok) { const j = await r.clone().json().catch(() => null); if (j && j.result !== undefined) return r; } } catch {} if (allowWallet) return walletRpc(u, init); throw new Error("the chain RPC did not answer"); };
const hopCtx = async (HM, f, hit, o) => ({ getUtxos: HM.makeGetUtxos(), authUsed: HM.makeAuthUsed(C, chainRpc), countPriorHops: HM.makeCountPriorHops(C, chainRpc), txKnown: HM.makeTxKnown(), store: HM.idbStore(), stealth: f.stealth, priv: hit.stealthPriv, chain: C, api: API, words: await HM.loadWords(), loadZjs: HM.sharedZjs, waitReceipt, randomNonce: randomBytes32,
  balance: async () => (await getBalances(rpcBatch, USDC, [f.stealth])).get(f.stealth.toLowerCase()).usdc, authUsed: HM.makeAuthUsed(C, chainRpc), onProgress: (s, m) => hopProgress(f, s, m), ...o });
const rpcOne = async (method, params) => { const r = await chainRpc(C.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }); const j = await r.json(); if (j.error) throw new Error(j.error.message || "rpc error"); return j.result; };
const rpcBatch = async calls => { try { return await fetchBatch(fetch, C.rpc, calls); } catch { const out = []; for (let i = 0; i < calls.length; i += 10) out.push(...await Promise.all(calls.slice(i, i + 10).map(([m, p]) => rpcOne(m, p)))); return out; } };
async function holdScreen() { try { return navigator.wakeLock ? await navigator.wakeLock.request("screen") : null; } catch { return null; } }
document.addEventListener("visibilitychange", () => { for (const h of hops.values()) if (h.running) h.hidden = document.hidden; renderHops(); });
function hopProgress(f, s, m) {
  const k = f.stealth.toLowerCase(), h = hops.get(k); if (!h) return;
  h.st = s; h.msg = m || ""; h.beatAt = Date.now(); h.hidden = document.hidden;      // beatAt: the card says "no update for N s" if the machine goes quiet
  if (s.relayed && s.inQuote && !h.sp) {                          // the deposit leg has left the stealth address: stop showing its old balance
    h.sp = true; const amtIn = BigInt(s.inQuote.amountIn);
    spent.set(k, { left: f.usdc > amtIn ? f.usdc - amtIn : 0n, until: Date.now() + 120_000 }); render(); setTimeout(() => refreshBalances().catch(() => {}), 3000);
  }
  if (h.running) { const v = hopView(h); if (v.kind === "run" && v.what) say("pay-hint", statusLine(v), "ok"); }   // green while it runs normally
  renderHops();
}
/** start (o = { recipient, amount, dest }) or resume (o = null) the hop of one found payment; one tab at a time per address */
async function runHop(f, hit, o) {
  const k = f.stealth.toLowerCase(); if ((hops.get(k) || {}).running) return;
  const HM = await hopMod(), ctx = await hopCtx(HM, f, hit, o || {}), key = "zec-hop:" + k;
  let h;
  if (o) h = { f, hit, running: true, msg: "", st: { step: "QUOTE_IN", chain: C.key, dest: o.dest.key, amount: o.amount.toString(), recipient: o.recipient, startedAt: Date.now() } };
  else { const r = await HM.findHop(ctx.store, f.stealth); if (!r) throw new Error("nothing to resume"); if (r.rec.st.chain !== C.key) throw new Error("This transfer belongs to " + (CHAINS[r.rec.st.chain] || {}).name + ": open the app on that chain to resume it."); ctx.chain = CHAINS[r.rec.st.chain]; ctx.dest = CHAINS[r.rec.st.dest]; h = { f, hit, running: true, msg: "", st: r.rec.st }; }
  h.beatAt = Date.now(); hops.set(k, h); say("pay-hint", ""); renderHops(); render();
  const lock = await holdScreen();                                // a locked phone screen or a sleeping display freezes the tab and with it the transfer
  const run = () => (o ? HM.startHop(ctx) : HM.runHop(ctx));
  let st;
  try { st = await (navigator.locks ? navigator.locks.request(key, { ifAvailable: true }, l => l ? run() : Promise.reject(new Error("This transfer is already running in another tab."))) : run()); }
  catch (e) { if (lock) lock.release().catch(() => {}); if (o) hops.delete(k); else h.running = false; renderHops(); render(); throw e; }
  if (lock) lock.release().catch(() => {});
  h.st = st; h.running = false;
  if (["DONE", "FAILED_IN"].includes(st.step)) HM.scrubFinished(ctx.store, f.stealth).catch(() => {});   // audit 1088 L-6: no stealth -> recipient link kept in the browser after the end
  // transient failures (network, RPC, quote service) resume on their own (see below); a deliberate stop (a failed check) waits for the user
  if (!TERMINAL.includes(st.step) && st.err && !st.halted && (autoTries.get(k) || 0) < 7) {
    const n = (autoTries.get(k) || 0) + 1; autoTries.set(k, n); h.retryAt = Date.now() + Math.min(300_000, 15_000 * 2 ** (n - 1));      // 15 s, 30 s, 1, 2, 4, 5, 5 min; the card shows the cause and the countdown
    setTimeout(() => runHop(f, hit, null).catch(e => say("pay-hint", e.message || String(e), "bad")), h.retryAt - Date.now());
  } else if (TERMINAL.includes(st.step)) autoTries.delete(k);
  if (st.relayed && st.inQuote && !h.sp) { const amtIn = BigInt(st.inQuote.amountIn); spent.set(k, { left: f.usdc > amtIn ? f.usdc - amtIn : 0n, until: Date.now() + 120_000 }); }
  if (st.step === "FAILED_IN") spent.delete(k);
  if (st.step === "FAILED") try { const rec = (await HM.findHop(ctx.store, f.stealth)).rec; h.extra = (await HM.hopSummary(ctx, rec)).filter(x => x.transparent + x.orchard > 0n).map(x => "Hop wallet account " + x.account + ": " + (Number(x.transparent) / 1e8) + " ZEC transparent, " + (Number(x.orchard) / 1e8) + " ZEC shielded").join("\n"); } catch (e) { h.extra = "Could not read the hop wallet: " + e.message; }
  renderHops(); render(); await refreshBalances().catch(() => {});
}
async function privateWithdraw(to, value, hit) {
  const dest = CHAINS[$("wd-dest").value]; if (!dest || !dest.oneClick) throw new Error("pick a destination chain");
  const HM = await hopMod(), mode = $("wd-mode").value === "private" ? "private" : "fast", key = [to.toLowerCase(), value, dest.key, mode].join("|");
  if (!pv || pv.key !== key) {                                    // step 1: show what it will cost, send nothing
    say("pay-hint", "Asking NEAR Intents for a quote…");
    const q1 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqIn({ chain: C, amount: value, tAddr: HM.DRY_T, stealth: wd.stealth, dry: true }) }), zec = BigInt(q1.quote.amountOut);
    if (!HM.okSize(zec)) throw new Error("Too small for the private route. Try a larger amount.");
    const q2 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqOut({ dest, amount: HM.outAmount(zec - HM.SHIELD_FEE), recipient: to, refundT: HM.DRY_T, dry: true }) });
    const out = BigInt(q2.quote.amountOut), fee = value - out, box = $("wd-quote"); box.textContent = "";
    const pct = (Number(fee) / Number(value) * 100).toFixed(1), qt = el("div", "qt"), c1 = el("div"), c2 = el("div");
    c1.appendChild(el("span", "note", "Recipient gets")); c1.appendChild(el("span", "big", "≈ " + (Number(out) / 10 ** dest.token.decimals).toFixed(2) + " " + dest.token.symbol));
    c2.appendChild(el("span", "note", "Fee")); c2.appendChild(el("span", "big", "≈ " + (Number(fee) / TUNIT).toFixed(2) + " (" + pct + "%)"));
    const c3 = el("div"); c3.appendChild(el("span", "note", "Takes about")); c3.appendChild(el("span", "big", HM.etaLabel(mode)));
    qt.appendChild(c1); qt.appendChild(c2); qt.appendChild(c3); box.appendChild(qt); box.appendChild(el("div", "note", "Takes about " + HM.etaLabel(mode) + " · keep this tab open" + (mode === "private" ? " (it can be resumed if you close it)" : "")));
    box.hidden = false; pv = { key }; $("btn-wd").textContent = "Confirm private transfer";
    say("pay-hint", "Check the quote, then confirm.", "warn"); return;
  }
  $("btn-wd").disabled = true; $("withdraw").hidden = true;
  try { await runHop(wd, hit, { recipient: to, amount: value, dest, mode }); } finally { $("btn-wd").disabled = false; pvReset(); }
}
// ---- unfinished hops of the payments found: banner with Resume (needs the keys, so it appears after Scan)
async function showResume() {
  if (!self.crossOriginIsolated || !keys || !((await (indexedDB.databases ? indexedDB.databases() : [])) || []).some(d => d.name === "stealth-zec-hop")) return;
  const HM = await hopMod(), store = HM.idbStore();
  for (const f of found) {
    const k = f.stealth.toLowerCase(); if ((hops.get(k) || {}).running) continue;
    const r = await HM.findHop(store, f.stealth); if (!r || r.rec.st.hidden || ["DONE", "FAILED_IN"].includes(r.rec.st.step)) continue;
    if (f.legacy) continue;                                         // legacy keys: scan and plain withdraw only
    const hit = checkAnnouncement(keys, f.eph, null); if (!hit || hit.stealth.toLowerCase() !== k) continue;
    const sv = await staleV1(HM, r, hit);
    if (sv.hide) { await underHopLock(f.stealth, async () => { const cur = await HM.findHop(store, f.stealth); if (cur) { cur.rec.st = { ...cur.rec.st, hidden: true }; await store.put(cur.key, cur.rec); } }); continue; }
    hops.set(k, { f, hit, running: false, msg: sv.obs ? "The server says there is no ZEC here; rechecking (" + sv.obs.count + "/3)" : "", st: r.rec.st });
  }
  renderHops(); render();
}
$("btn-wd-cancel").addEventListener("click", () => { $("withdraw").hidden = true; wd = null; });
const TYPEHASH = keccak(new TextEncoder().encode("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));
const DOMAIN_TYPEHASH = keccak(new TextEncoder().encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const domainSeparator = () => keccak(unhex(hex(DOMAIN_TYPEHASH) + hex(keccak(new TextEncoder().encode(TOK.domainName))).slice(2) + hex(keccak(new TextEncoder().encode(TOK.domainVersion))).slice(2) + pad(BigInt(C.chainId)) + padAddr(USDC)));
$("btn-wd").addEventListener("click", once(async () => {
  try {
    if (!wd || !keys) return;
    const to = $("wd-to").value.trim();
    if (!isAddr(to)) throw new Error("enter a destination address");
    if (acct && to.toLowerCase() === acct) throw new Error("Refused: that is the wallet your keys came from. Sending there would tie this payment to your public address.");
    if (wd.payer && to.toLowerCase() === wd.payer.toLowerCase()) throw new Error("Refused: that is the wallet that paid you. Sending it back links the two.");
    if (found.some(f => f.stealth.toLowerCase() === to.toLowerCase()) && !confirm("That is another of your stealth addresses. Pooling payments links them to each other. Continue?")) return;
    const all = wd.usdc; const amtIn = $("wd-amt").value.trim();
    const exact = amtIn ? calcAmounts({ src: "amount", text: amtIn, decimals: TOK.decimals, fee: 0n }) : null;      // exact decimals, no floats (1098 I-1)
    if (amtIn && !exact) throw new Error("enter the amount as a plain number");
    const value = amtIn ? exact.send : all;
    if (!(value > 0n) || value > all) throw new Error("amount must be within the balance");
    const w = wd, hit = hitOf(w);
    if ((pendingWd.get(w.stealth.toLowerCase()) || 0) > Date.now() && !confirm("An earlier withdrawal from this address was sent to the network and has not been confirmed yet. Sending again may pay twice. Check the explorer first. Send anyway?")) return;
    if (!hit || hit.stealth.toLowerCase() !== w.stealth.toLowerCase()) throw new Error("could not re-derive the key for this address");
    // audit 1086 L-4: the token's own DOMAIN_SEPARATOR() read from the chain RPC / the wallet (not from our indexer, which would only prove config drift)
    const dsep = await chainRpc(C.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: USDC, data: "0x3644e515" }, "latest"] }) }, true).then(r => r.json()).then(j => j.result).catch(() => null);
    if (String(dsep).toLowerCase() !== hex(domainSeparator()).toLowerCase()) throw new Error(SYM + " domain mismatch (or could not be read from the chain); refusing to sign");
    if ($("wd-private").checked && !$("wd-priv-wrap").hidden) {
      // audit 1087 M-3: the relayer only sees the 1Click deposit address, so the real recipient is screened here, before anything is signed (fail closed if the check cannot run)
      // the whole list is fetched and checked here, so the recipient never reaches our server; /relay/screen only while a relayer without the list endpoint is live
      const sl = await api("/relay/sanctions-list").catch(() => null), local = sl && Array.isArray(sl.addresses) && sl.addresses.length === sl.count && sl.count > 0;
      if (!local) say("pay-hint", "The sanctions list could not be loaded here, so this recipient address is checked by the relayer instead (it will see it).", "warn");     // 1101 I-1
      const sc = local ? { listed: sl.addresses.includes(to.toLowerCase()) } : await api("/relay/screen?addr=" + to).catch(() => null);
      if (!sc || sc.listed !== false) throw new Error(sc && sc.listed ? "That recipient address is on a sanctions list; refusing." : "Could not check the recipient against the sanctions list; nothing was sent. Try again.");
      return await privateWithdraw(to, value, hit);
    }
    const now = Math.floor(Date.now() / 1000); const validBefore = BigInt(now + 3600); const nonce = randomBytes32();
    const struct = hex(TYPEHASH) + padAddr(wd.stealth) + padAddr(to) + pad(value) + pad(0n) + pad(validBefore) + nonce.slice(2);
    const digest = keccak(unhex("0x1901" + hex(domainSeparator()).slice(2) + hex(keccak(unhex(struct))).slice(2)));
    const sig = signDigest(digest, unhex(hit.stealthPriv));
    say("pay-hint", "Sending through the relayer…");
    const { r, d } = await postRelay(fetch, API + "/relay", { from: w.stealth, to, value: value.toString(), validAfter: "0", validBefore: validBefore.toString(), nonce, v: sig.v, r: sig.r, s: sig.s },
      { onBusy: m => say("pay-hint", m, "warn"), check: () => authorizationUsed(rpcOne, USDC, w.stealth, nonce) });
    if (!r.ok || d.error) throw new Error(d.error || "relayer error");
    if (d.used) d.hash = await txOfLogs({ address: USDC, topics: [AUTH_USED_TOPIC, "0x" + padAddr(w.stealth), nonce] }, () => true);      // 1101 L-1: found by THIS request's nonce, not by "an identical transfer"
    if (!isHash(d.hash)) throw new Error("the relayer answered without a valid transaction hash; check the explorer before sending again");
    $("withdraw").hidden = true; pendingWd.set(w.stealth.toLowerCase(), Date.now() + 600_000);
    say("pay-hint", "Submitted: " + fmtTok(value) + " " + SYM + " → " + to.slice(0, 8) + "… waiting for the block…");
    const rc = await waitReceipt(d.hash, x => hasTransfer(x, { token: USDC, from: w.stealth, to, value }) && hasAuthUsed(x, { token: USDC, authorizer: w.stealth, nonce }), true);
    if (!rc.ok && !rc.unexpected) pendingWd.delete(w.stealth.toLowerCase());
    if (!rc.ok) throw new Error(rc.unexpected ? "the transaction is mined but does not contain the expected transfer (tx " + rc.hash.slice(0, 12) + "…). Check the explorer." : "the transfer reverted on chain (tx " + rc.hash.slice(0, 12) + "…). Nothing moved.");
    d.hash = rc.hash; pendingWd.delete(w.stealth.toLowerCase());
    spent.set(w.stealth.toLowerCase(), { left: w.usdc - value, until: Date.now() + 120_000 });
    const doneMsg = "Done: " + fmtTok(value) + " " + SYM + " sent, tx " + d.hash.slice(0, 12) + "…";
    say("pay-hint", doneMsg, "ok"); await scan();
    $("pay-hint").textContent = doneMsg + "\n" + $("pay-hint").textContent;                // the rescan's status must not erase the confirmation
  } catch (e) { say("pay-hint", e.message || String(e), "bad"); }
}));
// audit 1098 L-4: the final receipt (and the Transfer / Paid event that proves it is the thing we wanted) is read from the chain RPC. The API is only asked for a replacement hash
// of a relayed transaction, and that hash is followed only if the chain shows the same sender and nonce. -> { ok, hash, unexpected? }
async function waitReceipt(h, expect = null, relayed = false) {
  if (!isHash(h)) throw new Error("bad transaction hash");
  try { return await waitFinal(rpcOne, h, { expect, follow: relayed ? () => api("/relay/status?hash=" + h).then(s => s && s.hash) : null }); }
  catch (e) { if (/^not mined yet/.test(e.message || "")) throw new Error("The transaction was handed to the network but is not confirmed yet (tx " + h + "). It may still go through: check the explorer and your balance before sending again."); throw e; }
}
// a relayed request whose answer was lost but whose authorization is used on chain: find its transaction from the event it produced
async function txOfLogs(filter, match) {
  for (let i = 0; i < 20; i++) {
    const l = (await recentLogs(rpcOne, filter)).filter(match).pop(); if (l) return l.transactionHash;
    await new Promise(z => setTimeout(z, 3000));
  }
  throw new Error("The payment is on chain but its receipt could not be found; check the explorer before doing anything else.");
}

// ---- pay someone: derive the one-time address, then hand off to payStealth() (the only code that builds/sends pay txs,
//      so the flow can be swapped without touching the rest)
/** Sends the payment + announcement from the payer's wallet. token: "TOKEN" (chain stablecoin) or "NATIVE". Returns the tx hash. */
async function payStealth({ token, amount, raw: rawIn = null, d, own = false }) {
  if (!STEALTHPAY) throw new Error("The pay contract is not deployed on " + C.name + " yet");
  const ephLen = pad(33n), ephData = d.ephPub.slice(2).padEnd(128, "0"), tagWord = d.viewTag.slice(2).padEnd(64, "0");
  if (token === "TOKEN" && !own) return payGasless({ amount, raw: rawIn, d, ephLen, ephData, tagWord });
  if (token === "TOKEN") {
    const raw = rawIn ?? BigInt(Math.round(amount * TUNIT));
    const al = BigInt(await wallet("eth_call", [{ to: USDC, data: "0xdd62ed3e" + padAddr(acct) + padAddr(STEALTHPAY) }, "latest"]));
    if (al < raw) {
      say("send-hint", "Approve " + amount + " " + SYM + " for the pay contract (1 of 2)…");
      const h = await wallet("eth_sendTransaction", [{ from: acct, to: USDC, data: "0x095ea7b3" + padAddr(STEALTHPAY) + pad(raw) }]);
      if (!(await waitReceipt(h)).ok) throw new Error("approve reverted");
    }
    const data = sel("payToken(address,uint256,address,bytes,bytes1)") + padAddr(USDC) + pad(raw) + padAddr(d.stealth) + pad(160n) + tagWord + ephLen + ephData;
    say("send-hint", "Pay + announce (" + (al < raw ? "2 of 2" : "1 of 1") + ")…");
    return wallet("eth_sendTransaction", [{ from: acct, to: STEALTHPAY, data }]);
  }
  const wei = BigInt(Math.round(amount * NUNIT));
  const data = sel("payETH(address,bytes,bytes1)") + padAddr(d.stealth) + pad(96n) + tagWord + ephLen + ephData;
  return wallet("eth_sendTransaction", [{ from: acct, to: STEALTHPAY, value: "0x" + wei.toString(16), data }]);
}
/** Token payment with ONE signature and no gas for the payer: EIP-3009 ReceiveWithAuthorization bound (via the nonce) to this exact
 *  stealth address, key, tag, fee and fee recipient; our relayer submits StealthPay.payWithAuthorization and takes `fee` from the amount. */
async function payGasless({ amount, raw: rawIn = null, d, ephLen, ephData, tagWord }) {
  const stats = await api("/relay/stats").catch(() => { throw new Error("The relayer is not reachable."); });
  if (!stats.pay_enabled || !isAddr(stats.relayer) || stats.pay_fee == null) throw new Error("Gasless payments are not available on " + C.name + " right now.");
  if (String(stats.stealthpay || "").toLowerCase() !== STEALTHPAY.toLowerCase()) throw new Error("The relayer serves a different StealthPay contract; refusing.");
  const raw = rawIn ?? BigInt(Math.round(amount * TUNIT)), fee = BigInt(stats.pay_fee), feeTo = stats.relayer;   // "you pay" = raw = what leaves the wallet; the fee comes out of it
  if (fee < 0n || fee >= raw) throw new Error("The amount is below the relayer fee (" + fmtTok(fee) + " " + SYM + ").");
  if (!feeWithinCap(fee, raw, BigInt(TUNIT))) throw new Error("The relayer asks " + fmtTok(fee) + " " + SYM + " in fees for a " + fmtTok(raw) + " " + SYM + " payment, which is more than this page accepts (max 1.00 and half of the payment). Refusing.");   // audit 1086 L-1
  const bal = BigInt(await wallet("eth_call", [{ to: USDC, data: "0x70a08231" + padAddr(acct) }, "latest"]));
  if (bal < raw) throw new Error("Your wallet holds less than " + amount + " " + SYM + ".");
  const args = { chainId: C.chainId, stealthPay: STEALTHPAY, token: USDC, stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee, feeRecipient: feeTo };
  const nonce = paymentNonce(args);
  const onchain = await wallet("eth_call", [{ to: STEALTHPAY, data: sel("paymentNonce(address,address,bytes,bytes1,uint256,address)") + padAddr(USDC) + padAddr(d.stealth) + pad(192n) + tagWord + pad(fee) + padAddr(feeTo) + ephLen + ephData }, "latest"]);
  if (String(onchain).toLowerCase() !== nonce.toLowerCase()) throw new Error("Payment nonce mismatch between this page and the contract; refusing to sign.");
  const msg = "You send " + fmtTok(raw) + " " + SYM + ". The receiver gets " + fmtTok(raw - fee) + " " + SYM + ". The relayer fee for the gas is " + fmtTok(fee) + " " + SYM + " (to " + feeTo + "). You pay no gas.";
  say("send-hint", msg + " Sign in your wallet…");
  if (!confirm(msg + "\n\nContinue and sign?")) throw new Error("Cancelled. Nothing was signed.");
  const validBefore = Math.floor(Date.now() / 1000) + 3600;
  const typed = receiveTypedData({ token: TOK, chainId: C.chainId, from: acct, stealthPay: STEALTHPAY, amount: raw, validAfter: 0, validBefore, nonce });
  const sig = splitSig(await wallet("eth_signTypedData_v4", [acct, typed]));
  say("send-hint", "Sending through the relayer…");
  const { r, d: j } = await postRelay(fetch, API + "/relay/pay", {
    token: USDC, amount: raw.toString(), stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: fee.toString(), feeRecipient: feeTo,
    auth: { from: acct, validAfter: "0", validBefore: String(validBefore), v: sig.v, r: sig.r, s: sig.s } },
    { onBusy: m => say("send-hint", m, "warn"), check: () => authorizationUsed(rpcOne, USDC, acct, nonce) });
  if (!r.ok || j.error) throw new Error((j.error || "relayer error") + ".");
  if (j.used) j.hash = await txOfLogs({ address: STEALTHPAY, topics: [PAID_TOPIC, "0x" + padAddr(d.stealth)] }, () => true);
  if (!isHash(j.hash)) throw new Error("The relayer answered without a valid transaction hash; check the explorer and your balance before paying again.");
  say("send-hint", "Submitted, tx " + j.hash.slice(0, 12) + "… waiting for the block…");
  return j.hash;
}
// ---- amount: two linked fields, "you pay" and "receiver gets"; editing one fills the other using the relayer's gasless fee
let payFee = null, amtSrc = "amount";
api("/relay/stats").then(s => { if (s.pay_enabled && s.pay_fee != null) payFee = BigInt(s.pay_fee); calc(); }).catch(() => {});
const curFee = () => $("token").value === "TOKEN" ? (payFee ?? 0n) : 0n, unit = () => $("token").value === "TOKEN" ? TUNIT : NUNIT;
/** Returns { send, get, fee } in token units from the field the user last edited, or null. */
function payAmounts() {
  return calcAmounts({ src: amtSrc, text: $(amtSrc).value, decimals: Math.round(Math.log10(unit())), fee: curFee() });   // exact decimals, see pay-auth.js
}
function calc() {
  const out = $("pay-calc"), a = payAmounts(), other = amtSrc === "amount" ? "amount-get" : "amount", u = unit();
  $(other).value = a ? String(Number(amtSrc === "amount" ? a.get : a.send) / u) : "";
  if (a && a.get <= 0n) { $(other).value = ""; out.textContent = "Minimum is above the " + fmtTok(a.fee) + " " + SYM + " network fee."; return; }
  out.textContent = $("token").value !== "TOKEN" ? "Gas is paid from your wallet." : payFee != null ? "Network fee " + fmtTok(payFee) + " " + SYM + " included" : "";
}
["amount", "amount-get"].forEach(id => $(id).addEventListener("input", () => { amtSrc = id; calc(); }));
$("token").addEventListener("change", calc);
async function doPay(own) {
  try {
    if (!acct && !(await connect())) return;
    let metaIn = $("to-meta").value.trim();
    try { const u = new URL(metaIn); metaIn = u.searchParams.get("to") || metaIn; } catch {}
    const mc = chainOfMeta(metaIn);
    if (mc && mc.key !== C.key) throw new Error("This meta-address is for " + mc.name + ". Open this page with ?chain=" + mc.key + " to pay it.");
    const m = parseMeta(metaIn);
    await ensureChain();
    const token = $("token").value, a = payAmounts(); if (!a) throw new Error("enter an amount");
    const amount = Number(a.send) / unit();
    if (a.get <= 0n) throw new Error("the amount is below the network fee");
    const d = deriveForPayment(m);
    say("send-hint", "Paying " + amount + " " + (token === "TOKEN" ? SYM : NAT) + " to a fresh address " + d.stealth.slice(0, 10) + "…");
    const tx = await payStealth({ token, amount, raw: token === "TOKEN" ? a.send : null, d, own });   // raw = exactly what leaves the wallet, no float round trip
    const want = token === "TOKEN" ? { stealthPay: STEALTHPAY, stealth: d.stealth, token: USDC, amount: own ? a.send : a.get } : { stealthPay: STEALTHPAY, stealth: d.stealth, token: ETH_TOKEN };
    const rc = await waitReceipt(tx, x => hasPaid(x, want), token === "TOKEN" && !own);
    if (!rc.ok) throw new Error(rc.unexpected ? "the transaction is mined but the pay contract did not record this payment (tx " + rc.hash + "). Check the explorer." : "the payment reverted: " + tx);
    say("send-hint", "Paid. tx " + rc.hash.slice(0, 12) + "… The receiver will find it with their keys.", "ok");
  } catch (e) { say("send-hint", e.message || String(e), "bad"); }
}
const doPayOnce = once(doPay);
$("btn-pay").addEventListener("click", () => doPayOnce(false));
