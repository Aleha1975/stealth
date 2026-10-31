import { keysFromSignature, keyRequestTypedData, metaAddress, parseMeta, deriveForPayment, checkAnnouncement, decodeMetadata, hex, unhex, keccak, signDigest, randomBytes32 } from "./stealth-crypto.js";
import { postRelay } from "./relay-post.js";
import { paymentNonce, receiveTypedData, splitSig, payAmounts as calcAmounts, feeWithinCap, payFeeFor } from "./pay-auth.js";
import { CHAINS, pickChain, chainOfMeta, addChainParams, appFeesOf } from "./chains.js";
import * as PW from "./private-withdraw.js";
import { hopCard, hopView, statusLine } from "./hop-card.js";
import { getBalances, fetchBatch, authorizationUsed, waitFinal, hasTransfer, hasPaid, hasAuthUsed, recentLogs, logSpanSince, timeoutSignal, TRANSFER_TOPIC, PAID_TOPIC, AUTH_USED_TOPIC, ETH_TOKEN } from "./chain-read.js";

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
  try { if ($("fast-resume")) { showFastBox(); if (acct && fastDeferred) { fastDeferred = false; resumeFast().catch(() => {}); } } } catch {}      // 1132 M-1: this account's recovery notes (a try/catch, not a typeof check: showFastBox is hoisted, the bindings it reads are not). 1135 L-4: records that waited for an account are followed now
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
      const r = await fetch(API + "/pages/p" + String(k).padStart(6, "0") + ".json?v=" + man.version, { signal: timeoutSignal(60000) });      // 1109 L-2
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
// 1109 L-1: armed BEFORE the request leaves, kept until the signed authorization expires (validBefore) and persisted, so a reload or a second tab does not lose it. Cleared only by a confirmed outcome.
const PW_KEY = "stealth-pending-wd";
// 1121 L-1: the in-memory copy is ALWAYS consulted too (per key the later expiry wins), so a storage that reads fine but refuses writes cannot hide an armed guard.
const pendingWd = { _m() { let s = {}; try { s = JSON.parse(localStorage.getItem(PW_KEY) || "{}") || {}; } catch {} const m = { ...(this._mem || {}) }; for (const k of Object.keys(s)) if (!(Number(m[k]) >= Number(s[k]))) m[k] = s[k]; return m; }, _w(m) { this._mem = m; try { localStorage.setItem(PW_KEY, JSON.stringify(m)); } catch {} },
  get(k) { const v = Number(this._m()[k]); return v > Date.now() ? v : 0; }, set(k, until) { const m = this._m(); m[k] = until; this._w(m); }, delete(k) { const m = this._m(); delete m[k]; this._w(m); } };
const spent = new Map();   // stealth -> { left, until }
async function scan() {
  if (!keys) { say("pay-hint", "Derive your keys first (Receive tab).", "bad"); return; }
  if (lostDone.size) { lostDone.clear(); renderHops(); }      // a new Scan retires the old results
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
  try { const r = await fetch(API + "/pages/manifest.json", { cache: "no-cache", signal: timeoutSignal() }); if (r.ok) { const m = await r.json(); if (m && m.chain === C.key && m.page_size === 1024 && Number.isInteger(m.full_pages) && m.full_pages >= 0 && m.full_pages <= 100000 && Number.isInteger(m.tail_since_id)) man = m; } } catch {}
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
  found = mine; render(); showResume().catch(() => {}); resumeFast().catch(() => {});      // 1101 M-1: the payments are listed BEFORE any balance is read; a failing RPC can no longer hide them
  const unread = await refreshBalances(true);
  checkLost().catch(() => {});      // 1130 G: in the background; a failure only means no card
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
      if (!x) { f.usdc = null; unread++; continue; }      // 1109 I-5: a failed re-read never keeps an old amount (and its Withdraw button) on screen
      f.usdc = x.usdc; f.eth = x.eth; const sp = spent.get(f.stealth.toLowerCase()); if (sp && Date.now() < sp.until && f.usdc > sp.left) f.usdc = sp.left; }
  } };
  await Promise.all(Array.from({ length: Math.min(3, pages.length) }, worker));
  if (redraw && list === found) render();
  return unread;
}
// ---- private transfers in flight or unfinished: stealth -> { f, hit, st, msg, running, extra }; drawn as cards at the top of My payments
const fastBusy = new Set();     // stealth addresses with a "private, fast" withdraw running in this tab
const autoTries = new Map(), hops = new Map(), TERMINAL = ["DONE", "FAILED_IN", "FAILED"];
const activeHop = f => { const h = hops.get(f.stealth.toLowerCase()); return h && !TERMINAL.includes(h.st.step) ? h : null; };
function renderHops() {
  const box = $("hop-resume"); box.textContent = "";
  for (const [k, h] of hops) box.appendChild(hopCard(h, { onContinue: b => { b.disabled = true; runHop(h.f, h.hit, null, { interactive: true }).catch(e => say("pay-hint", e.message || String(e), "bad")); },
    onFunds: b => { b.disabled = true; runHop(h.f, h.hit, null, { interactive: true }).catch(e => say("pay-hint", e.message || String(e), "bad")); }, onDismiss: () => { hops.delete(k); renderHops(); },
    onReturn: (b, card) => { b.disabled = true; returnZec(h, card).catch(e => { b.disabled = false; say("pay-hint", e.message || String(e), "bad"); }); } }));
  for (const [k, l] of lost) if (!hops.has(k)) box.appendChild(lostCard(k, l));
  for (const [k, d] of lostDone) { const c = el("div", "hop " + (d.ok ? "ok" : "warn")), b = el("button", "btn ghost", "Dismiss"); b.type = "button"; b.addEventListener("click", () => { lostDone.delete(k); renderHops(); }); c.appendChild(el("div", "hop-line", d.text)); const a = el("div", "row hop-act"); a.appendChild(b); c.appendChild(a); box.appendChild(c); }      // the result of a Return on a lost wallet outlives its card and every redraw
  box.hidden = !hops.size && !lost.size && !lostDone.size;
}
// ---- 1130 G: a private transfer whose record this browser lost (cleared storage, another device). The hop seed is a function of the stealth key, so after Scan the hop t-addresses of a payment that now holds nothing
// (and has no local record) are asked for UTXOs: one cheap call each, no wallet sync, rate limited. A finding becomes a card with Return money / Continue; shielded ZEC needs a wallet sync, so it has its own button.
const lost = new Map(), lostBusy = { v: false }, LOST_CHECK_KEY = "stealth-lost-checked", LOST_RECHECK_MS = 6 * 3600_000, LOST_PER_PASS = 10;
const lostSeen = { read() { try { const o = JSON.parse(localStorage.getItem(LOST_CHECK_KEY) || "{}"); return o && typeof o === "object" ? o : {}; } catch { return {}; } },
  fresh(k) { return Date.now() - (Number(this.read()[k]) || 0) < LOST_RECHECK_MS; }, unmark(k) { const o = this.read(); delete o[k]; try { localStorage.setItem(LOST_CHECK_KEY, JSON.stringify(o)); } catch {} }, mark(k) { const o = this.read(); o[k] = Date.now(); const ks = Object.keys(o); if (ks.length > 500) for (const x of ks.slice(0, ks.length - 500)) delete o[x]; try { localStorage.setItem(LOST_CHECK_KEY, JSON.stringify(o)); } catch {} } };
const lostNone = new Map();      // payments checked on the chain with nothing found -> the range looked at; they get the explicit "Check shielded balance" button
// LOSTDONE-BEGIN: the final line of a Return money on a lost wallet (k = stealth address). The card it was written on goes with lostForget and every rescan, so it is kept here until Dismiss or the next Scan
const lostDone = new Map(), lostSay = (k, text, ok) => { lostDone.set(k, { text, ok: !!ok }); };
// LOSTDONE-END
const lostForget = k => { lost.delete(k); lostNone.delete(k); lostSeen.unmark(k); };
const zecText = z => (Number(z) / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
// 1136 F-2: the range of hop wallets looked at is always said (1-based), with what was NOT looked at when the cap cut it
const scanText = r => r && r.top > r.lo ? "Looked at transfer wallet" + (r.top - r.lo > 1 ? "s " + (r.lo + 1) + "–" + r.top : " " + r.top) + (r.capped ? "; " + r.lo + " older wallet" + (r.lo > 1 ? "s were" : " was") + " not looked at." : ".") : "";
async function setLost(HM, k, f, hit, res) {      // res: a findLostFunds result (or one merged with an older scan)
  if (!res.found.length) { lostNone.set(k, res); return; }
  let tip = null; try { tip = await (await import("./zec-return.js")).getTip((await import("./chains.js")).zcash.lightwalletd); } catch {}      // 1133 M-1: no tip = young (fail closed)
  lost.set(k, { f, hit, ...res, n: res.found[0].n, young: HM.lostYoung(res.found, tip), contAcct: HM.lostContinueAcct(res.found) });
}
async function checkLost() {
  if (!keys || lostBusy.v || !indexedDB) return; lostBusy.v = true;
  try {
    const HM = await hopMod(), store = HM.idbStore(), sleep = ms => new Promise(r => setTimeout(r, ms)); let done = 0;
    for (const f of found.slice()) {
      if (done >= LOST_PER_PASS) break;
      const k = f.stealth.toLowerCase(); if (f.legacy || f.usdc !== 0n || (hops.get(k) || {}).running || lost.has(k) || lostNone.has(k) || lostSeen.fresh(k)) continue;
      const hit = hitOf(f); if (!hit || hit.stealth.toLowerCase() !== k) continue;
      const ctx = { store, stealth: f.stealth, priv: hit.stealthPriv, words: await HM.loadWords(), getUtxos: HM.makeGetUtxos(), sleep };
      let cnt = null; try { cnt = await HM.makeCountPriorHops(C, chainRpc)(f.stealth); } catch {}
      if (cnt === 0) { lostSeen.mark(k); continue; }       // no authorization was ever spent from this address: no hop can exist
      if (cnt != null) ctx.priorHops = cnt;
      done++; const res = await HM.findLostFunds(ctx);
      if (res.error) continue;                              // not marked: the next Scan tries again
      if (!res.capped) lostSeen.mark(k);                    // 1136 F-2: a result that left older wallets unread is not "checked" for 6 h (this page still asks once: lostNone / lost)
      if (res.skipped) continue;
      await setLost(HM, k, f, hit, res);
      renderHops(); render();
    }
  } finally { lostBusy.v = false; }
}
// 1136 F-2: the explicit way to read the wallets below the range already looked at; the richer find is shown, the range widens
async function lostOlder(k, f, hit, line) {
  const HM = await hopMod(), prev = lost.get(k) || lostNone.get(k); if (!prev || !prev.capped) return;
  line.textContent = "Looking at older transfer wallets…";
  const res = { found: [], total: 0n, ...(await HM.findLostFunds({ store: HM.idbStore(), stealth: f.stealth, priv: hit.stealthPriv, words: await HM.loadWords(), getUtxos: HM.makeGetUtxos(), sleep: ms => new Promise(r => setTimeout(r, ms)), before: prev.lo })) };
  if (res.error) throw new Error(res.error);
  const keepPrev = prev.found && prev.found.length && (prev.total >= (res.total || 0n) || !res.found.length), range = { lo: res.lo, top: prev.top, capped: res.capped };
  lostNone.delete(k); await setLost(HM, k, f, hit, keepPrev ? { ...prev, ...range } : { ...res, ...range }); renderHops(); render();
}
function lostCard(k, l) {
  const card = el("div", "hop warn"), line = el("div", "hop-line"), acts = el("div", "row hop-act"), older = l.maxLocal != null && l.n < l.maxLocal;
  card.appendChild(el("div", "hop-t", "Unfinished private transfer found: " + zecText(l.total) + " ZEC" + (l.shielded ? " (shielded)" : "")));
  const why = l.young ? "The ZEC arrived recently, so this transfer may still be running on another device. It is available here later (about 2 hours after it arrived); nothing can be sent or returned from this card yet."      // 1133 M-1
    : older ? "This is an earlier transfer wallet of this address, and a newer transfer record exists in this browser, so it cannot be continued from here." + (l.found.length ? " Return money still works." : "")
    : "This browser has no record of it (storage was cleared, or it ran on another device), but the ZEC is still on the transfer's temporary wallet, rebuilt from your key. " + (l.shielded && !l.found.length ? "Continue sends it on to a recipient you enter now." : l.shielded || l.found.length ? "Return it to your wallet" + (l.shielded || l.contAcct == null ? " first (it sweeps every account, in rounds)." : ", or continue the transfer to a recipient you enter now.") : "") + (l.truncated ? " More outputs exist than could be read at once; Return money handles them in rounds." : "");      // truncated = one address's list was cut; the wallet cap is capped (scanText)
  card.appendChild(el("div", "hop-line", why)); if (!l.young && scanText(l)) card.appendChild(el("div", "note", scanText(l))); card.appendChild(line);
  const btn = (txt, cls, fn) => { const b = el("button", "btn " + cls, txt); b.type = "button"; b.addEventListener("click", () => fn(b)); acts.appendChild(b); return b; };
  const fail = (b, e) => { if (b) b.disabled = false; line.textContent = (e && e.message) || String(e); };
  if (l.young) btn("Check again", "ghost", b => { lostForget(k); renderHops(); checkLost().catch(() => {}); });
  else {
    if (l.found.length) btn("Return money", "", b => { b.disabled = true; lostReturn(k, l, card).catch(e => fail(b, e)).finally(() => { b.disabled = false; }); });      // 1136 F-4: from the keys alone, any wallet, no record
    const canContinue = !older && self.crossOriginIsolated && (l.shielded ? !l.found.length : l.contAcct != null);      // 1133 L-4: one account only; ZEC on several accounts goes back first. Continue needs a record, so not on an earlier wallet
    if (canContinue) btn("Continue", "ghost", b => { const f = el("div", "row"); const inp = el("input"); inp.placeholder = "Recipient address 0x…"; inp.setAttribute("aria-label", "Recipient address"); inp.autocomplete = "off"; inp.spellcheck = false;
      const go = el("button", "btn", "Continue transfer"); go.type = "button"; go.addEventListener("click", () => { go.disabled = true; lostContinue(k, l, inp.value.trim(), line).catch(e => { go.disabled = false; line.textContent = (e && e.message) || String(e); }); });
      f.appendChild(inp); f.appendChild(go); card.insertBefore(f, acts); b.disabled = true; line.textContent = "Enter the recipient again: it cannot be read from the chain. It is checked like a normal withdraw."; });
    if (!l.shielded && !older) btn("Check shielded balance", "ghost", b => { b.disabled = true; lostShielded(k, l.f, l.hit, line).catch(e => fail(b, e)).finally(() => { b.disabled = false; }); });
    if (l.capped) btn("Scan older wallets", "ghost", b => { b.disabled = true; lostOlder(k, l.f, l.hit, line).catch(e => fail(b, e)); });
  }
  card.appendChild(acts); return card;
}
const blockTimeSec = async n => { const b = await rpcOne("eth_getBlockByNumber", ["0x" + Number(n).toString(16), false]); const t = b && Number(BigInt(b.timestamp)); if (!Number.isFinite(t)) throw new Error("could not read the payment's block time"); return t; };
// shielded ZEC needs a wallet sync (minutes), so it only runs on this button
async function lostShielded(k, f, hit, line) {
  if (!self.crossOriginIsolated) throw new Error("This page cannot run the Zcash wallet here (it is not cross-origin isolated).");
  const HM = await hopMod(), base = await hopCtx(HM, f, hit, {}); let cnt = null; try { cnt = await base.countPriorHops(f.stealth); } catch {}
  if (cnt === 0) { line.textContent = "No private transfer was ever started from this address."; return; }
  const bt = await blockTimeSec(HM.firstBlock(found, f.stealth) || f.block), prev = lost.get(k) || {}, rg = HM.lostRange(cnt, await HM.localNs(base.store, f.stealth), (prev.top != null ? prev : lostNone.get(k) || {}).top); let best = null;      // 1133 I-4: the note cannot predate the FIRST payment to this address
  for (const n of rg.ns) {      // 1133 L-4: every wallet is looked at (bounded by LOST_MAX_N) and the richest wins; transparent ZEC already found counts for its own wallet
    line.textContent = "Syncing the Zcash wallet to look for shielded ZEC (hop wallet " + (n + 1) + ")… this takes a few minutes. Keep this tab open.";
    const rows = await HM.hopSummary({ ...base, n, blockTimeSec: bt, nAccts: HM.scanAccts(null) }, null), row = rows.filter(x => x.orchard >= HM.HOLD_DUST).sort((a, b) => (b.orchard > a.orchard ? 1 : -1))[0];
    if (row) { const sum = row.orchard + (prev.found && prev.found.length && prev.n === n ? prev.total : 0n); if (!best || sum > best.sum) best = { n, row, rows, sum }; }
  }
  if (!best) { line.textContent = "No shielded ZEC found. " + scanText(rg); if (lostNone.has(k)) lostNone.set(k, { ...lostNone.get(k), lo: rg.lo, top: rg.top, capped: rg.capped }); return; }
  const keep = prev.found && prev.n === best.n;      // transparent findings of another wallet are not mixed in; a note says they exist
  const other = prev.found && prev.found.length && !keep ? " Transparent ZEC (" + zecText(prev.total) + ") also sits on another transfer wallet of this address; recover this one first, then check again." : "";
  lost.set(k, { ...prev, f, hit, n: best.n, found: keep ? prev.found : [], total: best.row.orchard + (keep ? prev.total : 0n), young: keep ? prev.young : false, contAcct: keep ? prev.contAcct : null, maxLocal: rg.maxLocal, lo: rg.lo, top: rg.top, capped: rg.capped, truncated: !!(keep && prev.truncated), shielded: { account: best.row.account, blockTimeSec: bt } });
  line.textContent = other.trim(); lostNone.delete(k); renderHops(); render();
}
const lostLock = stealth => fn => underHopLock(stealth, fn);      // 1133 M-2: the app's own hop lock around find + write (undefined = another tab holds it)
const NOT_ADOPTED = r => new Error(r.reason === "newer" ? "A newer transfer record exists in this browser, so this earlier transfer wallet cannot be continued from here. Return money still works." : "A transfer record for this payment already exists in this browser (another tab or an earlier press). Nothing was changed; reload and use its card.");
// 1133 M-1: re-checked at the moment of the click with a fresh tip, not only when the card was drawn (Continue; Return re-checks the very outputs it sweeps, in returnZec)
async function lostGuard(l) {
  const ZR = await import("./zec-return.js"), { zcash: ZC } = await import("./chains.js"), HM = await hopMod(); let tip = null; try { tip = await ZR.getTip(ZC.lightwalletd); } catch {}
  if (l.found.length && HM.lostYoung(l.found, tip)) { l.young = true; renderHops(); throw new Error("This may still be running on another device: its ZEC is too recent to touch. Try again in about 2 hours."); }
}
// 1136 F-4: Return needs only the keys: no record is adopted, so every recoverable wallet keeps its Return button (h.lost marks the card the result comes back to)
const lostReturn = (k, l, card) => returnZec({ f: l.f, hit: l.hit, running: false, msg: "", st: { n: l.n }, lost: k }, card);
async function lostContinue(k, l, to, line) {
  if (!self.crossOriginIsolated) throw new Error("This page cannot run the Zcash wallet here (it is not cross-origin isolated).");
  if (!vetRecipient(to, l.f)) { line.textContent = "Cancelled."; return; }
  await lostGuard(l);
  line.textContent = "Checking the recipient…"; await screenRecipient(to);
  const HM = await hopMod(), { zcash: ZC } = await import("./chains.js"), ZR = await import("./zec-return.js"), ctx = { store: HM.idbStore(), stealth: l.f.stealth, lock: lostLock(l.f.stealth) };
  let birthday, account, zats = l.total;
  if (l.shielded) { if (l.found.length) throw new Error("ZEC also sits on the transparent addresses: press Return money first."); birthday = HM.birthdayFromTime(l.shielded.blockTimeSec, await ZR.getTip(ZC.lightwalletd)); account = l.shielded.account; }
  else { account = HM.lostContinueAcct(l.found); if (account == null) throw new Error("The ZEC is on several accounts: press Return money first, it sweeps all of them."); zats = l.found.reduce((s, x) => s + x.value, 0n); const hs = l.found.map(x => x.height).filter(x => x > 0); birthday = (hs.length ? Math.min(...hs) : (await ZR.getTip(ZC.lightwalletd)) - 5000) - 10; }
  const r = await HM.adoptLostHop(ctx, { n: l.n, account, birthday, zats, recipient: to, chain: C, dest: C });
  if (!r.created) throw NOT_ADOPTED(r);      // 1133 L-1: never run on another record's recipient
  lost.delete(k); renderHops(); render(); await runHop(l.f, l.hit, null, { interactive: true });
}
// 1105 L-4: every writer of a hop record outside the machine takes the machine's own Web Lock (non-blocking). If the hop is running (or another writer is) the write is skipped, never interleaved.
const underHopLock = (stealth, fn) => navigator.locks ? navigator.locks.request("zec-hop:" + stealth.toLowerCase(), { ifAvailable: true }, l => l ? fn() : undefined) : fn();
// 1136 F-4: the sweep intent (recorded before the broadcast; it is what stops a second sweep and lets a reload follow the swap) is kept per hop wallet (stealth#n), not in a hop record: Return works on a wallet that has none
const SWEEP_KEY = "stealth-sweep-intents", sweepIntents = { key: h => h.f.stealth.toLowerCase() + "#" + (h.st.n || 0), all() { try { const o = JSON.parse(localStorage.getItem(SWEEP_KEY) || "{}"); return o && typeof o === "object" ? o : {}; } catch { return {}; } },
  get(h) { return this.all()[this.key(h)] || null; }, set(h, v) { const o = this.all(); o[this.key(h)] = v; const ks = Object.keys(o); if (ks.length > 200) for (const x of ks.slice(0, ks.length - 200)) delete o[x]; try { localStorage.setItem(SWEEP_KEY, JSON.stringify(o)); return localStorage.getItem(SWEEP_KEY) === JSON.stringify(o); } catch { return false; } } };
// ZEC stuck on the hop t-address (shielding is refused since NU6.3): sign a plain transparent tx here and swap it back to the connected wallet
async function returnZec(h, card) {
  const [HM, ZR] = await Promise.all([hopMod(), import("./zec-return.js")]), { zcash: ZC } = await import("./chains.js");
  if (!acct) throw new Error("Connect your wallet first.");
  const line = el("div", "hop-line", "Looking for the ZEC…"); card.appendChild(line); const step = t => { line.textContent = t; };
  const seed = await HM.mnemonicSeed(await HM.mnemonicFor(h.hit.stealthPriv, await HM.loadWords(), h.st.n || 0));
  let key = null, utxos = [], unspendable = false;
  for (let a = 0; a < HM.scanAccts(h.st) && !utxos.length; a++) for (let i = 0; i < HM.SCAN_INDEXES && !utxos.length; i++) {      // 1129 F-1: ONE rule for the range (max mode uses accounts 0-4)
    key = ZR.deriveT(seed, ZR.tPath(a, i)); const raw = await ZR.getUtxos(ZC.lightwalletd, key.addr); utxos = ZR.sweepSet(raw);
    if (!utxos.length && (raw.length || raw.truncated)) unspendable = true;      // 1103 M-1: dust only, or a list too long to read to the end: that is NOT "empty"
  }
  if (!utxos.length && unspendable) { step("This address holds only tiny outputs (below the network fee) or more outputs than can be read at once. Nothing was removed and nothing can be swept from them yet. Try again later."); return; }
  const prevOf = async () => sweepIntents.get(h) || await HM.findHop(HM.idbStore(), h.f.stealth).then(r => r && (r.rec.st.n || 0) === (h.st.n || 0) ? r.rec.st.sweep : null).catch(() => null);      // 1136 F-4: the intent lives beside the keys, not in a hop record (an older build's record is still read)
  const prevOk = p => p && /^[0-9a-f]{64}$/i.test(p.txid || "") && /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(p.deposit || "");
  if (!utxos.length) {                                   // the server lists nothing: that is an ANSWER of an untrusted server, not proof (1100 M-1). Never hide on one answer.
    // 1110 L-1: an unresolved sweep intent means the inputs are gone because the sweep went out: follow its swap (never count "empty" observations, never hide) until NEAR ends it
    const sp = await prevOf();
    if (prevOk(sp) && !sp.notSent) {
      if (!sp.ended) return await finishSweep(HM, h, step, { txid: sp.txid, deposit: sp.deposit, amountOut: sp.amountOut });
      if (sp.ended !== "SUCCESS" && Date.now() - (sp.endedAt || 0) < 3600_000) { step("The swap ended as " + sp.ended + ". The refund is on its way back to the hop address: press Return money again in a few minutes."); return; }
    }
    if (h.lost) { const t = "Nothing is listed on the transparent addresses now (moved already, or the server is behind). Scan checks again; the shielded balance has its own button."; lostSay(h.lost, t, false); lostForget(h.lost); step(t); renderHops(); return; }      // no record to count empty observations in: the card just goes, and is found again if the ZEC is still there
    step("Checking the shielded balance…");
    const r = await HM.findHop(HM.idbStore(), h.f.stealth), left = await HM.hopSummary(await hopCtx(HM, h.f, h.hit, null), r && r.rec);
    if (HM.holdsZec(left)) throw new Error("ZEC is still in the shielded pool. Press Continue transfer.");
    const v = await noteEmptyFor(HM, h, true);
    if (v.hide) { await hideHop(HM, h); step("Nothing left here, confirmed by repeated checks. Removed."); return; }
    step("The server says there is nothing here (" + ((v.obs && v.obs.count) || 1) + "/" + ZR.EMPTY_N + " checks, spread over at least 30 minutes). Not removed: rechecking. Press Return money again later."); return;
  }
  if (!h.lost) noteEmptyFor(HM, h, false).catch(() => {});
  const total = utxos.reduce((s, u) => s + u.value, 0n), amount = total - ZR.sweepFee(utxos.length);
  // 1138 M-1: the whole protocol (earlier unended intent of ANY age is followed or ended as EXPIRED; "busy" only for an intent the pre-check did not see) lives in zec-return.js runSweep
  const r = await ZR.runSweep({ prevOf, prevOk, get: () => sweepIntents.get(h), set: v => sweepIntents.set(h, v), lock: fn => underHopLock(h.f.stealth, fn),
    txKnownFn: id => ZR.txKnown(ZC.lightwalletd, id), tipFn: () => ZR.getTip(ZC.lightwalletd),
    midCheck: async () => {
      if (!h.lost) return false;      // 1136 F-3a: the age rule applies to the very outputs about to be swept (fresh query), not to the card's snapshot
      let tip = null; try { tip = await ZR.getTip(ZC.lightwalletd); } catch {}
      if (HM.lostYoung([HM.outputAge(utxos)], tip)) { step("This may still be running on another device: its ZEC is too recent to touch. Try again in about 2 hours."); return true; }
      return false; },
    quote: async () => {
      step("Getting a quote…");
      const j = await PW.requestQuote({ req: HM.reqOut({ dest: C, amount, recipient: acct, refundT: key.addr }), okDeposit: a => /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(a || "") });
      step("Sending " + (Number(amount) / 1e8) + " ZEC…");
      const sw = ZR.buildSweep({ utxos, key, to: j.quote.depositAddress, tip: await ZR.getTip(ZC.lightwalletd) });
      if (sw.amount !== BigInt(j.quote.amountIn)) throw new Error("amount mismatch; refusing");
      // 1133 L-3: the hop lock is held from recording the intent through the broadcast; the broadcast is bounded by its own request timeouts plus 5 min. 1100 L-2: the node must hand our exact bytes back before this counts as sent
      return { intent: { txid: sw.txid, deposit: j.quote.depositAddress, amountOut: j.quote.amountOut, at: Date.now(), expiry: sw.expiry }, send: () => HM.withTimeout(ZR.sendAndConfirm(ZC.lightwalletd, sw.raw, undefined, sw.txid), 5 * 60_000, "Zcash broadcast") }; } });
  if (r.stopped) return;
  await finishSweep(HM, h, step, r.follow ? { txid: r.follow.txid, deposit: r.follow.deposit, amountOut: r.follow.amountOut } : r.intent);
}
async function finishSweep(HM, h, step, sw) {
  let note = ""; await PW.submitDeposit({ txHash: sw.txid, depositAddress: sw.deposit }).catch(e => { note = " (could not notify NEAR Intents: " + ((e && e.message) || e) + ")"; });
  if (note) step("Sent" + note);
  const fin = await PW.pollStatus({ depositAddress: sw.deposit, timeoutMs: 60 * 60_000, intervalMs: 10_000, onUpdate: s => step("Returning · " + s.status.toLowerCase().replace(/_/g, " ") + " · usually 10–20 min" + note) });
  const settled = await (await import("./zec-return.js")).settleIntent({ lock: fn => underHopLock(h.f.stealth, fn), get: () => sweepIntents.get(h), set: v => sweepIntents.set(h, v), sw, status: fin.status });      // 1137 L-1 / 1110 L-1: every end settles the intent (SUCCESS too); 1138 M-1: retried while the hop machine holds the lock, never skipped silently
  const sh = h.lost && lost.get(h.lost) && lost.get(h.lost).shielded;      // 1137 L-2: a shielded finding is dropped with the card, so the Done text says it may remain
  const doneText = (fin.status === "SUCCESS" ? "Done: ≈ " + (Number(sw.amountOut) / 1e6).toFixed(2) + " " + SYM + " sent to your wallet." + (sh ? " Shielded ZEC was found on this wallet earlier and may remain: press Check shielded balance." : "") : "Swap ended as " + fin.status + ". The ZEC is back on the hop address; press Return money again.") + (settled ? "" : " (Could not mark this return as finished in this browser: if ZEC is still listed, press Return money again.)");
  step(doneText); if (h.lost) { lostSay(h.lost, doneText, fin.status === "SUCCESS"); renderHops(); }      // kept on its own card: the lost card is redrawn or removed below
  if (fin.status === "SUCCESS" && h.lost) { lostForget(h.lost); checkLost().catch(() => {}); }      // a lost wallet has no card to keep: it is looked for again, and any other wallet of this address shows up with its own Return
  else if (fin.status === "SUCCESS") {      // 1122 L-3: the transparent return worked, but the card goes away only when the hop wallet holds nothing at all (shielded ZEC included); a failed check keeps the card
    let left = null; try { const r = await HM.findHop(HM.idbStore(), h.f.stealth); left = await HM.hopSummary(await hopCtx(HM, h.f, h.hit, null), r && r.rec); } catch {}
    if (left && !HM.holdsZec(left)) await hideHop(HM, h); else step("Done: the payout was sent. The hop wallet may still hold some ZEC, so the card stays: press Return money again.");
  }
      // 1110 L-1: a non-SUCCESS intent is settled above (no endless resume) but kept so "empty" is not counted while the refund is still on its way
}
// A transfer from the first version (before Ironwood) could never shield, so its ZEC only ever sat on the hop t-addresses:
// once those are empty (returned) the record is history and shows nothing. Later versions are never hidden this way.
async function staleV1(HM, r, hit) {
  if (r.rec.st.v === 2) return { hide: false };
  try {
    const ZR = await import("./zec-return.js"), { zcash: ZC } = await import("./chains.js");
    const seed = await HM.mnemonicSeed(await HM.mnemonicFor(hit.stealthPriv, await HM.loadWords(), r.rec.st.n || 0));
    let empty = true;
    for (let a = 0; a < HM.scanAccts(r.rec.st) && empty; a++) for (let i = 0; i < HM.SCAN_INDEXES && empty; i++) if ((await ZR.getUtxos(ZC.lightwalletd, ZR.deriveT(seed, ZR.tPath(a, i)).addr)).length) empty = false;
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
  await underHopLock(h.f.stealth, async () => { const r = await HM.findHop(store, h.f.stealth); if (r) { r.rec.st = { ...r.rec.st, step: "FAILED", result: "RETURNED", hidden: true, earlierFunds: false }; await store.put(r.key, r.rec); } });
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
    const kk = f.stealth.toLowerCase();
    if (!hp && f.usdc === 0n && lostNone.has(kk) && !lost.has(kk) && (self.crossOriginIsolated || lostNone.get(kk).capped)) { const nr = lostNone.get(kk), d = el("div"), ln = el("div", "note", scanText(nr)), bar = el("div", "row"); d.style.marginTop = "8px"; d.appendChild(ln); d.appendChild(bar);      // 1136 F-2: an empty result says what it looked at
      const mk = (txt, fn) => { const b = el("button", "btn ghost", txt); b.type = "button"; b.addEventListener("click", () => { b.disabled = true; fn(kk, f, hitOf(f), ln).catch(e => { ln.textContent = (e && e.message) || String(e); }).finally(() => { b.disabled = false; }); }); bar.appendChild(b); };
      if (self.crossOriginIsolated) mk("Check shielded balance", lostShielded); if (nr.capped) mk("Scan older wallets", lostOlder); row.appendChild(d); }
    if (!hp && f.usdc > 0n) { const d = el("div"); d.style.marginTop = "8px"; const b = el("button", "btn ghost", "Withdraw " + SYM); b.type = "button"; b.addEventListener("click", () => openWithdraw(i)); d.appendChild(b); row.appendChild(d); }
    list.appendChild(row);
  });
}
$("btn-scan").addEventListener("click", once(() => scan().catch(e => say("pay-hint", e.message || String(e), "bad"))));

// ---- withdraw the stablecoin gaslessly: EIP-3009 authorization signed by the stealth key, submitted by the relayer
let wd = null;
function openWithdraw(i) {
  if (fastBusy.has(found[i].stealth.toLowerCase())) { $("withdraw").hidden = true; say("pay-hint", "A private withdraw from this payment is running: wait for it to finish.", "warn"); return; }
  if (activeHop(found[i])) { $("withdraw").hidden = true; say("pay-hint", "This payment has a transfer in progress: use the card above.", "warn"); return; }
  wd = found[i]; $("wd-from").textContent = wd.stealth; $("wd-to").value = ""; $("wd-amt").value = ""; $("withdraw").hidden = false;
  // Three ways to send (labels and ETAs come from code constants): standard (direct, gasless), private fast (NEAR Intents only), maximum privacy (the hidden Zcash hop, web/zec-hop.js:
  // only on a cross-origin isolated page and only if the module loads). Fast and maximum need a chain with 1Click and a non-legacy key.
  const mine = wd; $("wd-priv-wrap").hidden = true; setRoutes(null); pvReset();
  const dest = $("wd-dest"); dest.textContent = "";
  for (const k of [C.key]) {   /* one payout chain for now: the same chain */ const c = CHAINS[k]; if (c && c.oneClick && !Array.from(dest.options).some(o => o.value === c.key)) { const o = el("option", null, c.name + " (" + c.token.symbol + ")" + (c.key === C.key ? " · same chain" : "")); o.value = c.key; dest.appendChild(o); } }
  if (C.privateWithdraw && C.oneClick && !wd.legacy) {
    $("wd-priv-wrap").hidden = false; setRoutes(null);
    if (self.crossOriginIsolated) hopMod().then(HM => { if (wd === mine) setRoutes(HM); }).catch(() => {});
  }
}
// route select: std / fast / max. `HM` (the hop module) is only known once it has loaded; without it "max" is not offered.
const ROUTE_NOTE = {
  std: "Gasless, straight from the stealth address to the recipient. Anyone can see that link on-chain.",
  fast: "No Zcash: NEAR Intents swaps the money in 1–2 parts at random times. The link is broken by the swap, not by cryptography: someone who sees both sides and matches amounts and times can still connect them.",
  max: "Through the Zcash shielded pool and back, paid out in 2 parts, one after the other (the second follows as soon as the first has been sent, so the gap between them is not random). Keep this tab open; it can be resumed if you close it.",
};
function setRoutes(HM) {
  const sel = $("wd-route"), prev = sel.value, priv = !$("wd-priv-wrap").hidden; sel.textContent = "";
  const add = (v, t) => { const o = el("option", null, t); o.value = v; sel.appendChild(o); };
  add("std", "Standard · gasless, direct · " + PW.standardEtaLabel());
  if (priv) add("fast", "Private, fast · no Zcash · about " + PW.fastEtaLabel());
  if (priv && HM) add("max", "Maximum privacy · via Zcash · about " + HM.etaLabel(HM.DEFAULT_MODE));
  sel.value = Array.from(sel.options).some(o => o.value === prev) ? prev : (HM ? "max" : priv ? "fast" : "std");
  routeChanged();
}
const route = () => $("wd-route").value || "std";
function routeChanged() { $("wd-route-note").textContent = ROUTE_NOTE[route()]; $("wd-priv-opts").hidden = route() === "std"; pvReset(); }
// ---- private withdraw: preview (two dry quotes) first, then a second click starts the hop. Any input change drops the preview.
let pv = null, HOPM = null;
const hopMod = () => HOPM || (HOPM = import("./zec-hop.js"));
function pvReset() { pv = null; $("wd-quote").hidden = true; $("btn-wd").textContent = route() === "std" ? "Send without gas" : "Preview"; }
$("wd-route").addEventListener("change", routeChanged);
["wd-to", "wd-amt", "wd-dest"].forEach(id => { $(id).addEventListener("input", pvReset); $(id).addEventListener("change", pvReset); });
// wallet-RPC fallback, used ONLY for the token's domain separator (no stealth address in it); same JSON-RPC shape as fetch, so zec-hop.js stays injectable
const walletRpc = async (_u, init) => { const { method, params } = JSON.parse(init.body); try { if (method !== "eth_chainId" && String(await wallet("eth_chainId", [])).toLowerCase() !== CHAIN_HEX) throw new Error("your wallet is on another network than " + C.name); const result = await wallet(method, params); return { ok: true, json: async () => ({ result }) }; } catch (e) { return { ok: true, json: async () => ({ error: { message: String((e && e.message) || e) } }) }; } };
// chain reads: the chain's public RPC directly (CORS open, listed in the page CSP)
// 1101 L-3/L-5: reads that name a stealth address NEVER fall back to the wallet's provider (it already knows the account and IP); only `allowWallet` calls (the token's domain separator) may. All reads time out.
const chainRpc = async (u, init, allowWallet = false) => { try { const r = await fetch(u, { ...init, signal: init.signal || timeoutSignal() }); if (r.ok) { const j = await r.clone().json().catch(() => null); if (j && j.result !== undefined) return r; } } catch {} if (allowWallet) return walletRpc(u, init); throw new Error("the chain RPC did not answer"); };
// 1133 L-5: a rebuilt transfer has no original amount to check a quote against, so the user sees what was found, what is sent and what comes out, and confirms
const confirmRebuiltQuote = q => confirm("Found on the transfer wallet: " + zecText(q.zecFound) + " ZEC.\nThis payout sends " + zecText(q.amount) + " ZEC" + (q.zatsLeft > q.amount ? " (of " + zecText(q.zatsLeft) + " ZEC still to send)" : "") + " and pays out about " + fmtTok(q.amountOut) + " " + SYM + " (≈ " + (Number(q.amountOut) / TUNIT / (Number(q.amount) / 1e8)).toFixed(2) + " " + SYM + " per ZEC) to " + q.recipient + ".\nThe network fee and swap fee are inside that figure. Pay out at this quote?");
const confirmHopLoss = q => { const dec = Number.isInteger(q.destDecimals) ? q.destDecimals : TOK.decimals, sym = q.destSymbol || SYM, f = v => (Number(v) / 10 ** dec).toFixed(2), total = Number(q.amountOut) * Number(q.zatsLeft) / Number(q.amount);      // 1138 L-2: the PAYOUT token, not the connected chain's
  return confirm("This quote is worse than the " + (q.cap * 100).toFixed(1) + "% limit: the whole transfer would lose about " + (q.loss * 100).toFixed(1) + "%" + (q.approved != null ? " (you approved about " + (q.approved * 100).toFixed(1) + "% on the preview)" : "") + ".\nStill to send: " + zecText(q.zatsLeft) + " ZEC. This payout: about " + f(q.amountOut) + " " + sym + " to " + q.recipient + "; about " + f(BigInt(Math.floor(total))) + " " + sym + " in total if later payouts get this rate (an estimate).\nThe fees on a small transfer are mostly fixed. Pay out at this quote? Cancel keeps the ZEC shielded."); };
const hopCtx = async (HM, f, hit, o) => ({ getUtxos: HM.makeGetUtxos(), authUsed: HM.makeAuthUsed(C, chainRpc), countPriorHops: HM.makeCountPriorHops(C, chainRpc), txKnown: HM.makeTxKnown(), store: HM.idbStore(), stealth: f.stealth, priv: hit.stealthPriv, chain: C, api: API, words: await HM.loadWords(), loadZjs: HM.sharedZjs, waitReceipt, randomNonce: randomBytes32,
  confirmQuote: q => confirmRebuiltQuote(q), confirmLoss: q => confirmHopLoss(q), balance: async () => (await getBalances(rpcBatch, USDC, [f.stealth])).get(f.stealth.toLowerCase()).usdc, onProgress: (s, m) => hopProgress(f, s, m), ...o });
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
async function runHop(f, hit, o, opts = {}) {
  const k = f.stealth.toLowerCase(); if ((hops.get(k) || {}).running) return;
  const HM = await hopMod(), ctx = await hopCtx(HM, f, hit, { ...(o || {}), interactive: !!o || opts.interactive === true }), key = "zec-hop:" + k;      // 1138 L-3: interactive = the user just clicked (Confirm / Continue); a timer-driven run never opens a dialog
  let h;
  if (o) h = { f, hit, running: true, msg: "", st: { step: "QUOTE_IN", chain: C.key, dest: o.dest.key, amount: o.amount.toString(), recipient: o.recipient, startedAt: Date.now() } };
  else { const r = await HM.findHop(ctx.store, f.stealth); if (!r) throw new Error("nothing to resume"); if (r.rec.st.chain !== C.key) throw new Error("This transfer belongs to " + (CHAINS[r.rec.st.chain] || {}).name + ": open the app on that chain to resume it."); ctx.chain = CHAINS[r.rec.st.chain]; ctx.dest = CHAINS[r.rec.st.dest]; h = { f, hit, running: true, msg: "", st: r.rec.st }; }
  h.beatAt = h.sessionAt = Date.now(); hops.set(k, h); say("pay-hint", ""); renderHops(); render();
  const lock = await holdScreen();                                // a locked phone screen or a sleeping display freezes the tab and with it the transfer
  const run = () => (o ? HM.startHop(ctx) : HM.runHop(ctx));
  let st;
  try { st = await (navigator.locks ? navigator.locks.request(key, { ifAvailable: true }, l => l ? run() : Promise.reject(new Error("This transfer is already running in another tab."))) : run()); }
  catch (e) { if (lock) lock.release().catch(() => {}); if (o) hops.delete(k); else h.running = false; renderHops(); render(); if (e && e.code === "EARLIER_HOP") await showResume().catch(() => {}); throw e; }      // 1111 L-4: the earlier transfer's card (with Return money) comes back
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
  if (st.step === "FAILED") try { const rec = (await HM.findHop(ctx.store, f.stealth)).rec; h.extra = (await HM.hopSummary(ctx, rec)).filter(x => x.transparent + x.orchard >= HM.HOLD_DUST).map(x => "Hop wallet account " + x.account + ": " + (Number(x.transparent) / 1e8) + " ZEC transparent, " + (Number(x.orchard) / 1e8) + " ZEC shielded").join("\n"); } catch (e) { h.extra = "Could not read the hop wallet: " + e.message; }
  renderHops(); render(); await refreshBalances().catch(() => {});
}
/** Quote preview: when the service fee is on (chains.js privateFee), say how much of the shown Fee is ours. Nothing is added while it is off. */
function feeNote(box, value) {
  const af = appFeesOf(); if (!af) return;
  box.appendChild(el("div", "note", "Includes our service fee " + (af[0].fee / 100) + "% (≈ " + fmtTok(value * BigInt(af[0].fee) / 10000n) + " " + SYM + "), charged on the first step."));
}
async function privateWithdraw(to, value, hit) {
  const dest = CHAINS[$("wd-dest").value]; if (!dest || !dest.oneClick) throw new Error("pick a destination chain");
  const HM = await hopMod(), mode = HM.DEFAULT_MODE, key = [to.toLowerCase(), value, dest.key, mode, "max"].join("|");
  if (!pv || pv.key !== key) {                                    // step 1: show what it will cost, send nothing
    say("pay-hint", "Asking NEAR Intents for a quote…");
    const q1 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqIn({ chain: C, amount: value, tAddr: HM.DRY_T, stealth: wd.stealth, dry: true }) }), zec = BigInt(q1.quote.amountOut);
    if (!HM.okSize(zec)) throw new Error("Too small for the private route. Try a larger amount.");
    const q2 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqOut({ dest, amount: HM.previewOut(zec, mode), recipient: to, refundT: HM.DRY_T, dry: true }) });
    const out = BigInt(q2.quote.amountOut), fee = value - out, box = $("wd-quote"); box.textContent = "";
    const pct = (Number(fee) / Number(value) * 100).toFixed(1), qt = el("div", "qt"), c1 = el("div"), c2 = el("div");
    c1.appendChild(el("span", "note", "Recipient gets")); c1.appendChild(el("span", "big", "≈ " + (Number(out) / 10 ** dest.token.decimals).toFixed(2) + " " + dest.token.symbol));
    c2.appendChild(el("span", "note", "Fee")); c2.appendChild(el("span", "big", "≈ " + (Number(fee) / TUNIT).toFixed(2) + " (" + pct + "%)"));
    const c3 = el("div"); c3.appendChild(el("span", "note", "Takes about")); c3.appendChild(el("span", "big", HM.etaLabel(mode)));
    qt.appendChild(c1); qt.appendChild(c2); qt.appendChild(c3); box.appendChild(qt); feeNote(box, value); box.appendChild(el("div", "note", "Takes about " + HM.etaLabel(mode) + " · keep this tab open (it can be resumed if you close it)"));
    box.appendChild(el("div", "note", "Pressing Confirm private transfer accepts this total cost (about " + pct + "% Fee, " + (Number(out) / 10 ** dest.token.decimals).toFixed(2) + " " + dest.token.symbol + " out). The payouts are checked against it; the real rate can differ a little, and if a payout quote ends up clearly worse you are asked to review it in this tab."));
    if (Number(fee) / Number(value) > HM.MAX_LOSS) box.appendChild(el("div", "note", "Zcash fees are mostly fixed, so this route is expensive on small amounts. It is usually cheaper from a few tens of " + TOK.symbol + "; Private fast is usually cheaper below that."));
    box.hidden = false; pv = { key, loss: Number(fee) / Number(value) }; $("btn-wd").textContent = "Confirm private transfer";
    say("pay-hint", "Check the quote, then confirm.", "warn"); return;
  }
  $("btn-wd").disabled = true; $("withdraw").hidden = true;
  try { await runHop(wd, hit, { recipient: to, amount: value, dest, mode, approvedLoss: pv.loss }); } finally { $("btn-wd").disabled = false; pvReset(); }
}

// ---- route "private, fast": NEAR Intents only (web/private-withdraw.js runFast). The record (no recipient in it) is kept in localStorage while a part is open, so a closed tab can still follow the swaps.
const FAST_KEY = "stealth-fast-wd";
// 1130 L-1: ONE storage key per stealth address ("stealth-fast-wd:<addr>"), so two tabs working on different addresses never overwrite each other's record (the old single map lost updates).
// The old single-map key is migrated on read. put() THROWS when the record cannot be stored (full / blocked storage): the caller must not start a withdraw it could not follow after a reload.
const fastRecs = { read() { const m = {}; try {
    const old = JSON.parse(localStorage.getItem(FAST_KEY) || "null");
    if (old && typeof old === "object") { let all = true; for (const a of Object.keys(old)) { m[a] = old[a]; try { if (localStorage.getItem(FAST_KEY + ":" + a) == null) localStorage.setItem(FAST_KEY + ":" + a, JSON.stringify(old[a])); } catch { all = false; } } if (all) localStorage.removeItem(FAST_KEY); }
    for (let i = 0; i < localStorage.length; i++) { const key = localStorage.key(i); if (key && key.startsWith(FAST_KEY + ":")) { try { const r = JSON.parse(localStorage.getItem(key)); if (r && typeof r === "object") m[key.slice(FAST_KEY.length + 1)] = r; } catch {} } }
  } catch {} return m; },
  put(rec) { try { localStorage.setItem(FAST_KEY + ":" + rec.stealth, JSON.stringify(rec)); } catch (e) { throw new Error("Could not save the withdraw record in this browser (storage is full or blocked): " + ((e && e.message) || e)); } },
  del(k) { try { localStorage.removeItem(FAST_KEY + ":" + k); } catch {} } };
// 1125 F-1: ONE record per withdraw. A new withdraw from an address that still has an open record (a part in flight, not yet followed to its end) is refused, never written over it.
// 1130 L-1: and it is refused when the record cannot be persisted (written, then read back), because an unrecorded withdraw cannot be followed after a reload and would not block the next one.
function fastClaim(rec) {
  if (PW.fastOpenRec(fastRecs.read()[rec.stealth])) throw new Error("An earlier private withdraw from this address is still open (a part is with NEAR Intents or not finished). Reload this page to follow it, or abandon that record below, then try again.");
  fastRecs.put(rec); const back = fastRecs.read()[rec.stealth];
  if (!back || back.startedAt !== rec.startedAt) throw new Error("Could not save the withdraw record in this browser (storage is full or blocked); nothing was sent.");
}
// 1125 F-2: what the user needs to find a deposit address later (UNKNOWN / FAILED / STUCK part) is kept until dismissed, not shown once and lost with the record.
// 1130 L-3: notes are kept per wallet account (acct), the cap is 200 (not 20), and "Dismiss" removes only the notes that were on screen.
const FAST_NOTES_KEY = "stealth-fast-notes", NOTES_MAX = 200;
const noteId = t => { let h = 5381; for (let i = 0; i < t.length; i++) h = ((h * 33) ^ t.charCodeAt(i)) >>> 0; return h.toString(16); };
const fastNotes = { all() { try { const o = JSON.parse(localStorage.getItem(FAST_NOTES_KEY) || "{}"); if (Array.isArray(o)) return { "": o.filter(x => typeof x === "string").map(t => ({ id: noteId(t), t })) }; return o && typeof o === "object" ? o : {}; } catch { return {}; } },
  save(o) { try { localStorage.setItem(FAST_NOTES_KEY, JSON.stringify(o)); } catch {} },
  read(acct) { const o = this.all(), l = String(acct || "").toLowerCase(); return (o[""] || []).concat(l ? o[l] || [] : []).filter(x => x && typeof x.t === "string"); },      // "" = notes from before they were per account: shown to every account until dismissed
  // 1135 L-4: no owner, no note (the "" bucket is only what older builds left behind)
  add(t, acct) { const l = String(acct || "").toLowerCase(); if (!l) return false; const o = this.all(), a = o[l] || []; if (!a.some(x => x.t === t)) a.push({ id: noteId(t), t }); o[l] = a.slice(-NOTES_MAX); this.save(o); return true; },
  drop(ids, acct) { const o = this.all(), l = String(acct || "").toLowerCase(), set = new Set(ids); for (const k of ["", l]) if (o[k]) { o[k] = o[k].filter(x => !set.has(x.id)); if (!o[k].length) delete o[k]; } if (Object.keys(o).length) this.save(o); else { try { localStorage.removeItem(FAST_NOTES_KEY); } catch {} } } };
const fastNeedsNote = rec => rec.parts.some(p => p.depositAddress && (p.state === "UNKNOWN" || p.state === "FAILED" || p.state === "STUCK"));
let shownNotes = [], fastExtra = [], fastLive = "", fastDeferred = false;      // 1135 L-3: transient lines and the text of a running resume are kept here, so every showFastBox() (e.g. from setAcct) draws them again
const fastOpenIdle = () => { const m = fastRecs.read(); return Object.keys(m).filter(k => !fastBusy.has(k) && PW.fastOpenRec(m[k])); };
function showFastBox(extra = []) { for (const x of extra) if (!fastExtra.includes(x)) fastExtra.push(x); const box = $("fast-resume"), n = fastNotes.read(acct), txt = (fastLive ? [fastLive] : []).concat(n.map(x => x.t), fastExtra).join("\n\n"); shownNotes = n.map(x => x.id); box.textContent = txt; box.hidden = !txt; $("btn-fast-dismiss").hidden = !n.length && !fastExtra.length; $("btn-fast-abandon").hidden = !fastOpenIdle().length; }
async function fastWithdraw(to, value, hit) {
  const dest = CHAINS[$("wd-dest").value]; if (!dest || !dest.oneClick) throw new Error("pick a destination chain");
  const key = [to.toLowerCase(), value, dest.key, "fast"].join("|");
  if (!pv || pv.key !== key) {                                    // step 1: show what it will cost, send nothing
    say("pay-hint", "Asking NEAR Intents for a quote…");
    const j = await PW.requestQuote({ base: PW.ONECLICK, req: PW.buildQuoteRequest({ from: C, to: dest, amount: value, recipient: to, refundTo: wd.stealth, dry: true }) }), sm = PW.summarizeQuote(j, TOK.decimals, dest.token.decimals);
    const box = $("wd-quote"); box.textContent = "";
    const qt = el("div", "qt"), c1 = el("div"), c2 = el("div"), c3 = el("div");
    c1.appendChild(el("span", "note", "Recipient gets")); c1.appendChild(el("span", "big", "≈ " + sm.outText + " " + dest.token.symbol));
    c2.appendChild(el("span", "note", "Fee")); c2.appendChild(el("span", "big", "≈ " + sm.feeText + " (" + sm.feePct + "%)"));
    c3.appendChild(el("span", "note", "Takes about")); c3.appendChild(el("span", "big", PW.fastEtaLabel()));
    qt.appendChild(c1); qt.appendChild(c2); qt.appendChild(c3); box.appendChild(qt); feeNote(box, value);
    box.appendChild(el("div", "note", "Sent in 1–2 parts at random times, up to " + PW.FAST.delayMaxMin + " min apart · keep this tab open. The link is broken by the swap, not by cryptography."));
    box.hidden = false; pv = { key, ratio: Number(sm.amountOut) / Number(sm.amountIn) }; $("btn-wd").textContent = "Confirm private withdraw";
    say("pay-hint", "Check the quote, then confirm.", "warn"); return;
  }
  const w = wd, k = w.stealth.toLowerCase(), plan = PW.fastPlan(value), ratio = pv.ratio;
  const rec = { v: 1, stealth: k, chain: C.key, dest: dest.key, startedAt: Date.now(), parts: plan };
  $("btn-wd").disabled = true; $("withdraw").hidden = true; fastBusy.add(k);
  const lock = await holdScreen(), fmt = v => fmtTok(v);
  const save = r => { try { fastRecs.put(r); } catch (e) { say("pay-hint", e.message + " The withdraw continues, but if this tab is closed it cannot be followed.", "warn"); } };      // 1130 L-1: surfaced, never silent (the START is refused in fastClaim)
  const owner = acct;      // 1135 L-4: the account that started this withdraw owns its notes, whatever is connected when it ends
  let cur = null, claimed = false;      // claimed: this run owns the stored record (a refused second start must not touch the guard or notes of the live one)
  const noteIfNeeded = () => { if (claimed && fastNeedsNote(rec)) { fastNotes.add("Private withdraw of " + fmtTok(value) + " " + SYM + " (" + C.name + "), started " + new Date(rec.startedAt).toLocaleString() + ":\n" + PW.fastSummary(rec, fmt, SYM).join("\n"), owner); showFastBox(); } };
  const settleGuard = () => { if (claimed && !rec.parts.some(p => p.state === "SIGNED" || p.state === "UNKNOWN")) pendingWd.delete(k); };
  const ctx = { from: C, to: dest, priv: hit.stealthPriv, stealth: w.stealth, recipient: to, api: API, base: PW.ONECLICK, fetchFn: fetch, minRatio: ratio * 0.98, randomNonce: randomBytes32,
    authUsed: (a, n) => authorizationUsed(rpcOne, USDC, a, n), onProgress: m => say("pay-hint", m, "ok"),
    findTx: a => txOfLogs({ address: USDC, topics: [AUTH_USED_TOPIC, "0x" + padAddr(w.stealth), a.nonce], span: logSpanSince(a.validBefore) }, () => true), onRefused: () => pendingWd.delete(k),
    onSigned: info => { cur = info; pendingWd.set(k, (info.validBefore + 60) * 1000); },       // armed before the request leaves; cleared only when the deposit is confirmed
    waitReceipt: h => waitReceipt(h, x => hasTransfer(x, { token: USDC, from: w.stealth, to: cur.depositAddress, value: cur.amount }) && hasAuthUsed(x, { token: USDC, authorizer: w.stealth, nonce: cur.auth.nonce }), true),
    onDeposited: info => { if (info.index === rec.parts.length - 1) pendingWd.delete(k); spent.set(k, { left: (spent.get(k) || { left: w.usdc }).left - BigInt(rec.parts[info.index].amount), until: Date.now() + 120_000 }); render(); } };
  try {
    const run = () => { fastClaim(rec); claimed = true; return PW.runFast(ctx, rec, save); };      // claimed inside the lock: a second tab is refused before it can write
    if (navigator.locks) await navigator.locks.request("fast-wd:" + k, { ifAvailable: true }, l => l ? run() : Promise.reject(new Error("A withdraw from this address is already running in another tab."))); else await run();
    const sums = PW.fastSummary(rec, fmt, SYM), ok = rec.parts.every(p => p.state === "SUCCESS");
    if (PW.fastDone(rec)) fastRecs.del(k);
    noteIfNeeded(); settleGuard();
    say("pay-hint", (ok ? "Done privately: " + fmtTok(value) + " " + SYM + " sent through NEAR Intents to " + to.slice(0, 8) + "… on " + dest.name + "." : "Finished with problems:") + (ok && rec.parts.length < 2 ? "" : "\n" + sums.join("\n")), ok ? "ok" : "warn");
  } catch (e) { say("pay-hint", (e.message || String(e)) + (e.config ? PW.CONFIG_NOTE + " Use Abandon below to clear this record." : "\n" + PW.fastSummary(rec, fmt, SYM).join("\n")), "bad");      // 1135 L-2: the true reason, the guard stays, Abandon is the way out
    if (PW.fastDone(rec) && fastRecs.read()[k] && fastRecs.read()[k].startedAt === rec.startedAt) fastRecs.del(k); noteIfNeeded(); settleGuard(); }
  finally { fastBusy.delete(k); showFastBox(); if (lock) lock.release().catch(() => {}); $("btn-wd").disabled = false; pvReset(); await refreshBalances().catch(() => {}); render(); }
}
// after a reload: follow parts that were handed to NEAR Intents, mark the rest (never signed -> still on the stealth address; signed but unconfirmed -> check the explorer)
async function resumeFast() {
  const m = fastRecs.read(), extra = [];
  for (const k of Object.keys(m)) {
    const rec = m[k]; if (!rec || !Array.isArray(rec.parts) || fastBusy.has(k)) continue;
    let ran = false;
    const go = async () => { ran = true; fastBusy.add(k); try { await PW.runFast({ base: PW.ONECLICK, fetchFn: fetch, onProgress: t => { fastLive = "Earlier private withdraw: " + t; showFastBox(); } }, rec, r => { try { fastRecs.put(r); } catch {} }, { resume: true }); } finally { fastBusy.delete(k); fastLive = ""; } };
    try { if (navigator.locks) await navigator.locks.request("fast-wd:" + k, { ifAvailable: true }, l => l ? go() : undefined); else await go(); } catch (e) { extra.push("Earlier private withdraw: " + (e.message || e)); continue; }
    if (!ran) continue;                                      // 1125 F-6: another tab holds the lock, so this record is a LIVE withdraw there, not an earlier one
    const chain = CHAINS[rec.chain] || C, sums = PW.fastSummary(rec, v => (Number(v) / 10 ** chain.token.decimals).toFixed(2), chain.token.symbol), text = "Earlier private withdraw (" + chain.name + "):\n" + sums.join("\n");
    if (fastNeedsNote(rec)) { if (!acct) { extra.push(text); fastDeferred = true; continue; } fastNotes.add(text, acct); } else extra.push(text);      // 1135 L-4: no account yet -> shown now, the record is kept and followed again when one connects      // 1125 F-2: all summaries are listed (not only the last), and the ones with a deposit address to look up stay
    if (PW.fastDone(rec)) { fastRecs.del(k); if (!rec.parts.some(p => p.state === "UNKNOWN")) pendingWd.delete(k); }   // UNKNOWN: the signed transfer may still land, the guard stays until its authorization expires
  }
  showFastBox(extra);
}
$("btn-fast-dismiss").addEventListener("click", () => { fastNotes.drop(shownNotes, acct); fastExtra = []; showFastBox(); });
// 1130 M-2: the explicit way out of a record that cannot be closed (a part that never got a final 1Click status, a tab that died): every open part is parked in the state that tells the truth, the deposit address goes into a note.
$("btn-fast-abandon").addEventListener("click", once(async () => {
  if (!acct) { say("pay-hint", "Connect your wallet first: the note with the deposit address is saved for your account.", "warn"); return; }
  const ks = fastOpenIdle(); if (!ks.length || !confirm("Abandon the unfinished private withdraw record" + (ks.length > 1 ? "s" : "") + "? Parts already handed to NEAR Intents stay with NEAR Intents (their deposit addresses are kept in a note); this page stops following them.")) return;
  for (const k of ks) {
    const go = () => { const rec = fastRecs.read()[k]; if (!rec || !PW.fastOpenRec(rec)) return; const chain = CHAINS[rec.chain] || C; PW.abandonRec(rec);
      fastNotes.add("Abandoned private withdraw (" + chain.name + "), started " + new Date(rec.startedAt).toLocaleString() + ":\n" + PW.fastSummary(rec, v => (Number(v) / 10 ** chain.token.decimals).toFixed(2), chain.token.symbol).join("\n"), acct);
      fastRecs.del(k); };
    if (navigator.locks) await navigator.locks.request("fast-wd:" + k, { ifAvailable: true }, l => { if (l) go(); }); else go();      // a record another tab is running is not abandoned from here
  }
  showFastBox();
}));
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
// the same checks for every recipient the user types (a normal withdraw and "Continue" of a recovered transfer)
function vetRecipient(to, w) {
  if (!isAddr(to)) throw new Error("enter a destination address");
  if (acct && to.toLowerCase() === acct) throw new Error("Refused: that is the wallet your keys came from. Sending there would tie this payment to your public address.");
  if (w && w.payer && to.toLowerCase() === w.payer.toLowerCase()) throw new Error("Refused: that is the wallet that paid you. Sending it back links the two.");
  if (found.some(f => f.stealth.toLowerCase() === to.toLowerCase()) && !confirm("That is another of your stealth addresses. Pooling payments links them to each other. Continue?")) return false;
  return true;
}
async function screenRecipient(to) {
  // audit 1087 M-3: the relayer only sees the 1Click deposit address, so the real recipient is screened here, before anything is signed (fail closed if the check cannot run)
  // the whole list is fetched and checked here, so the recipient never reaches our server; /relay/screen only while a relayer without the list endpoint is live
  const sl = await api("/relay/sanctions-list").catch(() => null), local = sl && Array.isArray(sl.addresses) && sl.addresses.length === sl.count && sl.count > 0;
  if (!local) say("pay-hint", "The sanctions list could not be loaded here, so this recipient address is checked by the relayer instead (it will see it).", "warn");     // 1101 I-1
  const sc = local ? { listed: sl.addresses.includes(to.toLowerCase()) } : await api("/relay/screen?addr=" + to).catch(() => null);
  if (!sc || sc.listed !== false) throw new Error(sc && sc.listed ? "That recipient address is on a sanctions list; refusing." : "Could not check the recipient against the sanctions list; nothing was sent. Try again.");
}
$("btn-wd").addEventListener("click", once(async () => {
  try {
    if (!wd || !keys) return;
    const to = $("wd-to").value.trim();
    if (!vetRecipient(to, wd)) return;
    const all = wd.usdc; const amtIn = $("wd-amt").value.trim();
    const exact = amtIn ? calcAmounts({ src: "amount", text: amtIn, decimals: TOK.decimals, fee: 0n }) : null;      // exact decimals, no floats (1098 I-1)
    if (amtIn && !exact) throw new Error("enter the amount as a plain number");
    const value = amtIn ? exact.send : all;
    if (typeof all !== "bigint" || !(value > 0n) || value > all) throw new Error("amount must be within the balance");
    const w = wd, hit = hitOf(w);
    if ((pendingWd.get(w.stealth.toLowerCase()) || 0) > Date.now() && !confirm("An earlier withdrawal from this address was sent to the network and has not been confirmed yet. Sending again may pay twice. Check the explorer first. Send anyway?")) return;
    if (!hit || hit.stealth.toLowerCase() !== w.stealth.toLowerCase()) throw new Error("could not re-derive the key for this address");
    // audit 1086 L-4: the token's own DOMAIN_SEPARATOR() read from the chain RPC / the wallet (not from our indexer, which would only prove config drift)
    const dsep = await chainRpc(C.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: USDC, data: "0x3644e515" }, "latest"] }) }, true).then(r => r.json()).then(j => j.result).catch(() => null);
    if (String(dsep).toLowerCase() !== hex(domainSeparator()).toLowerCase()) throw new Error(SYM + " domain mismatch (or could not be read from the chain); refusing to sign");
    if (route() !== "std" && !$("wd-priv-wrap").hidden) {
      await screenRecipient(to);
      return route() === "fast" ? await fastWithdraw(to, value, hit) : await privateWithdraw(to, value, hit);
    }
    const now = Math.floor(Date.now() / 1000); const validBefore = BigInt(now + 3600); const nonce = randomBytes32();
    pendingWd.set(w.stealth.toLowerCase(), (now + 3600 + 60) * 1000);                    // 1109 L-1: from here on an unknown outcome blocks a second send until this authorization has expired
    const struct = hex(TYPEHASH) + padAddr(wd.stealth) + padAddr(to) + pad(value) + pad(0n) + pad(validBefore) + nonce.slice(2);
    const digest = keccak(unhex("0x1901" + hex(domainSeparator()).slice(2) + hex(keccak(unhex(struct))).slice(2)));
    const sig = signDigest(digest, unhex(hit.stealthPriv));
    say("pay-hint", "Sending through the relayer…");
    const { r, d } = await postRelay(fetch, API + "/relay", { from: w.stealth, to, value: value.toString(), validAfter: "0", validBefore: validBefore.toString(), nonce, v: sig.v, r: sig.r, s: sig.s },
      { onBusy: m => say("pay-hint", m, "warn"), check: () => authorizationUsed(rpcOne, USDC, w.stealth, nonce) });
    // 1121 L-2: the guard is cleared only by a DEFINITE refusal (400/403/429 JSON, not "already used"). "authorization already used" means an earlier attempt of this same request went through (lost answer, then the retry): follow it like d.used.
    const ans = PW.relayOutcome(r, d);      // 1125 F-3: the same reading of the answer as the fast route
    if (ans.kind === "error") { if (ans.definite) pendingWd.delete(w.stealth.toLowerCase()); throw new Error(ans.message + (ans.config ? PW.CONFIG_NOTE : "")); }      // 1135 L-2: the true reason; the guard stays
    if (ans.kind === "used") d.hash = await txOfLogs({ address: USDC, topics: [AUTH_USED_TOPIC, "0x" + padAddr(w.stealth), nonce], span: logSpanSince(validBefore) }, () => true);      // 1101 L-1: found by THIS request's nonce, not by "an identical transfer"
    if (!isHash(d.hash)) throw new Error("the relayer answered without a valid transaction hash; check the explorer before sending again");
    $("withdraw").hidden = true;
    say("pay-hint", "Submitted: " + fmtTok(value) + " " + SYM + " → " + to.slice(0, 8) + "… waiting for the block…");
    const rc = await waitReceipt(d.hash, x => hasTransfer(x, { token: USDC, from: w.stealth, to, value }) && hasAuthUsed(x, { token: USDC, authorizer: w.stealth, nonce }), true);
    if (!rc.ok && !rc.unexpected) pendingWd.delete(w.stealth.toLowerCase());
    if (!rc.ok) throw new Error(rc.unexpected ? "the transaction is mined but does not contain the expected transfer (tx " + rc.hash.slice(0, 12) + "…). Check the explorer." : "the transfer reverted on chain (tx " + rc.hash.slice(0, 12) + "…). Nothing moved.");
    d.hash = rc.hash; pendingWd.delete(w.stealth.toLowerCase());
    spent.set(w.stealth.toLowerCase(), { left: all - value, until: Date.now() + 120_000 });
    const doneMsg = "Done: " + fmtTok(value) + " " + SYM + " sent, tx " + d.hash.slice(0, 12) + "…";
    say("pay-hint", doneMsg, "ok"); await scan();
    $("pay-hint").textContent = doneMsg + "\n" + $("pay-hint").textContent;                // the rescan's status must not erase the confirmation
  } catch (e) { say("pay-hint", e.message || String(e), "bad"); }
}));
// audit 1098 L-4: the final receipt (and the Transfer / Paid event that proves it is the thing we wanted) is read from the chain RPC. The API is only asked for a replacement hash
// of a relayed transaction, and that hash is followed only if the chain shows the same sender and nonce. -> { ok, hash, unexpected? }
async function waitReceipt(h, expect = null, relayed = false) {
  if (!isHash(h)) throw new Error("bad transaction hash");
  try { return await waitFinal(rpcOne, h, { expect, confirmations: C.key === "rh" ? 2 : 1, follow: relayed ? () => api("/relay/status?hash=" + h).then(s => s && s.hash) : null }); }
  catch (e) { if (/^not mined yet/.test(e.message || "")) throw new Error("The transaction was handed to the network but is not confirmed yet (tx " + h + "). It may still go through: check the explorer and your balance before sending again."); throw e; }
}
// a relayed request whose answer was lost but whose authorization is used on chain: find its transaction from the event it produced
async function txOfLogs(filter, match) {
  for (let i = 0; i < 20; i++) {
    let l = null; try { l = (await recentLogs(rpcOne, filter)).filter(match).pop(); } catch {}      // 1109 L-3: a failed read is retried, not reported as a failed withdrawal
    if (l) return l.transactionHash;
    await new Promise(z => setTimeout(z, 3000));
  }
  throw new Error("The withdrawal is already on chain (its authorization is used) but its receipt could not be read or found; check the explorer before doing anything else.");
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
  const bps = payBps(stats), raw = rawIn ?? BigInt(Math.round(amount * TUNIT)), fee = payFeeFor(raw, BigInt(stats.pay_fee), bps), feeTo = stats.relayer;   // "you pay" = raw = what leaves the wallet; the fee comes out of it (flat fee, or bps of it when the relayer announces one)
  if (fee < 0n || fee >= raw) throw new Error("The amount is below the relayer fee (" + fmtTok(fee) + " " + SYM + ").");
  if (!feeWithinCap(fee, raw, BigInt(TUNIT), bps ? PAY_BPS_CAP : 0)) throw new Error("The relayer asks " + fmtTok(fee) + " " + SYM + " in fees for a " + fmtTok(raw) + " " + SYM + " payment, which is more than this page accepts (max " + (bps ? "1.00 or " + PAY_BPS_CAP / 100 + "%" : "1.00") + " and half of the payment). Refusing.");   // audit 1086 L-1
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
let payFee = null, payBpsNow = 0, amtSrc = "amount";
const PAY_BPS_CAP = 100;       // this page never accepts a percentage fee above 1% of the payment, whatever the relayer announces
const payBps = s => { const b = Number(s.pay_fee_bps || 0); if (!Number.isInteger(b) || b < 0 || b > PAY_BPS_CAP) throw new Error("The relayer announces an unusual fee rate; refusing."); return b; };
api("/relay/stats").then(s => { if (s.pay_enabled && s.pay_fee != null) { const f = BigInt(s.pay_fee), b = payBps(s); payFee = f; payBpsNow = b; } calc(); }).catch(() => {});
const curFee = () => $("token").value === "TOKEN" ? (payFee ?? 0n) : 0n, unit = () => $("token").value === "TOKEN" ? TUNIT : NUNIT;
/** Returns { send, get, fee } in token units from the field the user last edited, or null. */
function payAmounts() {
  return calcAmounts({ src: amtSrc, text: $(amtSrc).value, decimals: Math.round(Math.log10(unit())), fee: curFee(), bps: $("token").value === "TOKEN" ? payBpsNow : 0 });   // exact decimals, see pay-auth.js
}
function calc() {
  const out = $("pay-calc"), a = payAmounts(), other = amtSrc === "amount" ? "amount-get" : "amount", u = unit();
  $(other).value = a ? String(Number(amtSrc === "amount" ? a.get : a.send) / u) : "";
  if (a && a.get <= 0n) { $(other).value = ""; out.textContent = "Minimum is above the " + fmtTok(a.fee) + " " + SYM + " network fee."; return; }
  out.textContent = $("token").value !== "TOKEN" ? "Gas is paid from your wallet." : payFee != null ? (payBpsNow ? "Fee " + (payBpsNow / 100) + "% (minimum " + fmtTok(payFee) + " " + SYM + ")" + (a ? " = " + fmtTok(a.fee) + " " + SYM : "") + " included" : "Network fee " + fmtTok(payFee) + " " + SYM + " included") : "";
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
resumeFast().catch(() => {});     // follows the parts of an earlier "private, fast" withdraw whose tab was closed (needs no keys)
