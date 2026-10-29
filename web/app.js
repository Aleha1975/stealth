import { keysFromSignature, keyRequestTypedData, metaAddress, parseMeta, deriveForPayment, checkAnnouncement, decodeMetadata, hex, unhex, keccak, signDigest, randomBytes32 } from "./stealth-crypto.js";
import { paymentNonce, receiveTypedData, splitSig } from "./pay-auth.js";
import { CHAINS, pickChain, chainOfMeta, addChainParams } from "./chains.js";
import * as PW from "./private-withdraw.js";

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

// ---- wallet (payer path only talks to the wallet's own provider; reads go through our API)
async function api(path) { const r = await fetch(API + path, { cache: "no-store" }); const d = await r.json(); if (!r.ok || d.error) throw new Error(d.error || ("api " + r.status)); return d; }
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
$("btn-keys").addEventListener("click", async () => {
  try {
    if (!acct && !(await connect())) return;
    say("recv-hint", "Sign the request in your wallet…");
    const sig = await wallet("eth_signTypedData_v4", [acct, keyRequestTypedData(acct)]);
    keys = keysFromSignature(sig, acct);
    const meta = metaAddress(keys, C.key);
    // remember the public meta-address per account: if a later derivation differs, say so before a link is shared
    let prev = null; try { prev = localStorage.getItem("stealth.meta." + acct); localStorage.setItem("stealth.meta." + acct, meta); } catch {}
    $("meta").textContent = meta; $("paylink").textContent = location.origin + "/stealth/?" + (C.key === pickChain("").key ? "" : "chain=" + C.key + "&") + "to=" + meta;
    $("recv-out").hidden = false;
    if (prev && prev !== meta) say("recv-hint", "Warning: these keys differ from the ones this account derived before on this device. Payments sent to the old link are reachable only with the old keys. Check your wallet account.", "warn");
    else say("recv-hint", "Keys derived in this browser. They are not stored anywhere.", "ok");
    $("scan-note").textContent = "Ready to scan " + C.name + " for payments to your keys.";
  } catch (e) { say("recv-hint", e.message || String(e), "bad"); }
});
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
const spent = new Map();   // stealth -> { left, until }
async function scan() {
  if (!keys) { say("pay-hint", "Derive your keys first (Receive tab).", "bad"); return; }
  const head = await api("/head");
  if (head.lag != null && head.lag > 50) say("pay-hint", "Index is " + head.lag + " blocks behind the chain; very recent payments may not show yet.", "warn");
  else say("pay-hint", "Reading announcements on " + C.name + "…");
  found = []; let n = 0;
  const check = (id, block, tx, stealth, eph, meta, payer) => {
    n++;
    if (!eph || !isHash(tx) || !isAddr(stealth)) return;
    const md = decodeMetadata(meta) || {};
    const hit = checkAnnouncement(keys, eph, md.viewTag);          // view-tag filter first, full check only on a tag match
    if (!hit || hit.stealth.toLowerCase() !== stealth.toLowerCase()) return;
    found.push({ stealth: hit.stealth, tx, block: Number(block) || 0, token: md.token, amount: md.amount, payer: isAddr(payer) ? payer : null, eph });
  };
  let since = 0;
  // 1) immutable history pages (static files, cached forever locally); 2) only the tail from the indexer. Old indexers (no manifest) -> paged API.
  let man = null;
  try { const r = await fetch(API + "/pages/manifest.json", { cache: "no-cache" }); if (r.ok) { const m = await r.json(); if (m && m.chain === C.key && m.page_size === 1024 && Number.isInteger(m.full_pages) && m.full_pages >= 0 && Number.isInteger(m.tail_since_id)) man = m; } } catch {}
  if (man) {
    const rowsOf = await getPages(man);
    for (let k = 0; k < man.full_pages; k++) {
      for (const r of rowsOf(k)) check(r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
      if (k % 20 === 19) say("pay-hint", n + " announcements checked…");
    }
    since = man.tail_since_id;
  }
  for (;;) {
    const d = await api("/announcements?since=" + since + "&limit=2000");
    for (const r of d.rows) { if (r.scheme === 1) check(r.id, r.block, r.tx, r.stealth, r.eph, r.meta, r.payer); }
    if (n % 2000 === 0 && n) say("pay-hint", n + " announcements checked…");
    if (!d.rows.length || d.next === since) break; since = d.next;
  }
  if (found.length) {
    const b = await api("/balances?addrs=" + found.map(f => f.stealth).join(","));
    for (const f of found) { const x = b[f.stealth.toLowerCase()] || {}; f.usdc = BigInt(x.usdc || "0"); f.eth = BigInt(x.eth || "0");
      const sp = spent.get(f.stealth.toLowerCase()); if (sp && Date.now() < sp.until && f.usdc > sp.left) f.usdc = sp.left; }
  }
  render(); showResume().catch(() => {});
  const msg = n + " announcements scanned, " + found.length + " are yours.";
  if (head.lag != null && head.lag > 50) say("pay-hint", msg + " Index is " + head.lag + " blocks behind.", "warn"); else say("pay-hint", msg, "ok");
}
function render() {
  const list = $("pay-list"); list.textContent = "";
  if (!found.length) { list.appendChild(el("p", "note", "Nothing found yet. Payments appear a few seconds after they land.")); return; }
  found.forEach((f, i) => {
    const row = el("div", "pay"); const top = el("div", "row"); top.style.justifyContent = "space-between";
    const label = f.token === "ETH" ? (Number(f.amount) / NUNIT).toFixed(5) + " " + NAT : f.token && f.token.toLowerCase() === USDC.toLowerCase() ? fmtTok(f.amount) + " " + SYM : "payment";
    top.appendChild(el("span", "amt", label)); top.appendChild(el("span", "mono", f.stealth.slice(0, 8) + "…" + f.stealth.slice(-4)));
    row.appendChild(top);
    const small = el("small", null, "block " + f.block + " · now holds " + fmtTok(f.usdc) + " " + SYM + (f.eth ? " + " + (Number(f.eth) / NUNIT).toFixed(5) + " " + NAT : "") + " · ");
    const a = el("a", null, "tx"); a.href = C.explorer + "/tx/" + f.tx; a.target = "_blank"; a.rel = "noopener noreferrer"; small.appendChild(a); row.appendChild(small);
    if (f.usdc > 0n) { const d = el("div"); d.style.marginTop = "8px"; const b = el("button", "btn ghost", "Withdraw " + SYM); b.type = "button"; b.addEventListener("click", () => openWithdraw(i)); d.appendChild(b); row.appendChild(d); }
    list.appendChild(row);
  });
}
$("btn-scan").addEventListener("click", () => scan().catch(e => say("pay-hint", e.message || String(e), "bad")));

// ---- withdraw the stablecoin gaslessly: EIP-3009 authorization signed by the stealth key, submitted by the relayer
let wd = null;
function openWithdraw(i) {
  wd = found[i]; $("wd-from").textContent = wd.stealth; $("wd-to").value = ""; $("wd-amt").value = ""; $("withdraw").hidden = false;
  // Private = the hidden Zcash hop (web/zec-hop.js): offered only on a cross-origin isolated page, on chains with 1Click, and only if the module loads; then it is on by default
  const mine = wd; $("wd-priv-wrap").hidden = true; $("wd-private").checked = false; $("wd-priv-opts").hidden = true; pvReset();
  const dest = $("wd-dest"); dest.textContent = "";
  for (const k of [C.key]) {   /* one payout chain for now: the same chain */ const c = CHAINS[k]; if (c && c.oneClick && !Array.from(dest.options).some(o => o.value === c.key)) { const o = el("option", null, c.name + " (" + c.token.symbol + ")" + (c.key === C.key ? " · same chain" : "")); o.value = c.key; dest.appendChild(o); } }
  if (self.crossOriginIsolated && C.privateWithdraw && C.oneClick) hopMod().then(() => { if (wd !== mine) return; $("wd-priv-wrap").hidden = false; $("wd-private").checked = true; $("wd-priv-opts").hidden = false; pvReset(); }).catch(() => {});
}
// ---- private withdraw: preview (two dry quotes) first, then a second click starts the hop. Any input change drops the preview.
let pv = null, HOPM = null;
const hopMod = () => HOPM || (HOPM = import("./zec-hop.js"));
function pvReset() { pv = null; $("wd-quote").hidden = true; $("btn-wd").textContent = $("wd-private").checked ? "Preview private send" : "Send without gas"; }
$("wd-private").addEventListener("change", () => { $("wd-priv-opts").hidden = !$("wd-private").checked; pvReset(); });
["wd-to", "wd-amt", "wd-dest"].forEach(id => { $(id).addEventListener("input", pvReset); $(id).addEventListener("change", pvReset); });
const hopCtx = async (HM, f, hit, o) => ({ store: HM.idbStore(), stealth: f.stealth, priv: hit.stealthPriv, chain: C, api: API, words: await HM.loadWords(), loadZjs: HM.sharedZjs, waitReceipt, randomNonce: randomBytes32,
  balance: async () => BigInt(((await api("/balances?addrs=" + f.stealth))[f.stealth.toLowerCase()] || {}).usdc || "0"), onProgress: (s, m) => say("pay-hint", HM.progressText(s) + (m ? "\n" + m : "")), ...o });
/** start (o = { recipient, amount, dest }) or resume (o = null) the hop of one found payment; one tab at a time per address */
async function runHop(f, hit, o) {
  const HM = await hopMod(), ctx = await hopCtx(HM, f, hit, o || {});
  if (!o) { const r = await HM.findHop(ctx.store, f.stealth); if (!r) throw new Error("nothing to resume"); ctx.chain = CHAINS[r.rec.st.chain]; ctx.dest = CHAINS[r.rec.st.dest]; }
  const run = () => (o ? HM.startHop(ctx) : HM.runHop(ctx)), key = "zec-hop:" + f.stealth.toLowerCase();
  const st = await (navigator.locks ? navigator.locks.request(key, { ifAvailable: true }, l => l ? run() : Promise.reject(new Error("This transfer is already running in another tab."))) : run());
  if (st.relayed) spent.set(f.stealth.toLowerCase(), { left: f.usdc > BigInt(st.inQuote.amountIn) ? f.usdc - BigInt(st.inQuote.amountIn) : 0n, until: Date.now() + 120_000 });
  if (st.step === "DONE") { const m = "Done privately: " + fmtTok(BigInt(st.amount)) + " " + SYM + " sent to " + st.recipient.slice(0, 8) + "… on " + CHAINS[st.dest].name + "."; say("pay-hint", m, "ok"); await scan(); $("pay-hint").textContent = m + "\n" + $("pay-hint").textContent; return; }
  let msg = HM.recoveryText(st);
  if (st.step === "FAILED") try { const rec = (await HM.findHop(ctx.store, f.stealth)).rec; msg += "\n" + (await HM.hopSummary(ctx, rec)).filter(x => x.transparent + x.orchard > 0n).map(x => "Hop wallet account " + x.account + ": " + x.t + " " + (Number(x.transparent) / 1e8) + " ZEC transparent, " + (Number(x.orchard) / 1e8) + " ZEC shielded").join("\n"); } catch (e) { msg += " (could not read the hop wallet: " + e.message + ")"; }
  say("pay-hint", msg, st.step === "FAILED_IN" ? "warn" : "bad"); await showResume();
}
async function privateWithdraw(to, value, hit) {
  const dest = CHAINS[$("wd-dest").value]; if (!dest || !dest.oneClick) throw new Error("pick a destination chain");
  const HM = await hopMod(), key = [to.toLowerCase(), value, dest.key].join("|");
  if (!pv || pv.key !== key) {                                    // step 1: show what it will cost, send nothing
    say("pay-hint", "Asking NEAR Intents for a quote…");
    const q1 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqIn({ chain: C, amount: value, tAddr: HM.DRY_T, stealth: wd.stealth, dry: true }) }), zec = BigInt(q1.quote.amountOut);
    if (!HM.okSize(zec)) throw new Error("Too small for the private route. Try a larger amount.");
    const q2 = await PW.requestQuote({ base: PW.ONECLICK, req: HM.reqOut({ dest, amount: HM.outAmount(zec - HM.SHIELD_FEE), recipient: to, refundT: HM.DRY_T, dry: true }) });
    const out = BigInt(q2.quote.amountOut), fee = value - out, box = $("wd-quote"); box.textContent = "";
    box.appendChild(el("div", null, "You send " + fmtTok(value) + " " + SYM + "; the recipient gets about " + (Number(out) / 10 ** dest.token.decimals).toFixed(2) + " " + dest.token.symbol + " on " + dest.name + "."));
    box.appendChild(el("div", "note", "Fees about " + (Number(fee) / TUNIT).toFixed(2) + " (" + (Number(fee) / Number(value) * 100).toFixed(1) + "%) · ~" + HM.ETA_MIN + " min · keep this tab open."));
    box.hidden = false; pv = { key }; $("btn-wd").textContent = "Confirm: send privately";
    say("pay-hint", "Check the quote above, then press Confirm.", "warn"); return;
  }
  $("btn-wd").disabled = true; $("withdraw").hidden = true;
  try { await runHop(wd, hit, { recipient: to, amount: value, dest }); } finally { $("btn-wd").disabled = false; pvReset(); }
}
// ---- unfinished hops of the payments found: banner with Resume (needs the keys, so it appears after Scan)
async function showResume() {
  const box = $("hop-resume"); box.hidden = true; box.textContent = "";
  if (!self.crossOriginIsolated || !keys || !((await (indexedDB.databases ? indexedDB.databases() : [])) || []).some(d => d.name === "stealth-zec-hop")) return;
  const HM = await hopMod(), store = HM.idbStore();
  for (const f of found) {
    const r = await HM.findHop(store, f.stealth); if (!r || ["DONE", "FAILED_IN"].includes(r.rec.st.step)) continue;
    const hit = checkAnnouncement(keys, f.eph, null); if (!hit || hit.stealth.toLowerCase() !== f.stealth.toLowerCase()) continue;
    const row = el("div", "row"), b = el("button", "btn", r.rec.st.step === "FAILED" ? "Show funds" : "Resume"); b.type = "button";
    b.addEventListener("click", () => { b.disabled = true; runHop(f, hit, null).catch(e => say("pay-hint", e.message || String(e), "bad")).finally(() => { b.disabled = false; }); });
    row.appendChild(el("span", "note", f.stealth.slice(0, 8) + "… · " + HM.progressText(r.rec.st))); row.appendChild(b); box.appendChild(row); box.hidden = false;
  }
}
$("btn-wd-cancel").addEventListener("click", () => { $("withdraw").hidden = true; wd = null; });
const TYPEHASH = keccak(new TextEncoder().encode("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));
const DOMAIN_TYPEHASH = keccak(new TextEncoder().encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const domainSeparator = () => keccak(unhex(hex(DOMAIN_TYPEHASH) + hex(keccak(new TextEncoder().encode(TOK.domainName))).slice(2) + hex(keccak(new TextEncoder().encode(TOK.domainVersion))).slice(2) + pad(BigInt(C.chainId)) + padAddr(USDC)));
$("btn-wd").addEventListener("click", async () => {
  try {
    if (!wd || !keys) return;
    const to = $("wd-to").value.trim();
    if (!isAddr(to)) throw new Error("enter a destination address");
    if (acct && to.toLowerCase() === acct) throw new Error("Refused: that is the wallet your keys came from. Sending there would tie this payment to your public address.");
    if (wd.payer && to.toLowerCase() === wd.payer.toLowerCase()) throw new Error("Refused: that is the wallet that paid you. Sending it back links the two.");
    if (found.some(f => f.stealth.toLowerCase() === to.toLowerCase()) && !confirm("That is another of your stealth addresses. Pooling payments links them to each other. Continue?")) return;
    const all = wd.usdc; const amtIn = $("wd-amt").value.trim();
    const value = amtIn ? BigInt(Math.round(Number(amtIn) * TUNIT)) : all;
    if (!(value > 0n) || value > all) throw new Error("amount must be within the balance");
    const hit = checkAnnouncement(keys, wd.eph, null);
    if (!hit || hit.stealth.toLowerCase() !== wd.stealth.toLowerCase()) throw new Error("could not re-derive the key for this address");
    const info = await api("/usdc-domain");                       // the token's own domain separator, read server-side
    if (String(info.domain_separator).toLowerCase() !== hex(domainSeparator()).toLowerCase()) throw new Error(SYM + " domain mismatch; refusing to sign");
    if ($("wd-private").checked && !$("wd-priv-wrap").hidden) return await privateWithdraw(to, value, hit);
    const now = Math.floor(Date.now() / 1000); const validBefore = BigInt(now + 3600); const nonce = randomBytes32();
    const struct = hex(TYPEHASH) + padAddr(wd.stealth) + padAddr(to) + pad(value) + pad(0n) + pad(validBefore) + nonce.slice(2);
    const digest = keccak(unhex("0x1901" + hex(domainSeparator()).slice(2) + hex(keccak(unhex(struct))).slice(2)));
    const sig = signDigest(digest, unhex(hit.stealthPriv));
    say("pay-hint", "Sending through the relayer…");
    const r = await fetch(API + "/relay", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ from: wd.stealth, to, value: value.toString(), validAfter: "0", validBefore: validBefore.toString(), nonce, v: sig.v, r: sig.r, s: sig.s }) });
    const d = await r.json(); if (!r.ok || d.error) throw new Error(d.error || "relayer error");
    $("withdraw").hidden = true;
    say("pay-hint", "Submitted: " + fmtTok(value) + " " + SYM + " → " + to.slice(0, 8) + "… waiting for the block…");
    const rc = await waitReceipt(d.hash);
    if (!rc.ok) throw new Error("the transfer reverted on chain (tx " + d.hash.slice(0, 12) + "…). Nothing moved.");
    spent.set(wd.stealth.toLowerCase(), { left: wd.usdc - value, until: Date.now() + 120_000 });
    const doneMsg = "Done: " + fmtTok(value) + " " + SYM + " sent, tx " + d.hash.slice(0, 12) + "…";
    say("pay-hint", doneMsg, "ok"); await scan();
    $("pay-hint").textContent = doneMsg + "\n" + $("pay-hint").textContent;                // the rescan's status must not erase the confirmation
  } catch (e) { say("pay-hint", e.message || String(e), "bad"); }
});
async function waitReceipt(h) {
  for (let i = 0; i < 60; i++) { const r = await api("/receipt?tx=" + h); if (r.status != null) return { ok: r.status === 1 }; await new Promise(z => setTimeout(z, 2000)); }
  throw new Error("not mined yet: " + h);
}

// ---- pay someone: derive the one-time address, then hand off to payStealth() (the only code that builds/sends pay txs,
//      so the flow can be swapped without touching the rest)
/** Sends the payment + announcement from the payer's wallet. token: "TOKEN" (chain stablecoin) or "NATIVE". Returns the tx hash. */
async function payStealth({ token, amount, d, own = false }) {
  if (!STEALTHPAY) throw new Error("The pay contract is not deployed on " + C.name + " yet");
  const ephLen = pad(33n), ephData = d.ephPub.slice(2).padEnd(128, "0"), tagWord = d.viewTag.slice(2).padEnd(64, "0");
  if (token === "TOKEN" && !own) return payGasless({ amount, d, ephLen, ephData, tagWord });
  if (token === "TOKEN") {
    const raw = BigInt(Math.round(amount * TUNIT));
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
async function payGasless({ amount, d, ephLen, ephData, tagWord }) {
  const stats = await api("/relay/stats").catch(() => { throw new Error("The relayer is not reachable."); });
  if (!stats.pay_enabled || !isAddr(stats.relayer) || stats.pay_fee == null) throw new Error("Gasless payments are not available on " + C.name + " right now.");
  if (String(stats.stealthpay || "").toLowerCase() !== STEALTHPAY.toLowerCase()) throw new Error("The relayer serves a different StealthPay contract; refusing.");
  const raw = BigInt(Math.round(amount * TUNIT)), fee = BigInt(stats.pay_fee), feeTo = stats.relayer;
  if (fee < 0n || fee >= raw) throw new Error("The amount is below the relayer fee (" + fmtTok(fee) + " " + SYM + ").");
  const bal = BigInt(await wallet("eth_call", [{ to: USDC, data: "0x70a08231" + padAddr(acct) }, "latest"]));
  if (bal < raw) throw new Error("Your wallet holds less than " + amount + " " + SYM + ".");
  const args = { chainId: C.chainId, stealthPay: STEALTHPAY, token: USDC, stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee, feeRecipient: feeTo };
  const nonce = paymentNonce(args);
  const onchain = await wallet("eth_call", [{ to: STEALTHPAY, data: sel("paymentNonce(address,address,bytes,bytes1,uint256,address)") + padAddr(USDC) + padAddr(d.stealth) + pad(192n) + tagWord + pad(fee) + padAddr(feeTo) + ephLen + ephData }, "latest"]);
  if (String(onchain).toLowerCase() !== nonce.toLowerCase()) throw new Error("Payment nonce mismatch between this page and the contract; refusing to sign.");
  const msg = "You send " + fmtTok(raw) + " " + SYM + ". The receiver gets " + fmtTok(raw - fee) + " " + SYM + ". The relayer fee for the gas is " + fmtTok(fee) + " " + SYM + ". You pay no gas.";
  say("send-hint", msg + " Sign in your wallet…");
  if (!confirm(msg + "\n\nContinue and sign?")) throw new Error("Cancelled. Nothing was signed.");
  const validBefore = Math.floor(Date.now() / 1000) + 3600;
  const typed = receiveTypedData({ token: TOK, chainId: C.chainId, from: acct, stealthPay: STEALTHPAY, amount: raw, validAfter: 0, validBefore, nonce });
  const sig = splitSig(await wallet("eth_signTypedData_v4", [acct, typed]));
  say("send-hint", "Sending through the relayer…");
  const r = await fetch(API + "/relay/pay", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
    token: USDC, amount: raw.toString(), stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: fee.toString(), feeRecipient: feeTo,
    auth: { from: acct, validAfter: "0", validBefore: String(validBefore), v: sig.v, r: sig.r, s: sig.s } }) });
  const j = await r.json(); if (!r.ok || j.error) throw new Error((j.error || "relayer error") + ".");
  say("send-hint", "Submitted, tx " + j.hash.slice(0, 12) + "… waiting for the block…");
  return j.hash;
}
// ---- amount: two linked fields, "you pay" and "receiver gets"; editing one fills the other using the relayer's gasless fee
let payFee = null, amtSrc = "amount";
api("/relay/stats").then(s => { if (s.pay_enabled && s.pay_fee != null) payFee = BigInt(s.pay_fee); calc(); }).catch(() => {});
const curFee = () => $("token").value === "TOKEN" ? (payFee ?? 0n) : 0n, unit = () => $("token").value === "TOKEN" ? TUNIT : NUNIT;
/** Returns { send, get, fee } in token units from the field the user last edited, or null. */
function payAmounts() {
  const v = Number($(amtSrc).value); if (!(v > 0)) return null;
  const raw = BigInt(Math.round(v * unit())), fee = curFee();
  return amtSrc === "amount-get" ? { send: raw + fee, get: raw, fee } : { send: raw, get: raw - fee, fee };
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
    const tx = await payStealth({ token, amount, d, own });
    if (!(await waitReceipt(tx)).ok) throw new Error("the payment reverted: " + tx);
    say("send-hint", "Paid. tx " + tx.slice(0, 12) + "… The receiver will find it with their keys.", "ok");
  } catch (e) { say("send-hint", e.message || String(e), "bad"); }
}
$("btn-pay").addEventListener("click", () => doPay(false));
