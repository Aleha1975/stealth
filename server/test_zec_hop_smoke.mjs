/* Headless Chrome smoke test of the Zcash hop. Run: node test_zec_hop_smoke.mjs   (needs Google Chrome, network: lightwalletd proxy + 1Click DRY quotes only).
   Serves web/ at /stealth-zec/ with COOP/COEP/CORP exactly like ops/nginx-stealth-zec.conf, under the page's REAL CSP. Loads the app, then in the page:
   dry hop with a fake stealth key -> real wasm wallet, 4 accounts, dry in-quote -> must stop at WAIT_T with a valid t-address; wallet restore + sync through the proxy.
   Fails if: the page is not cross-origin isolated, any CSP violation / page error, any request to /relay, any non-dry quote. Nothing is signed or sent. */
import { spawn } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import { fileURLToPath } from "url";
const WEB = path.join(path.dirname(fileURLToPath(import.meta.url)), "../web"), PORT = 8961, CP = 9461, SITE = "http://127.0.0.1:" + PORT + "/stealth-zec/";
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const types = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json", ".wasm": "application/wasm", ".txt": "text/plain" };
let fails = 0; const ok = (n, p, x = "") => { console.log((p ? "PASS " : "FAIL ") + n + (x ? "  " + x : "")); if (!p) fails++; };
const sleep = ms => new Promise(r => setTimeout(r, ms)); const seen = [];
const srv = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split("?")[0]); seen.push(req.method + " " + u);
  let p = u.replace(/^\/stealth-zec\//, ""); if (p === "" || p.endsWith("/")) p += "index.html"; const f = path.join(WEB, p);
  if (!f.startsWith(WEB) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end("nf"); }
  res.writeHead(200, { "Content-Type": types[path.extname(f)] || "application/octet-stream", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cross-Origin-Resource-Policy": "same-origin", "Cache-Control": "no-store" });
  fs.createReadStream(f).pipe(res);
}).listen(PORT, "127.0.0.1");
const prof = fs.mkdtempSync(path.join(os.tmpdir(), "zec-smoke-"));
const ch = spawn(CHROME, ["--headless=new", "--remote-debugging-port=" + CP, "--user-data-dir=" + prof, "--no-first-run", "about:blank"], { stdio: "ignore" });
const done = code => { try { ch.kill(); srv.close(); fs.rmSync(prof, { recursive: true, force: true }); } catch {} setTimeout(() => process.exit(code), 200); };
process.on("uncaughtException", e => { console.log("UNCAUGHT", e.stack || e); done(2); });
try {
  let tabs; for (let i = 0; i < 40 && !tabs; i++) { await sleep(500); tabs = await fetch("http://127.0.0.1:" + CP + "/json").then(r => r.json()).catch(() => null); }
  const ws = new WebSocket(tabs.find(t => t.type === "page").webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const pend = {}, errors = [], reqs = [];
  const send = (method, params = {}) => new Promise((res, rej) => { pend[++id] = { res, rej }; ws.send(JSON.stringify({ id, method, params })); });
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { const c = pend[m.id]; delete pend[m.id]; m.error ? c.rej(new Error(m.error.message)) : c.res(m.result); }
    else if (m.method === "Runtime.exceptionThrown") errors.push("exception: " + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text).slice(0, 300));
    else if (m.method === "Log.entryAdded" && m.params.entry.level === "error") errors.push("log: " + m.params.entry.text.slice(0, 300) + " " + (m.params.entry.url || ""));
    else if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") errors.push("console: " + m.params.args.map(a => a.value ?? a.description).join(" ").slice(0, 600));
    else if (m.method === "Network.requestWillBeSent") reqs.push(m.params.request.method + " " + m.params.request.url); };
  for (const d of ["Runtime", "Page", "Log", "Network"]) await send(d + ".enable");
  await send("Page.navigate", { url: SITE + "app.html" });
  const ev = async expr => { const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text); return r.result.value; };
  for (let i = 0; i < 40; i++) { if (await ev("document.readyState === 'complete' && !!document.getElementById('btn-keys')").catch(() => false)) break; await sleep(250); }
  ok("app loaded under COOP/COEP, cross-origin isolated", await ev("crossOriginIsolated === true && typeof SharedArrayBuffer === 'function'"));
  ok("UI: Private checkbox present, speed selector, old split/delay options gone", await ev("!!document.getElementById('wd-private') && !document.getElementById('wd-parts') && !document.getElementById('wd-delay') && !!document.getElementById('wd-mode') && /^\\s*Private\\s*$/.test(document.getElementById('wd-private').parentElement.textContent)"));
  const t0 = Date.now();
  const tmo = setTimeout(() => { console.log('TIMEOUT errors:', errors, 'last reqs:', reqs.slice(-12)); done(3); }, 240000);
  const out = JSON.parse(await ev(`(async () => {
    const HM = await import("./zec-hop.js"), { CHAINS } = await import("./chains.js"), words = await HM.loadWords();
    const bad = u => { throw new Error("forbidden call in a dry run: " + u); };
    const fetchFn = (u, i) => { if (String(u).includes("/relay") || (i && i.body && String(i.body).includes('"dry":false'))) bad(u); return fetch(u, i); };
    const ctx = { store: HM.idbStore("zec-smoke-" + Date.now()), stealth: "0x" + "ab".repeat(20), priv: "0x" + "45".repeat(32), chain: CHAINS.rh, dest: CHAINS.base, recipient: "0x" + "11".repeat(20), amount: 5000000n,
      dry: true, stopAt: "WAIT_T", api: "http://127.0.0.1:1", words, loadZjs: HM.sharedZjs, fetchFn, waitReceipt: () => bad("receipt"), onProgress: () => {} };
    const st = await HM.startHop(ctx), { rec } = await HM.findHop(ctx.store, ctx.stealth);
    const summary = await HM.hopSummary(ctx, rec);                      // restore from the saved bytes + real sync through the proxy
    return JSON.stringify({ step: st.step, err: st.err, tIn: st.tIn, birthday: st.birthday, accts: st.accts, nAccts: st.nAccts, inQuote: st.inQuote, dbBytes: rec.db && rec.db.length, mn: await HM.mnemonicFor(ctx.priv, words),
      summary: summary.map(s => ({ account: s.account, t: s.t, transparent: String(s.transparent), orchard: String(s.orchard) })) });
  })()`)); clearTimeout(tmo);
  ok("dry hop stops at WAIT_T without error", out.step === "WAIT_T" && !out.err, out.step + " " + (out.err || "") + " " + (Date.now() - t0) + " ms");
  ok("valid t-address, dry quote recorded (no deposit address)", /^t1[1-9A-HJ-NP-Za-km-z]{33}$/.test(out.tIn) && out.inQuote && out.inQuote.depositAddress === null && BigInt(out.inQuote.amountOut) > 132000n, out.tIn + " zats " + out.inQuote?.amountOut);
  ok("accounts for the mode (" + out.nAccts + "), birthday near the Zcash tip, wallet bytes saved", out.accts.length === out.nAccts && out.nAccts >= 3 && out.birthday > 3_000_000 && out.dbBytes > 1000, "birthday " + out.birthday + " db " + out.dbBytes);
  // live sub-steps against the real wasm wallet + mainnet lightwalletd: continue the same state as a real (non-dry) hop that is waiting for its ZEC. Nothing is signed or sent; the ZEC never "arrives".
  const tmo2 = setTimeout(() => { console.log('TIMEOUT in live wait', errors); done(3); }, 150000);
  const wait = JSON.parse(await ev(`(async () => {
    const HM = await import("./zec-hop.js"), words = await HM.loadWords(), store = HM.idbStore("zec-smoke2-" + Date.now()), msgs = [];
    const ctx0 = { store, stealth: "0x" + "cd".repeat(20), priv: "0x" + "46".repeat(32), chain: (await import("./chains.js")).CHAINS.rh, dest: (await import("./chains.js")).CHAINS.base, recipient: "0x" + "11".repeat(20), amount: 5000000n, dry: true, stopAt: "WAIT_T",
      api: "http://127.0.0.1:1", words, loadZjs: HM.sharedZjs, waitReceipt: () => { throw new Error("no"); }, onProgress: () => {} };
    await HM.startHop(ctx0); const f = await HM.findHop(store, ctx0.stealth); f.rec.st.dry = false; f.rec.st.err = null; await store.put(f.key, f.rec);
    let sleeps = 0, t0 = performance.now(), firstSync = null;
    const ctx = { ...ctx0, dry: false, stopAt: undefined, beatMs: 1000, getUtxos: async () => [], onProgress: (st, m) => { msgs.push(m); if (firstSync == null && /^Syncing/.test(m)) firstSync = performance.now(); },
      sleep: async ms => { if (++sleeps > 3) throw new HM.Halt("smoke: stop waiting"); await new Promise(r => setTimeout(r, 300)); } };
    const st = await HM.runHop(ctx);
    return JSON.stringify({ step: st.step, err: st.err, msgs, syncMs: Math.round(performance.now() - t0), sleeps });
  })()`));
  clearTimeout(tmo2);
  ok("live wait: real wallet syncs from the birthday, shows 'Syncing Zcash wallet N%' then 'Waiting for ZEC to arrive… N s' heartbeats, stays at WAIT_T", wait.step === "WAIT_T" && /smoke: stop waiting/.test(wait.err || "") && wait.msgs.some(m => /^Syncing Zcash wallet \d+%( \(\d+ blocks\))? · \d+ s$/.test(m)) && wait.msgs.filter(m => /^Waiting for ZEC to arrive… \d+ s$/.test(m)).length >= 2, wait.syncMs + " ms, " + wait.msgs.slice(0, 4).join(" | "));
  ok("live wait: first sync from the birthday finished in under 60 s", wait.syncMs < 60000, wait.syncMs + " ms");
  ok("page mnemonic = node golden", out.mn === "youth alone tissue bomb stock old thank speed tissue night ugly exchange lumber salute switch glance peanut among average exhibit parrot stove tool derive");
  ok("restored wallet: same t-address on account 0, all addresses distinct, empty", out.summary[0].t === out.tIn && new Set(out.summary.map(s => s.t)).size === out.summary.length && out.summary.length === out.nAccts && out.summary.every(s => s.transparent === "0" && s.orchard === "0"));
  // the page itself reads GET /relay/stats on load (fee display); only a POST to the relayer would submit anything
  const isSubmit = r => /^POST .*\/relay(\/pay)?$/.test(r);
  ok("no relayer call, no non-dry quote", !reqs.some(isSubmit) && !seen.some(isSubmit));
  ok("only dry 1Click quotes went out", reqs.filter(r => r.startsWith("POST") && r.includes("/v0/quote")).length === 2);
  // the local test server has no API and no favicon: those 404s are expected here
  const real = errors.filter(e => !/404 \(Not Found\) http:\/\/127\.0\.0\.1:\d+\/(stealth-api\/rh\/relay\/stats|favicon\.svg)$/.test(e));
  ok("no page errors, no CSP violations", real.length === 0, real.join(" | "));
  ok("wasm served from /stealth-zec/vendor/webzjs", seen.some(r => r.endsWith("webzjs_wallet_bg.wasm")));
} catch (e) { console.log("ERROR", e.stack || e); fails++; }
console.log(fails ? fails + " FAILED" : "all passed"); done(fails ? 1 : 0);
