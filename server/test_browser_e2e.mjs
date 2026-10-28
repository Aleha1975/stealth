/* Browser E2E on an anvil fork of Robinhood Chain: drives the REAL web/app.js in headless Chrome over the DevTools Protocol.
   Run: node test_browser_e2e.mjs   (needs anvil, python3, Google Chrome; env CHROME=/path to override). Nothing goes to the live chain.
   Layout: anvil fork -> StealthPay deployed -> real indexer (python) + real relayer (node) -> tiny HTTP server emulating nginx
   (server/deploy/stealth-rh.conf) serving web/ with a patched chains.js (rh.stealthPay = deployed address) -> Chrome with a fake
   EIP-1193 window.ethereum (keys held here in Node, every wallet request counted). Receiver and payer are separate browser contexts. */
import { spawn } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import zlib from "zlib"; import { fileURLToPath } from "url";
import { createPublicClient, createWalletClient, http as vhttp, parseAbi, getAddress, toHex, keccak256, encodeAbiParameters, encodeFunctionData, pad } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { secpUtils, hex } from "../web/stealth-crypto.js";
const HERE = path.dirname(fileURLToPath(import.meta.url)), WEB = path.join(HERE, "../web");
const APORT = 8945, IPORT = 3993 + 40, RPORT = 3994 + 40, WPORT = 8946, CPORT = 9447;
const RPC = "http://127.0.0.1:" + APORT, IDX = "http://127.0.0.1:" + IPORT, RELAY = "http://127.0.0.1:" + RPORT, SITE = "http://127.0.0.1:" + WPORT;
const TOKEN = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", ANVIL1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";   // #1 is unlocked in anvil
const FEE = 50000n, AMOUNT = 5_000_000n, EXTRA = Number(process.env.EXTRA_ANN || 1100);
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = ms => new Promise(r => setTimeout(r, ms));
let fails = 0; const ok = (name, pass, extra = "") => { console.log((pass ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); if (!pass) fails++; };
const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });
const procs = []; const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-browser-"));
let httpd = null;
const done = code => { procs.forEach(p => { try { p.kill(); } catch {} }); try { httpd && httpd.close(); } catch {} setTimeout(() => process.exit(code), 200); };
process.on("SIGINT", () => done(1)); process.on("uncaughtException", e => { console.log("UNCAUGHT", e && e.stack || e); done(2); });
process.on("unhandledRejection", e => { console.log("UNHANDLED", e && e.stack || e); done(2); });
async function until(fn, what, ms = 60000, step = 250) { const t0 = Date.now(); let last; for (;;) { try { const v = await fn(); if (v) return v; } catch (e) { last = e; } if (Date.now() - t0 > ms) throw new Error("timeout: " + what + (last ? " (" + last.message + ")" : "")); await sleep(step); } }

// ---------------- minimal CDP client (Node 22 global WebSocket) ----------------
class CDP {
  constructor(url) { this.id = 0; this.cb = new Map(); this.handlers = []; this.ws = new WebSocket(url);
    this.ready = new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = e => rej(new Error("ws error")); });
    this.ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.id) { const c = this.cb.get(m.id); this.cb.delete(m.id); if (c) m.error ? c.rej(new Error(m.error.message + " " + JSON.stringify(m.error.data || ""))) : c.res(m.result); } else this.handlers.forEach(h => h(m)); }; }
  send(method, params = {}, sessionId) { const id = ++this.id; return new Promise((res, rej) => { this.cb.set(id, { res, rej }); this.ws.send(JSON.stringify({ id, method, params, sessionId })); }); }
  on(h) { this.handlers.push(h); }
}

// ---------------- fake wallet (EIP-1193 provider; keys stay in Node) ----------------
const FAKE_ETHEREUM = `(() => { let n = 0; const pend = new Map();
  window.__done = (i, ok, v) => { const p = pend.get(i); pend.delete(i); if (!p) return; const o = JSON.parse(v); ok ? p.res(o) : p.rej(Object.assign(new Error(o.message), { code: o.code })); };
  window.ethereum = { isMetaMask: true, request: ({ method, params }) => new Promise((res, rej) => { const i = ++n; pend.set(i, { res, rej }); window.__bridge(JSON.stringify({ id: i, method, params: params || [] })); }), on() {}, removeListener() {} };
})();`;
const WALLET_METHODS = ["eth_requestAccounts", "eth_signTypedData_v4", "eth_sendTransaction", "personal_sign", "eth_sign", "wallet_switchEthereumChain", "wallet_addEthereumChain"];

async function openPage(browser, name, pk, ctxPerms) {
  const account = privateKeyToAccount(pk);
  const { browserContextId } = await browser.send("Target.createBrowserContext");
  await browser.send("Browser.grantPermissions", { origin: SITE, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"], browserContextId }).catch(() => {});
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId, flatten: true });
  const S = (m, p) => browser.send(m, p, sessionId);
  const P = { name, account, sessionId, calls: [], dialogs: [], net: [], console: [], errors: [], counts: {}, S };
  const count = m => { P.counts[m] = (P.counts[m] || 0) + 1; };
  const reqs = new Map();
  browser.on(async m => {
    if (m.sessionId !== sessionId) return;
    if (m.method === "Runtime.bindingCalled" && m.params.name === "__bridge") {
      const { id, method, params } = JSON.parse(m.params.payload);
      let okv = true, out;
      try { out = await walletRequest(P, method, params); } catch (e) { okv = false; out = { message: e.message, code: e.code || -32603 }; }
      count(method); P.calls.push(method);
      await S("Runtime.evaluate", { expression: `window.__done(${id},${okv},${JSON.stringify(JSON.stringify(out === undefined ? null : out))})` });
    } else if (m.method === "Page.javascriptDialogOpening") {
      P.dialogs.push({ type: m.params.type, message: m.params.message });
      S("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
    } else if (m.method === "Network.requestWillBeSent") { reqs.set(m.params.requestId, { url: m.params.request.url, method: m.params.request.method, bytes: 0 }); P.net.push(reqs.get(m.params.requestId)); }
    else if (m.method === "Network.responseReceived") { const r = reqs.get(m.params.requestId); if (r) { r.status = m.params.response.status; r.cache = m.params.response.fromDiskCache || m.params.response.fromServiceWorker; } }
    else if (m.method === "Network.loadingFinished") { const r = reqs.get(m.params.requestId); if (r) r.bytes = m.params.encodedDataLength; }
    else if (m.method === "Runtime.exceptionThrown") P.errors.push(JSON.stringify(m.params.exceptionDetails.exception && m.params.exceptionDetails.exception.description || m.params.exceptionDetails.text));
    else if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") P.console.push(m.params.args.map(a => a.value || a.description).join(" "));
  });
  await S("Page.enable"); await S("Runtime.enable"); await S("Network.enable");
  await S("Network.setCacheDisabled", { cacheDisabled: false });
  await S("Runtime.addBinding", { name: "__bridge" });
  await S("Page.addScriptToEvaluateOnNewDocument", { source: FAKE_ETHEREUM });
  P.eval = async (expr) => { const r = await S("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error("eval: " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text)); return r.result.value; };
  P.goto = async url => { await S("Page.navigate", { url }); await until(() => P.eval("document.readyState === 'complete' && !!document.getElementById('btn-keys')"), name + " page load", 20000, 200); };
  P.text = id => P.eval(`document.getElementById(${JSON.stringify(id)}).textContent`);
  P.click = sel => P.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no element ${sel}'); e.click(); return true; })()`);
  P.type = (id, v) => P.eval(`(() => { const e = document.getElementById(${JSON.stringify(id)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  P.mark = () => P.net.length;
  P.wallet = () => ({ ...P.counts });
  return P;
}
const pubChain = { id: 4663, name: "rh-fork", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
async function walletRequest(P, method, params) {
  switch (method) {
    case "eth_requestAccounts": case "eth_accounts": return [P.account.address];
    case "eth_chainId": return "0x1237";
    case "net_version": return "4663";
    case "wallet_switchEthereumChain": return null;
    case "eth_signTypedData_v4": {
      if (String(params[0]).toLowerCase() !== P.account.address.toLowerCase()) throw new Error("sign for wrong account");
      const td = JSON.parse(params[1]); const types = { ...td.types }; delete types.EIP712Domain;
      const message = { ...td.message }; for (const f of types[td.primaryType]) if (/^u?int/.test(f.type)) message[f.name] = BigInt(message[f.name]);
      const domain = { ...td.domain }; if (domain.chainId != null) domain.chainId = Number(domain.chainId);
      (P.signed = P.signed || []).push(td.primaryType);
      return P.account.signTypedData({ domain, types, primaryType: td.primaryType, message });
    }
    case "eth_sendTransaction": throw new Error("test wallet: transactions are not expected in the gasless flow");
    default: return rpc(method, params);
  }
}

// ---------------- nginx emulation ----------------
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".css": "text/css" };
function startSite(SP, pagesDir) {
  const chainsJs = fs.readFileSync(path.join(WEB, "chains.js"), "utf8");
  if (!/stealthPay: null,/.test(chainsJs)) throw new Error("chains.js: rh stealthPay placeholder not found");
  const patched = chainsJs.replace("stealthPay: null,", `stealthPay: "${SP}",`);
  const proxy = async (req, res, base, plainPath, body) => {
    try {
      const r = await fetch(base + plainPath, { method: req.method, headers: { "content-type": req.headers["content-type"] || "application/json", "x-forwarded-for": "127.0.0.1" }, body: req.method === "POST" ? body : undefined });
      const buf = Buffer.from(await r.arrayBuffer()); res.writeHead(r.status, { "content-type": r.headers.get("content-type") || "application/json", "cache-control": "no-store" }); res.end(buf);
    } catch (e) { res.writeHead(502); res.end(JSON.stringify({ error: "upstream: " + e.message })); }
  };
  httpd = http.createServer((req, res) => {
    const u = new URL(req.url, SITE); let p = u.pathname;
    const chunks = []; req.on("data", c => chunks.push(c)); req.on("end", async () => {
      const body = Buffer.concat(chunks);
      if (p === "/stealth" ) { res.writeHead(301, { location: "/stealth/" + u.search }); return res.end(); }
      if (p.startsWith("/stealth/")) {
        const rel = p.slice("/stealth/".length) || "index.html"; if (rel.includes("..")) { res.writeHead(400); return res.end(); }
        if (rel === "chains.js") { res.writeHead(200, { "content-type": MIME[".js"] }); return res.end(patched); }
        const f = path.join(WEB, rel); if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end("nf"); }
        res.writeHead(200, { "content-type": MIME[path.extname(f)] || "application/octet-stream" }); return res.end(fs.readFileSync(f));
      }
      if (p.startsWith("/stealth-api/rh/pages/")) {                                          // nginx alias + gzip_static + immutable
        const name = p.slice("/stealth-api/rh/pages/".length); if (!/^(manifest\.json|p\d{6}\.json)$/.test(name)) { res.writeHead(404); return res.end(); }
        const f = path.join(pagesDir, name); if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
        const h = { "content-type": "application/json", "cache-control": name === "manifest.json" ? "public, max-age=5" : "public, max-age=31536000, immutable" };
        if (/gzip/.test(req.headers["accept-encoding"] || "") && fs.existsSync(f + ".gz")) { res.writeHead(200, { ...h, "content-encoding": "gzip", vary: "Accept-Encoding" }); return res.end(fs.readFileSync(f + ".gz")); }
        res.writeHead(200, h); return res.end(fs.readFileSync(f));
      }
      const m = p.match(/^\/stealth-api\/rh\/(.*)$/);
      if (m) {
        const plain = "/stealth-api/" + m[1] + u.search;
        if (/^relay(\/pay)?$/.test(m[1]) && req.method === "POST") return proxy(req, res, RELAY, plain, body);
        if (m[1] === "relay/stats" && req.method === "GET") return proxy(req, res, RELAY, plain);
        if (/^(head|known|balances|receipt|usdc-domain|announcements)$/.test(m[1]) && req.method === "GET") return proxy(req, res, IDX, plain);
      }
      res.writeHead(404, { "content-type": "application/json" }); res.end('{"error":"not an API"}');
    });
  });
  return new Promise(r => httpd.listen(WPORT, "127.0.0.1", r));
}

// ---------------- main ----------------
try {
  const anvil = spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(APORT), "--silent"], { stdio: "inherit" }); procs.push(anvil);
  await until(() => rpc("eth_chainId"), "anvil", 60000, 500);
  console.log("anvil fork chainId", parseInt(await rpc("eth_chainId"), 16), "block", parseInt(await rpc("eth_blockNumber"), 16));
  const pub = createPublicClient({ chain: pubChain, transport: vhttp(RPC) });
  const deployer = createWalletClient({ account: privateKeyToAccount(ANVIL0), chain: pubChain, transport: vhttp(RPC) });
  const art = JSON.parse(fs.readFileSync(path.join(HERE, "../out/StealthPay.sol/StealthPay.json"), "utf8"));
  const dh = await deployer.deployContract({ abi: art.abi, bytecode: art.bytecode.object, args: [ANNOUNCER, TOKEN] });
  const SP = getAddress((await pub.waitForTransactionReceipt({ hash: dh })).contractAddress); console.log("StealthPay deployed on fork:", SP);
  const startBlock = parseInt(await rpc("eth_blockNumber"), 16);
  const bal = a => pub.readContract({ address: TOKEN, abi: parseAbi(["function balanceOf(address) view returns (uint256)"]), functionName: "balanceOf", args: [a] });
  const mint = (a, v) => rpc("anvil_setStorageAt", [TOKEN, keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [a, 1n])), pad(toHex(v), { size: 32 })]);   // balance mapping = slot 1
  const recvPk = generatePrivateKey(), payerPk = generatePrivateKey(), thirdAddr = privateKeyToAccount(generatePrivateKey()).address;
  const recvA = privateKeyToAccount(recvPk).address, payerA = privateKeyToAccount(payerPk).address;
  await mint(payerA, 10_000_000n); await mint(recvA, 1_000_000n);
  ok("payer funded 10 USDG, no ETH", (await bal(payerA)) === 10_000_000n && (await pub.getBalance({ address: payerA })) === 0n);

  // indexer + relayer as real processes
  const pagesDir = path.join(tmp, "pages");
  const idx = spawn("python3", ["-B", path.join(HERE, "stealth_indexer.py")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, STEALTH_PORT: String(IPORT), STEALTH_DB: path.join(tmp, "ann.db"),
    STEALTH_START_BLOCK: String(startBlock), STEALTH_CONFIRMATIONS: "1", STEALTH_RECONCILE_EVERY: "2", STEALTH_POLL: "1", STEALTH_PAGES_DIR: pagesDir, STEALTH_PAGES_MARGIN: "0", STEALTH_BAL_TTL: "1" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(idx); let idxLog = ""; idx.stdout.on("data", d => { idxLog = (idxLog + d).slice(-1500); });
  const rk = generatePrivateKey(), relayerAddr = privateKeyToAccount(rk).address; await rpc("anvil_setBalance", [relayerAddr, toHex(10n ** 18n)]);
  const rp = spawn("node", [path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, RELAYER_KEY: rk, STEALTH_RELAY_PORT: String(RPORT), STEALTH_INDEXER: IDX,
    STEALTH_RELAY_STATE: path.join(tmp, "st.json"), STEALTH_RELAY_LOG: path.join(tmp, "r.log"), STEALTH_RELAY_PAY_FEE: String(FEE), STEALTH_RELAY_PAY_FEE_MIN: String(FEE), STEALTH_RELAY_FEE_MIN: "0",
    STEALTH_RELAY_MIN_USDC: "100000", STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", STEALTH_RELAY_MAX_PER_IP: "1000", STEALTH_RELAY_STUCK_S: "20" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(rp); await new Promise(r => rp.stdout.on("data", d => { if (String(d).includes("stealth relayer")) r(); }));
  await until(() => fetch(IDX + "/stealth-api/head").then(r => r.ok), "indexer up", 30000);
  await until(() => fs.existsSync(path.join(pagesDir, "manifest.json")), "initial manifest", 30000);
  await startSite(SP, pagesDir);
  const st = await (await fetch(SITE + "/stealth-api/rh/relay/stats")).json();
  ok("nginx emulation: relay/stats reachable, pay enabled, fee 0.05", st.pay_enabled === true && st.stealthpay === SP && st.pay_fee === String(FEE), JSON.stringify({ pay_fee: st.pay_fee }));
  ok("nginx emulation: non-API path is 404", (await fetch(SITE + "/stealth-api/rh/nope")).status === 404);

  // Chrome
  const chromeDir = path.join(tmp, "chrome");
  const chrome = spawn(CHROME, ["--headless=new", "--remote-debugging-port=" + CPORT, "--user-data-dir=" + chromeDir, "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" }); procs.push(chrome);
  const ver = await until(() => fetch("http://127.0.0.1:" + CPORT + "/json/version").then(r => r.json()), "chrome", 30000);
  const browser = new CDP(ver.webSocketDebuggerUrl); await browser.ready;
  console.log("browser:", ver.Browser);

  const R = await openPage(browser, "receiver", recvPk), Y = await openPage(browser, "payer", payerPk);
  await R.goto(SITE + "/stealth/?chain=rh");
  ok("page loaded for rh with deployed StealthPay (patched chains.js)", (await R.text("sp-addr")) === SP, await R.text("sp-addr"));
  await sleep(300); ok("wallet auto-detected via eth_accounts", (await R.text("wbtn")).startsWith(recvA.slice(0, 6).toLowerCase()), await R.text("wbtn"));

  // ---- 1. receiver derives keys
  const r0 = R.wallet();
  await R.click("#btn-keys");
  await until(async () => !(await R.eval("document.getElementById('recv-out').hidden")), "keys derived", 15000, 150);
  const meta = (await R.text("meta")).trim(), link = (await R.text("paylink")).trim();
  ok("receiver: meta-address st:rh:0x...", /^st:rh:0x[0-9a-f]{132}$/i.test(meta), meta.slice(0, 20) + "…");
  ok("receiver: pay link is SITE/stealth/?chain=rh&to=meta", link === SITE + "/stealth/?chain=rh&to=" + meta, link.slice(0, 50) + "…");
  const rKeys = { sig: (R.counts.eth_signTypedData_v4 || 0) - (r0.eth_signTypedData_v4 || 0), tx: (R.counts.eth_sendTransaction || 0) - (r0.eth_sendTransaction || 0) };
  ok("receiver keys: exactly 1 wallet signature, 0 transactions", rKeys.sig === 1 && rKeys.tx === 0 && R.signed[0] === "StealthKeys", JSON.stringify(rKeys) + " " + R.signed);
  await R.click("#copy-link");
  { const okc = await until(async () => /Link copied/.test(await R.text("recv-hint")), "copy link", 5000, 100).catch(() => false); ok("copy link button works", !!okc, "hint=" + await R.text("recv-hint")); }

  // ---- 2. payer pays 5 USDG gasless
  await Y.goto(SITE + "/stealth/?chain=rh&to=" + encodeURIComponent(meta));
  ok("payer: deep link fills recipient and opens Pay tab", (await Y.eval("document.getElementById('to-meta').value")) === meta && !(await Y.eval("document.getElementById('pane-pay').hidden")));
  await Y.type("amount", "5");
  const y0 = Y.wallet(), pm = Y.dialogs.length;
  await Y.click("#btn-pay");
  await until(async () => /^Paid\./.test(await Y.text("send-hint")) || /bad/.test(await Y.eval("document.getElementById('send-hint').className")), "payer finished", 90000, 300);
  const yHint = await Y.text("send-hint");
  ok("payer: UI says Paid.", /^Paid\. tx 0x[0-9a-f]{10}/.test(yHint), yHint.split("\n").pop().slice(0, 100));
  const yd = { sig: (Y.counts.eth_signTypedData_v4 || 0) - (y0.eth_signTypedData_v4 || 0), tx: (Y.counts.eth_sendTransaction || 0) - (y0.eth_sendTransaction || 0), dialogs: Y.dialogs.length - pm };
  ok("payer: exactly 1 signature, 0 transactions, 1 confirm()", yd.sig === 1 && yd.tx === 0 && yd.dialogs === 1 && Y.signed.at(-1) === "ReceiveWithAuthorization", JSON.stringify(yd));
  ok("payer: confirm text shows 5.00 / 4.95 / 0.05", /5\.00 USDG/.test(Y.dialogs.at(-1).message) && /4\.95 USDG/.test(Y.dialogs.at(-1).message) && /0\.05 USDG/.test(Y.dialogs.at(-1).message), Y.dialogs.at(-1).message.split("\n")[0]);
  ok("payer: debited 5 USDG on chain, still 0 ETH", (await bal(payerA)) === 10_000_000n - AMOUNT && (await pub.getBalance({ address: payerA })) === 0n);
  ok("relayer got the 0.05 fee", (await bal(relayerAddr)) === FEE);
  const payBlock = parseInt(await rpc("eth_blockNumber"), 16);
  await rpc("anvil_mine", ["0x4"]);

  // ---- 3. receiver scans, finds it, withdraws all via relayer to a third address
  await R.click('[data-pane="payments"]');
  const scan = async P => { await P.eval("document.getElementById('pay-hint').textContent=''"); await P.click("#btn-scan"); return until(async () => { const t = await P.text("pay-hint"); const bad = await P.eval("document.getElementById('pay-hint').className"); if (/bad/.test(bad)) throw new Error("scan error: " + t); return /announcements scanned, \d+ are yours/.test(t) ? t : null; }, "scan finished", 120000, 200); };
  let t = await until(async () => { const s = await scan(R); return /, 1 are yours/.test(s) ? s : null; }, "payment visible to scan", 40000, 500);
  const payText = await R.eval("document.getElementById('pay-list').innerText");
  ok("scan #1 finds the payment", /, 1 are yours/.test(t), t.split("\n").pop());
  ok("scan #1 shows 4.95 USDG (5 - fee) and holds 4.95", /4\.95 USDG/.test(payText) && /now holds 4\.95 USDG/.test(payText), payText.replace(/\n/g, " | ").slice(0, 140));
  const w0 = R.wallet(), rdl = R.dialogs.length;
  await R.eval("[...document.querySelectorAll('#pay-list button')].find(b => /^Withdraw/.test(b.textContent)).click(); true");
  await R.type("wd-to", thirdAddr); await R.click("#btn-wd");
  await until(async () => { const h = await R.text("pay-hint"); if (/bad/.test(await R.eval("document.getElementById('pay-hint').className"))) throw new Error("withdraw: " + h); return /^Done:/.test(h) && /announcements scanned/.test(h); }, "withdraw done", 90000, 300).catch(async e => { console.log("  withdraw hint:", await R.text("pay-hint"), "| errors:", R.errors.join(";"), "| relayer log:", fs.existsSync(path.join(tmp, "r.log")) ? fs.readFileSync(path.join(tmp, "r.log"), "utf8").slice(-600) : ""); throw e; });
  const wdWallet = Object.keys(R.counts).filter(k => WALLET_METHODS.includes(k)).reduce((s, k) => s + (R.counts[k] || 0) - (w0[k] || 0), 0);
  ok("withdraw: 0 wallet prompts, 0 confirm()", wdWallet === 0 && R.dialogs.length === rdl, "prompts=" + wdWallet);
  ok("third address received 5 - fee = 4.95 USDG on chain", (await bal(thirdAddr)) === AMOUNT - FEE, String(await bal(thirdAddr)));
  ok("withdraw hint says Done: 4.95 USDG", /Done: 4\.95 USDG/.test(await R.text("pay-hint")), (await R.text("pay-hint")).slice(0, 80));
  // withdrawing to own wallet / payer must be refused by the UI
  ok("(self-check) no page errors so far", R.errors.length === 0 && Y.errors.length === 0, [...R.errors, ...Y.errors].join(" | ").slice(0, 200));

  // ---- 4. 1100 extra announcements on chain -> one full history page
  console.log("generating", EXTRA, "announcements on chain ...");
  const ann = parseAbi(["function announce(uint256 schemeId, address stealthAddress, bytes ephemeralPubKey, bytes metadata)"]);
  const n0 = parseInt(await rpc("eth_getTransactionCount", [ANVIL1, "latest"]), 16);
  const tgen = Date.now(); await rpc("evm_setAutomine", [false]);          // parallel sends with automine on get dropped/reordered; queue them and mine explicitly
  for (let i = 0; i < EXTRA; i += 50) {
    await Promise.all(Array.from({ length: Math.min(50, EXTRA - i) }, (_, j) => {
      const k = i + j, eph = toHex(secpUtils.getPublicKey(secpUtils.utils.randomPrivateKey(), true)), sa = privateKeyToAccount(generatePrivateKey()).address;
      const meta = "0x" + (k % 256).toString(16).padStart(2, "0") + "a9059cbb" + TOKEN.slice(2).toLowerCase() + (1_000_000 + k).toString(16).padStart(64, "0");
      return rpc("eth_sendTransaction", [{ from: ANVIL1, to: ANNOUNCER, gas: "0x30d40", nonce: "0x" + (n0 + k).toString(16), data: encodeFunctionData({ abi: ann, functionName: "announce", args: [1n, sa, eph, meta] }) }]);
    }));
  }
  for (let i = 0; i < 40; i++) { await rpc("anvil_mine", ["0x1"]); if (parseInt(await rpc("eth_getTransactionCount", [ANVIL1, "latest"]), 16) >= n0 + EXTRA) break; }
  await rpc("evm_setAutomine", [true]);
  ok("all " + EXTRA + " announcements mined", parseInt(await rpc("eth_getTransactionCount", [ANVIL1, "latest"]), 16) === n0 + EXTRA);
  const lastBlock = parseInt(await rpc("eth_blockNumber"), 16);
  console.log("  done in", ((Date.now() - tgen) / 1000).toFixed(1), "s, head", lastBlock, "(txs mined:", lastBlock - payBlock - 4, ")");
  await rpc("anvil_mine", ["0x96"]);                                                          // 150 blocks: row #1024 is far below "safe"
  const head = await until(async () => { const h = await (await fetch(IDX + "/stealth-api/head")).json(); return h.head >= lastBlock && h.count >= 1024 + 20 ? h : null; }, "indexer caught up", 120000, 500).catch(async e => { console.log("  head:", JSON.stringify(await (await fetch(IDX + "/stealth-api/head")).json()), "anvil block", parseInt(await rpc("eth_blockNumber"), 16), "\n  indexer log:", idxLog); throw e; });
  console.log("  indexer head", head.head, "count", head.count);
  const man = await until(() => { try { const m = JSON.parse(fs.readFileSync(path.join(pagesDir, "manifest.json"), "utf8")); return m.full_pages >= 1 ? m : null; } catch { return null; } }, "history page written", 60000, 500);
  ok("indexer wrote >=1 full history page (+.gz)", man.full_pages >= 1 && fs.existsSync(path.join(pagesDir, "p000000.json.gz")), JSON.stringify(man));

  // ---- 5. scan A (fetches page 0 + tail), scan B (manifest + tail only)
  await sleep(1500);                                                                          // /balances micro-cache (prod 15 s, test 1 s): a rescan right after a withdraw shows the old balance
  let mk = R.mark();
  const sA = await scan(R); const netA = R.net.slice(mk).filter(x => x.url.startsWith(SITE + "/stealth-api/"));
  const pagesA = netA.filter(x => /\/pages\/p\d+\.json/.test(x.url));
  ok("scan A finds the payment among ~1100 others", /, 1 are yours/.test(sA), sA.split("\n").pop());
  ok("scan A scanned >= 1100 announcements", Number((sA.match(/(\d+) announcements scanned/) || [])[1]) >= EXTRA, sA.split("\n").pop());
  ok("scan A downloaded history page 0 (200, gzip path)", pagesA.length === 1 && /p000000\.json\?v=\d+$/.test(pagesA[0].url) && pagesA[0].status === 200, pagesA.map(x => x.url.replace(SITE, "")).join(","));
  const listA = await R.eval("document.getElementById('pay-list').innerText");
  ok("scan A still shows the 4.95 USDG payment (now holds 0.00)", /4\.95 USDG/.test(listA) && /now holds 0\.00 USDG/.test(listA), listA.replace(/\n/g, " | ").slice(0, 120));
  mk = R.mark();
  const sB = await scan(R); const netB = R.net.slice(mk);
  const bUrls = netB.map(x => x.url.replace(SITE, "").replace(/\?.*/, "?…"));
  ok("scan B finds the payment again", /, 1 are yours/.test(sB), sB.split("\n").pop());
  ok("scan B: no history page fetched (IndexedDB cache)", !netB.some(x => /\/pages\/p\d+\.json/.test(x.url)), bUrls.join(","));
  ok("scan B: only manifest + tail (+head/balances)", netB.some(x => /pages\/manifest\.json/.test(x.url)) && netB.some(x => /\/announcements\?since=1024&/.test(x.url)) && netB.every(x => /manifest\.json|\/announcements\?since=\d+&limit=2000|\/head|\/balances|\/favicon/.test(x.url)), bUrls.join(","));
  console.log("  scan A transfer", netA.reduce((s, x) => s + x.bytes, 0), "bytes in", netA.length, "requests; scan B", netB.reduce((s, x) => s + x.bytes, 0), "bytes in", netB.length, "requests");
  ok("no JS exceptions / console errors on either page", R.errors.length === 0 && Y.errors.length === 0 && R.console.length === 0 && Y.console.length === 0, [...R.errors, ...Y.errors, ...R.console, ...Y.console].join(" | ").slice(0, 300));

  console.log("PROMPTS receiver keys:", rKeys.sig, "signature,", rKeys.tx, "tx | payer:", yd.sig, "signature,", yd.tx, "tx,", yd.dialogs, "confirm | withdraw: wallet prompts", wdWallet);
  console.log("wallet calls receiver:", JSON.stringify(R.counts), " payer:", JSON.stringify(Y.counts));
  console.log(fails ? "RESULT FAIL " + fails : "RESULT PASS");
  done(fails ? 1 : 0);
} catch (e) { console.log("ERROR", e && e.stack || e); done(2); }
