/* Private withdraw (NEAR Intents 1Click) tests. Run: node test_private_withdraw.mjs   (needs anvil, python3, Google Chrome, network for part 1 only).
   1. REAL dry quotes (dry:true, nothing is created or paid) through web/private-withdraw.js: Base USDC -> Base USDC, Robinhood USDG -> Base USDC.
   2. Session sign-in payload/encoding against the output of @defuse-protocol/intents-sdk 0.93.0 (golden values, no network, nothing is sent to /v0/auth).
   3. Browser E2E on an anvil fork of Robinhood Chain (same harness as test_browser_e2e.mjs) with a LOCAL mock of the 1Click HTTP API:
      pay a stealth address, preview + confirm a private withdraw, assert the mock's deposit address got exactly the amount through the relayer with 0 wallet prompts. */
import { spawn } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import { fileURLToPath } from "url";
import { createPublicClient, createWalletClient, http as vhttp, parseAbi, getAddress, toHex, keccak256, encodeAbiParameters, pad, recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { base58 as scureB58 } from "@scure/base";
import * as PW from "../web/private-withdraw.js";
import { CHAINS } from "../web/chains.js";
import { unhex, hex, addressFromPriv } from "../web/stealth-crypto.js";
const HERE = path.dirname(fileURLToPath(import.meta.url)), WEB = path.join(HERE, "../web");
const APORT = 8955, IPORT = 4053, RPORT = 4054, WPORT = 8956, CPORT = 9457, MPORT = 8957;
const RPC = "http://127.0.0.1:" + APORT, IDX = "http://127.0.0.1:" + IPORT, RELAY = "http://127.0.0.1:" + RPORT, SITE = "http://127.0.0.1:" + WPORT, MOCK = "http://127.0.0.1:" + MPORT;
const TOKEN = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const FEE = 50000n;
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = ms => new Promise(r => setTimeout(r, ms));
let fails = 0; const ok = (name, pass, extra = "") => { console.log((pass ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); if (!pass) fails++; };
const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });
const procs = []; const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-pw-"));
let httpd = null, mockd = null;
const done = code => { procs.forEach(p => { try { p.kill(); } catch {} }); try { httpd && httpd.close(); mockd && mockd.close(); } catch {} setTimeout(() => process.exit(code), 200); };
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

// ---------------- local mock of the 1Click HTTP API (quote / deposit/submit / status) ----------------
const mock = { quotes: [], submits: [], statusPolls: {}, deposits: {}, log: [] };
function startMock() {
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type,authorization", "access-control-allow-methods": "GET,POST,OPTIONS" };
  mockd = http.createServer((req, res) => {
    const u = new URL(req.url, MOCK); const chunks = []; req.on("data", c => chunks.push(c)); req.on("end", async () => {
      const send = (code, o) => { res.writeHead(code, { ...cors, "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      if (req.method === "OPTIONS") { res.writeHead(204, cors); return res.end(); }
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null;
      if (u.pathname === "/v0/quote" && req.method === "POST") {
        mock.quotes.push(body); const amt = BigInt(body.amount), out = amt * 997n / 1000n - 2400n;
        const q = { amountIn: body.amount, amountInFormatted: String(Number(amt) / 1e6), amountInUsd: "0", minAmountIn: body.amount, amountOut: out.toString(), amountOutFormatted: String(Number(out) / 1e6), amountOutUsd: "0", minAmountOut: (out * 99n / 100n).toString(), timeEstimate: 20, refundFee: "75000", withdrawFee: "2400" };
        if (!body.dry) { const a = privateKeyToAccount(generatePrivateKey()).address; q.depositAddress = a; q.deadline = body.deadline; mock.deposits[a.toLowerCase()] = { amount: amt, state: "PENDING_DEPOSIT" }; }
        return send(200, { quote: q, quoteRequest: { ...body, depositMode: "SIMPLE" }, signature: "ed25519:mock", timestamp: new Date().toISOString(), correlationId: "mock" });
      }
      if (u.pathname === "/v0/deposit/submit" && req.method === "POST") {
        mock.submits.push(body); const d = mock.deposits[String(body.depositAddress).toLowerCase()];
        if (!d) return send(400, { message: "unknown deposit address" });
        const rc = await rpc("eth_getTransactionReceipt", [body.txHash]).catch(() => null);          // like 1Click: the deposit tx must exist and have paid the address
        const bal = BigInt(await rpc("eth_call", [{ to: TOKEN, data: "0x70a08231" + body.depositAddress.slice(2).toLowerCase().padStart(64, "0") }, "latest"]));
        if (!rc || bal < d.amount) return send(400, { message: "deposit not found" });
        d.state = "KNOWN_DEPOSIT_TX"; return send(200, { status: d.state });
      }
      if (u.pathname === "/v0/status" && req.method === "GET") {
        const a = (u.searchParams.get("depositAddress") || "").toLowerCase(), d = mock.deposits[a]; if (!d) return send(404, { message: "Deposit address not found" });
        mock.statusPolls[a] = (mock.statusPolls[a] || 0) + 1;
        if (d.state === "KNOWN_DEPOSIT_TX") d.state = "PROCESSING"; else if (d.state === "PROCESSING") d.state = "SUCCESS";
        return send(200, { status: d.state, correlationId: "mock", quoteResponse: {}, updatedAt: new Date().toISOString(), swapDetails: {} });
      }
      if (u.pathname.startsWith("/v0/auth")) { mock.log.push("AUTH CALLED " + u.pathname); return send(500, { message: "auth must never be called" }); }
      send(404, { message: "nf" });
    });
  });
  return new Promise(r => mockd.listen(MPORT, "127.0.0.1", r));
}

// ---------------- nginx emulation (as in test_browser_e2e.mjs) + patched chains.js / private-withdraw.js / index.html CSP pointing at the mock ----------------
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".css": "text/css" };
function startSite(SP, pagesDir) {
  const rd = f => fs.readFileSync(path.join(WEB, f), "utf8");
  const patch = (txt, from, to, what) => { if (!txt.includes(from)) throw new Error("patch target missing: " + what); return txt.split(from).join(to); };
  const patched = {
    "chains.js": patch(rd("chains.js"), "stealthPay: null,", `stealthPay: "${SP}",`, "stealthPay placeholder"),
    "private-withdraw.js": patch(rd("private-withdraw.js"), 'export const ONECLICK = "https://1click.chaindefuser.com";', `export const ONECLICK = "${MOCK}";`, "ONECLICK constant"),
    "index.html": patch(rd("index.html"), "https://1click.chaindefuser.com", MOCK, "CSP connect-src entry"),
  };
  const proxy = async (req, res, base, plainPath, body) => {
    try {
      const r = await fetch(base + plainPath, { method: req.method, headers: { "content-type": req.headers["content-type"] || "application/json", "x-forwarded-for": "127.0.0.1" }, body: req.method === "POST" ? body : undefined });
      const buf = Buffer.from(await r.arrayBuffer()); res.writeHead(r.status, { "content-type": r.headers.get("content-type") || "application/json", "cache-control": "no-store" }); res.end(buf);
    } catch (e) { res.writeHead(502); res.end(JSON.stringify({ error: "upstream: " + e.message })); }
  };
  httpd = http.createServer((req, res) => {
    const u = new URL(req.url, SITE); const p = u.pathname; const chunks = []; req.on("data", c => chunks.push(c)); req.on("end", async () => {
      const body = Buffer.concat(chunks);
      if (p === "/stealth") { res.writeHead(301, { location: "/stealth/" + u.search }); return res.end(); }
      if (p.startsWith("/stealth/")) {
        const rel = p.slice("/stealth/".length) || "index.html"; if (rel.includes("..")) { res.writeHead(400); return res.end(); }
        if (patched[rel]) { res.writeHead(200, { "content-type": MIME[path.extname(rel)] }); return res.end(patched[rel]); }
        const f = path.join(WEB, rel); if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end("nf"); }
        res.writeHead(200, { "content-type": MIME[path.extname(f)] || "application/octet-stream" }); return res.end(fs.readFileSync(f));
      }
      if (p.startsWith("/stealth-api/rh/pages/")) {
        const name = p.slice("/stealth-api/rh/pages/".length); if (!/^(manifest\.json|p\d{6}\.json)$/.test(name)) { res.writeHead(404); return res.end(); }
        const f = path.join(pagesDir, name); if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); return res.end(fs.readFileSync(f));
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

// ================= PART 2 (no network): session payload / encoding vs the official SDK =================
function sessionUnit() {
  const gk = "0x" + "45".repeat(32), ga = addressFromPriv(unhex(gk));
  // golden values produced by @defuse-protocol/intents-sdk 0.93.0 (IntentPayloadBuilder.buildWithSalt + createIntentSignerViem(...).signIntent) for these exact inputs
  const G = { address: "0xE0da1EdCea030875cD0F199d96eB70f6ab78fAF2", salt: "252812b3", deadline: "2026-10-28T12:05:00.000Z", rand15: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    nonce: "Vij2xgAlKBKzADiaWPyv4hgBAgMEBQYHCAkKCwwNDg8=",
    payload: "{\"signer_id\":\"0xe0da1edcea030875cd0f199d96eb70f6ab78faf2\",\"verifying_contract\":\"intents.near\",\"deadline\":\"2026-10-28T12:05:00.000Z\",\"nonce\":\"Vij2xgAlKBKzADiaWPyv4hgBAgMEBQYHCAkKCwwNDg8=\",\"intents\":[]}",
    signature: "secp256k1:FHcEzaJ3KT2cF4Kd9DCK6jPFrztwW2GKcgAikCni2fyd4Afv3ZX6ZJW9UjUS5SiMEtykxXpDXNakf7UqGkLwgtrjr" };
  ok("session: key 0x45.. -> address as in the SDK run", ga === G.address);
  const dl = Date.parse(G.deadline);
  ok("session: nonce == SDK VersionedNonceBuilder.encodeNonce", PW.encodeNonce(unhex("0x" + G.salt), dl, Uint8Array.from(G.rand15)) === G.nonce);
  const s = PW.signSession({ priv: gk, address: ga, saltHex: G.salt, now: dl - 300_000, nonce: G.nonce });
  ok("session: payload string byte-identical to the SDK's", s.payload === G.payload);
  ok("session: signature byte-identical to the SDK's (secp256k1:base58, v in {0,1})", s.signature === G.signature && s.standard === "erc191", s.signature.slice(0, 30) + "…");
  const raw = scureB58.decode(s.signature.slice("secp256k1:".length));
  ok("session: decodes to 65 bytes with recovery byte 0/1", raw.length === 65 && (raw[64] === 0 || raw[64] === 1));
  // what intents.near does: recover the signer from the EIP-191 hash of the payload string
  return recoverMessageAddress({ message: s.payload, signature: hex(Uint8Array.from([...raw.slice(0, 64), raw[64] + 27])) }).then(addr => {
    ok("session: signature verifies as ERC-191 over the payload and recovers the stealth address", addr.toLowerCase() === ga.toLowerCase());
    // random keys: our base58 + encoding == @scure/base on the same bytes; fresh nonces: magic, version, salt, start time ns in the first 8 random bytes
    let same = true; for (let i = 0; i < 50; i++) { const b = crypto.getRandomValues(new Uint8Array(65)); if (i % 5 === 0) b[0] = 0; b[64] &= 1; if (PW.base58(b) !== scureB58.encode(b)) same = false; }
    ok("session: base58 == @scure/base on 50 random byte strings (incl. leading zeros)", same);
    const now = Date.now(), p = JSON.parse(PW.sessionPayload({ address: ga, saltHex: G.salt, now })); const nb = Buffer.from(p.nonce, "base64");
    ok("session: fresh payload: lowercase signer, intents.near, deadline now+5min, empty intents, key order", p.signer_id === ga.toLowerCase() && p.verifying_contract === "intents.near" && p.deadline === new Date(now + 300_000).toISOString() && p.intents.length === 0 && Object.keys(p).join() === "signer_id,verifying_contract,deadline,nonce,intents");
    ok("session: fresh nonce = 32 bytes: magic 5628f6c6, version 0, salt, deadline, start time in the first 8 random bytes", nb.length === 32 && nb.subarray(0, 5).toString("hex") === "5628f6c600" && nb.subarray(5, 9).toString("hex") === G.salt && nb.readBigUInt64LE(9) === BigInt(now + 300_000) * 1000000n && nb.readBigInt64LE(17) === BigInt(now) * 1000000n);
    ok("session: two fresh nonces differ (7 random bytes)", PW.sessionPayload({ address: ga, saltHex: G.salt, now }) !== PW.sessionPayload({ address: ga, saltHex: G.salt, now }));
    return PW.fetchSalt({ fetchFn: async () => ({ json: async () => ({ result: { result: Array.from(Buffer.from('"252812b3"')) } }) }) });
  }).then(async salt => {
    ok("session: fetchSalt parses the NEAR call_function result (stubbed, no network)", salt === "252812b3");
    let seen = null;
    const tok = await PW.sessionSignIn({ priv: gk, address: ga, saltHex: "252812b3", fetchFn: async (url, init) => { seen = { url, init }; return { ok: true, json: async () => ({ accessToken: "T" }) }; } });
    const body = JSON.parse(seen.init.body);
    ok("session: sessionSignIn builds POST /v0/auth/authenticate {signedData:{standard:erc191,payload,signature}} (stub fetch; the real endpoint is never called)", tok === "T" && seen.url.endsWith("/v0/auth/authenticate") && body.signedData.standard === "erc191" && /^secp256k1:/.test(body.signedData.signature));
    ok("session sign-in is OFF in the app (SESSION_SIGNIN=false)", PW.SESSION_SIGNIN === false);
  });
}

// ================= PART 1 (network): REAL dry quotes =================
async function realQuotes() {
  const stealth = "0x" + "11".repeat(20), dest = "0x" + "22".repeat(20), amount = 5_000_000n;
  for (const [name, from, to] of [["Base USDC -> Base USDC", CHAINS.base, CHAINS.base], ["Robinhood USDG -> Base USDC", CHAINS.rh, CHAINS.base]]) {
    const req = PW.buildQuoteRequest({ from, to, amount, recipient: dest, refundTo: stealth, dry: true });
    let j; try { j = await PW.requestQuote({ req }); } catch (e) { ok("real dry quote " + name, false, e.message); continue; }
    const q = j.quote, e = j.quoteRequest, sm = PW.summarizeQuote(j);
    ok("real dry quote " + name + ": amountIn == 5.0, 0 < amountOut < amountIn, timeEstimate number", q.amountIn === "5000000" && BigInt(q.amountOut) > 0n && BigInt(q.amountOut) < 5000000n && BigInt(q.amountOut) > 4_500_000n && typeof q.timeEstimate === "number", `out=${q.amountOut} fee=${sm.feeText} (${sm.feePct}%) eta=${q.timeEstimate}s`);
    ok("real dry quote " + name + ": echoes assets, recipient, refundTo=stealth, ORIGIN_CHAIN/DESTINATION_CHAIN, EXACT_INPUT, dry, public", e.originAsset === from.oneClick.assetId && e.destinationAsset === to.oneClick.assetId && e.recipient === dest && e.refundTo === stealth && e.refundType === "ORIGIN_CHAIN" && e.depositType === "ORIGIN_CHAIN" && e.recipientType === "DESTINATION_CHAIN" && e.swapType === "EXACT_INPUT" && e.dry === true && e.confidentiality === "public");
    ok("real dry quote " + name + ": no depositAddress (dry), signature present", !q.depositAddress && typeof j.signature === "string" && j.signature.length > 10);
  }
  const r = await fetch(PW.ONECLICK + "/v0/quote", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(PW.buildQuoteRequest({ from: CHAINS.rh, to: CHAINS.base, amount, recipient: dest, refundTo: stealth, dry: true, confidentiality: "basic" })) });
  ok("real dry quote: confidentiality=basic without a session token is refused (401), which is why the app falls back to public", r.status === 401, r.status + " " + (await r.text()).slice(0, 80));
  const tiny = await PW.requestQuote({ req: PW.buildQuoteRequest({ from: CHAINS.base, to: CHAINS.base, amount: 100000n, recipient: dest, refundTo: stealth, dry: true }) }).then(() => "no error", e => e.message);
  ok("real dry quote: too-small amount gives a readable API message", /too low|at least/i.test(tiny), tiny);
}

// ---------------- main ----------------
try {
  await sessionUnit();
  await realQuotes();
  console.log("-- browser E2E on anvil fork of Robinhood Chain with a local mock of 1Click --");
  await startMock();
  const anvil = spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(APORT), "--silent"], { stdio: "inherit" }); procs.push(anvil);
  await until(() => rpc("eth_chainId"), "anvil", 60000, 500);
  const pub = createPublicClient({ chain: pubChain, transport: vhttp(RPC) });
  const deployer = createWalletClient({ account: privateKeyToAccount(ANVIL0), chain: pubChain, transport: vhttp(RPC) });
  const art = JSON.parse(fs.readFileSync(path.join(HERE, "../out/StealthPay.sol/StealthPay.json"), "utf8"));
  const dh = await deployer.deployContract({ abi: art.abi, bytecode: art.bytecode.object, args: [ANNOUNCER, TOKEN] });
  const SP = getAddress((await pub.waitForTransactionReceipt({ hash: dh })).contractAddress); console.log("StealthPay deployed on fork:", SP);
  const startBlock = parseInt(await rpc("eth_blockNumber"), 16);
  const bal = a => pub.readContract({ address: TOKEN, abi: parseAbi(["function balanceOf(address) view returns (uint256)"]), functionName: "balanceOf", args: [a] });
  const mint = (a, v) => rpc("anvil_setStorageAt", [TOKEN, keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [a, 1n])), pad(toHex(v), { size: 32 })]);
  const recvPk = generatePrivateKey(), payerPk = generatePrivateKey(), destAddr = privateKeyToAccount(generatePrivateKey()).address;
  const recvA = privateKeyToAccount(recvPk).address, payerA = privateKeyToAccount(payerPk).address;
  await mint(payerA, 20_000_000n);

  const pagesDir = path.join(tmp, "pages");
  const idx = spawn("python3", ["-B", path.join(HERE, "stealth_indexer.py")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, STEALTH_PORT: String(IPORT), STEALTH_DB: path.join(tmp, "ann.db"),
    STEALTH_START_BLOCK: String(startBlock), STEALTH_CONFIRMATIONS: "1", STEALTH_RECONCILE_EVERY: "2", STEALTH_POLL: "1", STEALTH_PAGES_DIR: pagesDir, STEALTH_PAGES_MARGIN: "0", STEALTH_BAL_TTL: "1" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(idx);
  const rk = generatePrivateKey(), relayerAddr = privateKeyToAccount(rk).address; await rpc("anvil_setBalance", [relayerAddr, toHex(10n ** 18n)]);
  const rp = spawn("node", [path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, RELAYER_KEY: rk, STEALTH_RELAY_PORT: String(RPORT), STEALTH_INDEXER: IDX,
    STEALTH_RELAY_STATE: path.join(tmp, "st.json"), STEALTH_RELAY_LOG: path.join(tmp, "r.log"), STEALTH_RELAY_PAY_FEE: String(FEE), STEALTH_RELAY_PAY_FEE_MIN: String(FEE), STEALTH_RELAY_FEE_MIN: "0",
    STEALTH_RELAY_MIN_USDC: "100000", STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", STEALTH_RELAY_MAX_PER_IP: "1000", STEALTH_RELAY_STUCK_S: "20" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(rp); await new Promise(r => rp.stdout.on("data", d => { if (String(d).includes("stealth relayer")) r(); }));
  await until(() => fetch(IDX + "/stealth-api/head").then(r => r.ok), "indexer up", 30000);
  await until(() => fs.existsSync(path.join(pagesDir, "manifest.json")), "initial manifest", 30000);
  await startSite(SP, pagesDir);

  const chrome = spawn(CHROME, ["--headless=new", "--remote-debugging-port=" + CPORT, "--user-data-dir=" + path.join(tmp, "chrome"), "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank"], { stdio: "ignore" }); procs.push(chrome);
  const ver = await until(() => fetch("http://127.0.0.1:" + CPORT + "/json/version").then(r => r.json()), "chrome", 30000);
  const browser = new CDP(ver.webSocketDebuggerUrl); await browser.ready;
  const R = await openPage(browser, "receiver", recvPk), Y = await openPage(browser, "payer", payerPk);
  await R.goto(SITE + "/stealth/?chain=rh"); await sleep(300);
  await R.click("#btn-keys"); await until(async () => !(await R.eval("document.getElementById('recv-out').hidden")), "keys derived", 15000, 150);
  const meta = (await R.text("meta")).trim();
  const pay = async amt => {
    await Y.goto(SITE + "/stealth/?chain=rh&to=" + encodeURIComponent(meta)); await Y.type("amount", amt); await Y.click("#btn-pay");
    await until(async () => /^Paid\./.test(await Y.text("send-hint")) || /bad/.test(await Y.eval("document.getElementById('send-hint').className")), "payer finished", 90000, 300);
    ok("payer paid " + amt + " USDG gaslessly", /^Paid\./.test(await Y.text("send-hint")), (await Y.text("send-hint")).slice(0, 60));
  };
  await pay("5"); await rpc("anvil_mine", ["0x4"]);
  const scan = async () => { await R.eval("document.getElementById('pay-hint').textContent=''"); await R.click("#btn-scan"); return until(async () => { const t = await R.text("pay-hint"); if (/bad/.test(await R.eval("document.getElementById('pay-hint').className"))) throw new Error("scan error: " + t); return /announcements scanned, \d+ are yours/.test(t) ? t : null; }, "scan finished", 120000, 200); };
  await R.click('[data-pane="payments"]');
  await until(async () => /, 1 are yours/.test(await scan()), "payment visible to scan", 40000, 500);
  const stealthAddr = (await R.eval("document.querySelector('#pay-list .pay .mono').textContent"));   // abbreviated; full one is in the withdraw box
  const openW = () => R.eval("[...document.querySelectorAll('#pay-list button')].find(b => /^Withdraw/.test(b.textContent)).click(); true");
  const walletTotal = P => Object.keys(P.counts).filter(k => WALLET_METHODS.includes(k)).reduce((s, k) => s + P.counts[k], 0);
  const hintBad = () => R.eval("/bad/.test(document.getElementById('pay-hint').className)");

  // ---- A. UI: option visible, destination list, guards
  await openW();
  ok("UI: Private option offered on rh (feature flag privateWithdraw)", !(await R.eval("document.getElementById('wd-priv-wrap').hidden")));
  const stealthFull = await R.text("wd-from");
  ok("UI: destination choices = Base (USDC) and Robinhood Chain (USDG), Base first", (await R.eval("[...document.querySelectorAll('#wd-dest option')].map(o => o.value).join()")) === "base,rh");
  await R.click("#wd-private"); ok("UI: options panel opens, button says Preview", !(await R.eval("document.getElementById('wd-priv-opts').hidden")) && /Preview/.test(await R.text("btn-wd")));
  const q0 = mock.quotes.length;
  await R.type("wd-to", recvA); await R.click("#btn-wd");
  await until(async () => await hintBad(), "guard: key wallet", 8000, 100);
  ok("guard: destination == key wallet refused in private mode, no quote requested", /Refused: that is the wallet your keys came from/.test(await R.text("pay-hint")) && mock.quotes.length === q0);
  await R.type("wd-to", payerA); await R.click("#btn-wd");     // the indexer now records the REAL payer (the signer) for a gasless payment, not the relayer (tx.from)
  await until(async () => /that paid you/.test(await R.text("pay-hint")), "guard: payer", 8000, 100).catch(async e => { console.log("  payer guard: hint=", await R.text("pay-hint"), "| payer field of the found payment:", await R.eval("1") , "| payer", payerA); throw e; });
  ok("guard: destination == real payer (the signer of the gasless payment, not the relayer) refused in private mode, no quote requested", mock.quotes.length === q0);

  // ---- B. preview (dry quote) -> confirm -> relayer -> submit -> status SUCCESS
  const sBefore = await bal(stealthFull), w0 = walletTotal(R), dl0 = R.dialogs.length;
  await R.type("wd-to", destAddr); await R.click("#btn-wd");
  await until(async () => !(await R.eval("document.getElementById('wd-quote').hidden")), "preview shown", 20000, 150);
  const qt = await R.text("wd-quote");
  ok("preview: shows send/receive amounts, fee, ETA and the honest privacy note", /You send 4\.95 USDG/.test(qt) && /receives about 4\.9\d+ USDC on Base/.test(qt) && /Fees: 0\.0\d+ \(\d\.\d+%\)/.test(qt) && /Estimated 20 s/.test(qt) && /public swap/.test(qt), qt.replace(/\n/g, " | ").slice(0, 230));
  ok("preview: the honest note about public deposit/payout is on the page", /deposit to NEAR Intents and the payout are both public/.test(await R.eval("document.getElementById('wd-priv-opts').innerText")));
  ok("preview: only a dry quote was requested, nothing sent (stealth balance unchanged, relayer idle)", mock.quotes.length === q0 + 1 && mock.quotes.at(-1).dry === true && (await bal(stealthFull)) === sBefore && mock.submits.length === 0);
  ok("preview: button now asks to confirm", /Confirm/.test(await R.text("btn-wd")));
  await R.click("#btn-wd");
  await until(async () => { const h = await R.text("pay-hint"); if (await hintBad()) throw new Error("private withdraw: " + h); return /^Done privately:/.test(h) && /announcements scanned/.test(h); }, "private withdraw done", 120000, 300)
    .catch(async e => { console.log("  hint:", await R.text("pay-hint"), "| errors:", R.errors.join(";"), "| relayer log:", fs.existsSync(path.join(tmp, "r.log")) ? fs.readFileSync(path.join(tmp, "r.log"), "utf8").slice(-500) : "", "| mock:", JSON.stringify(mock.log)); throw e; });
  const real = mock.quotes.filter(x => !x.dry); const rq = real[0];
  ok("flow: one real quote (dry:false) after the preview dry quote", real.length === 1 && mock.quotes.length === q0 + 2);
  ok("quote fields: originAsset USDG(hood), destinationAsset Base USDC, EXACT_INPUT, slippage 100, ORIGIN_CHAIN deposit, DESTINATION_CHAIN recipient", rq.originAsset === CHAINS.rh.oneClick.assetId && rq.destinationAsset === CHAINS.base.oneClick.assetId && rq.swapType === "EXACT_INPUT" && rq.slippageTolerance === 100 && rq.depositType === "ORIGIN_CHAIN" && rq.recipientType === "DESTINATION_CHAIN" && rq.amount === "4950000");
  ok("quote fields: recipient = typed destination, refundTo = THE STEALTH ADDRESS (not the key wallet, not the payer), refundType ORIGIN_CHAIN", rq.recipient.toLowerCase() === destAddr.toLowerCase() && rq.refundTo.toLowerCase() === stealthFull.toLowerCase() && rq.refundTo.toLowerCase() !== recvA.toLowerCase() && rq.refundTo.toLowerCase() !== payerA.toLowerCase() && rq.refundType === "ORIGIN_CHAIN");
  ok("quote fields: confidentiality public (no session token), deadline in the future, dry false", rq.confidentiality === "public" && rq.dry === false && Date.parse(rq.deadline) > Date.now());
  const dep1 = Object.keys(mock.deposits)[0];
  ok("deposit address received EXACTLY 4.95 USDG on chain via the relayer", (await bal(dep1)) === 4_950_000n, String(await bal(dep1)));
  ok("stealth address is empty afterwards and still has 0 ETH (relayer paid the gas)", (await bal(stealthFull)) === 0n && (await pub.getBalance({ address: stealthFull })) === 0n);
  const sub = mock.submits[0];
  const txRc = await rpc("eth_getTransactionReceipt", [sub.txHash]);
  ok("deposit/submit body {txHash, depositAddress}: the relayer tx that paid the deposit address", mock.submits.length === 1 && sub.depositAddress.toLowerCase() === dep1 && txRc && txRc.status === "0x1" && txRc.to.toLowerCase() === TOKEN.toLowerCase(), JSON.stringify(Object.keys(sub)));
  ok("status polled until SUCCESS (mock: PROCESSING then SUCCESS)", (mock.statusPolls[dep1] || 0) >= 2 && mock.deposits[dep1].state === "SUCCESS", "polls=" + mock.statusPolls[dep1]);
  ok("0 wallet prompts, 0 confirm() dialogs during the private withdraw", walletTotal(R) === w0 && R.dialogs.length === dl0, "prompts=" + (walletTotal(R) - w0));
  ok("hint says Done privately: 4.95 USDG ... Base", /Done privately: 4\.95 USDG sent through NEAR Intents to 0x[0-9a-fA-F]{6}… on Base\./.test(await R.text("pay-hint")), (await R.text("pay-hint")).split("\n")[0]);
  ok("/v0/auth/* was never called", !mock.log.some(l => /AUTH/.test(l)));

  // ---- C. split into 2 random parts from a second payment (relayer allows up to 3 withdrawals per address per day)
  await pay("5"); await rpc("anvil_mine", ["0x4"]);
  await R.click('[data-pane="payments"]');
  await until(async () => /, 2 are yours/.test(await scan()), "second payment visible", 40000, 500);
  await R.eval("[...document.querySelectorAll('#pay-list button')].filter(b => /^Withdraw/.test(b.textContent)).at(-1).click(); true");
  const st2 = await R.text("wd-from"); ok("second stealth address differs from the first", st2.toLowerCase() !== stealthFull.toLowerCase());
  const depsBefore = Object.keys(mock.deposits).length, rqBefore = mock.quotes.filter(x => !x.dry).length;
  await R.click("#wd-private"); await R.eval("(() => { const s = document.getElementById('wd-parts'); s.value = '2'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()");
  await R.eval("document.getElementById('wd-delay-on').click(); true"); await R.type("wd-delay", "0.02");          // random delay up to 1.2 s per part (keeps the test fast)
  await R.type("wd-to", destAddr); await R.click("#btn-wd");
  await until(async () => !(await R.eval("document.getElementById('wd-quote').hidden")), "split preview", 20000, 150);
  ok("split preview mentions 2 random parts and the delay", /cut into 2 random parts/.test(await R.text("wd-quote")) && /random time up to 0\.02 min/.test(await R.text("wd-quote")), (await R.text("wd-quote")).replace(/\n/g, " | ").slice(-170));
  const tSplit = Date.now(); await R.click("#btn-wd");
  const fin = await until(async () => { const h = await R.text("pay-hint"); return (/^Done privately:/.test(h) && /announcements scanned/.test(h)) || (await hintBad()) ? h : null; }, "split finished", 120000, 300);
  const deps = Object.keys(mock.deposits).slice(depsBefore); const got = await Promise.all(deps.map(bal)); const parts = mock.quotes.filter(x => !x.dry).slice(rqBefore).map(x => BigInt(x.amount));
  console.log("  split hint:", fin.split("\n")[0].slice(0, 200), "| quotes:", parts.join("+"), "| deposits got:", got.join("+"), "| took", Date.now() - tSplit, "ms");
  ok("split: both parts delivered through the relayer (3/day per address), sum == 4.95 USDG, each >= 1 USDG and unequal", /^Done privately/.test(fin) && got.length === 2 && got[0] + got[1] === 4_950_000n && parts.every(p => p >= 1_000_000n) && parts[0] !== parts[1] && /Done privately: 4\.95 USDG/.test(fin) && !/already withdrew|limit/.test(fin), fin.split("\n")[0].slice(0, 160));

  ok("no JS exceptions / console errors on either page", R.errors.length === 0 && Y.errors.length === 0 && R.console.length === 0 && Y.console.length === 0, [...R.errors, ...Y.errors, ...R.console, ...Y.console].join(" | ").slice(0, 300));
  console.log("wallet calls receiver:", JSON.stringify(R.counts), " payer:", JSON.stringify(Y.counts));
  console.log(fails ? "RESULT FAIL " + fails : "RESULT PASS");
  done(fails ? 1 : 0);
} catch (e) { console.log("ERROR", e && e.stack || e); done(2); }
