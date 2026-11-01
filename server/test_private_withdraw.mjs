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
    case "eth_sendTransaction": {
      if (!P.allowTx) throw new Error("test wallet: transactions are not expected in the gasless flow");      // only the payer of an ETH payment sends a normal transaction (payETH), and only while allowTx is set
      const t = params[0]; if (String(t.from).toLowerCase() !== P.account.address.toLowerCase()) throw new Error("tx for wrong account");
      return createWalletClient({ account: P.account, chain: pubChain, transport: vhttp(RPC) }).sendTransaction({ to: t.to, data: t.data, value: t.value ? BigInt(t.value) : 0n });
    }
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
        if (!body.dry) { const a = privateKeyToAccount(generatePrivateKey()).address; q.depositAddress = a; q.deadline = body.deadline; mock.deposits[a.toLowerCase()] = { amount: amt, state: "PENDING_DEPOSIT", eth: body.originAsset === "nep141:hood.omft.near" }; }
        return send(200, { quote: q, quoteRequest: { ...body, depositMode: "SIMPLE" }, signature: "ed25519:mock", timestamp: new Date().toISOString(), correlationId: "mock" });
      }
      if (u.pathname === "/v0/deposit/submit" && req.method === "POST") {
        mock.submits.push(body); const d = mock.deposits[String(body.depositAddress).toLowerCase()];
        if (!d) return send(400, { message: "unknown deposit address" });
        const rc = await rpc("eth_getTransactionReceipt", [body.txHash]).catch(() => null);          // like 1Click: the deposit tx must exist and have paid the address
        const bal = d.eth ? BigInt(await rpc("eth_getBalance", [body.depositAddress, "latest"])) : BigInt(await rpc("eth_call", [{ to: TOKEN, data: "0x70a08231" + body.depositAddress.slice(2).toLowerCase().padStart(64, "0") }, "latest"]));      // an ETH deposit is a plain transfer: the address balance is the proof
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
    "chains.js": patch(patch(rd("chains.js"), 'stealthPay: "0x6f488f9036519b9eb0f3db98b76c2c1b02b08ac7",', `stealthPay: "${SP}",`, "rh stealthPay"), 'rpc: "https://rpc.mainnet.chain.robinhood.com",', `rpc: "${RPC}",`, "rh rpc"),
    "private-withdraw.js": patch(rd("private-withdraw.js"), 'export const ONECLICK = "https://1click.chaindefuser.com";', `export const ONECLICK = "${MOCK}";`, "ONECLICK constant"),
    "app.html": patch(patch(rd("app.html"), "https://1click.chaindefuser.com", MOCK, "CSP connect-src 1click"), "https://rpc.mainnet.chain.robinhood.com", RPC, "CSP connect-src rpc"),
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
        const rel = p.slice("/stealth/".length) || "app.html"; if (rel.includes("..")) { res.writeHead(400); return res.end(); }
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
        if (/^relay\/(sanctions-list|screen|status)$/.test(m[1]) && req.method === "GET") return proxy(req, res, RELAY, plain);
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


// ================= PART 1b (no network): route "private, fast" = NEAR Intents only (runFast) =================
async function fastUnit() {
  const sd = n => { let a = n >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; };
  // plan: 1-2 parts, sum exact, each >= MIN_PART, delay 0..3 min, tiny amounts are not split
  let good = true, seen = new Set();
  for (let i = 1; i <= 300; i++) { const rng = sd(i), tot = 5_000_000n + BigInt(Math.floor(rng() * 1e9)), pl = PW.fastPlan(tot, rng); seen.add(pl.length);
    if (pl.length < 1 || pl.length > 2 || pl.reduce((a, p) => a + BigInt(p.amount), 0n) !== tot || pl.some(p => BigInt(p.amount) < PW.MIN_PART || p.delayMs < 0 || p.delayMs > 3 * 60_000 || p.state !== "PLANNED")) good = false; }
  ok("fast plan: 1-2 parts (both occur), sum exact, each >= 1 token, delay 0..3 min, PLANNED (300 seeds)", good && seen.has(1) && seen.has(2));
  ok("fast plan: an amount below splitMin is never split", PW.fastPlan(4_000_000n, sd(1)).length === 1);
  // ETA labels come from the constants
  const [lo, hi] = PW.fastEtaRangeMin();
  ok("ETA: fast = " + PW.fastEtaLabel() + " from FAST/FAST_STEP_MIN; standard = " + PW.standardEtaLabel() + " from STANDARD_SEC; fast is well under the 5-15 min of the old split-with-delay", lo === 3 && hi === 11 && PW.fastEtaLabel() === lo + "–" + hi + " min" && PW.standardEtaLabel() === PW.STANDARD_SEC[0] + "–" + PW.STANDARD_SEC[1] + " s" && hi < 15);
  // runFast with stubbed 1Click and relayer
  const world = (o = {}) => { const w = { relays: [], quotes: [], submits: [], polls: {}, deps: 0, saves: [] };
    w.fetchFn = async (url, init = {}) => { const u = String(url), j = x => ({ ok: true, status: 200, json: async () => x });
      if (u.endsWith("/v0/quote")) { const q = JSON.parse(init.body); w.quotes.push(q); if (o.quoteFailAt === w.quotes.length) return { ok: false, status: 500, json: async () => ({ message: "quote service down" }) };
        const dep = "0x" + (0xd0 + ++w.deps).toString(16).padStart(2, "0").repeat(20); return j({ quote: { amountIn: q.amount, amountOut: String(BigInt(q.amount) - 3000n), depositAddress: dep, timeEstimate: 30 }, quoteRequest: q }); }
      if (u.endsWith("/relay")) { const b = JSON.parse(init.body); w.relays.push(b); if (o.relay) return o.relay(b); return j({ hash: "0x" + String(w.relays.length).padStart(64, "0") }); }
      if (u.endsWith("/v0/deposit/submit")) { w.submits.push(JSON.parse(init.body)); return j({}); }
      if (u.includes("/v0/status")) { const a = new URL(u).searchParams.get("depositAddress"); w.polls[a] = (w.polls[a] || 0) + 1; return j({ status: w.polls[a] >= 2 ? "SUCCESS" : "PROCESSING" }); }
      throw new Error("unexpected url " + u); };
    return w; };
  const mk = (w, o = {}) => ({ from: CHAINS.base, to: CHAINS.base, priv: "0x" + "45".repeat(32), stealth: "0x" + "ab".repeat(20), recipient: "0x" + "cd".repeat(20), api: "http://relay", base: "http://1click", fetchFn: w.fetchFn, sleep: async () => {}, pollMs: 1,
    randomNonce: () => "0x" + "11".repeat(32), waitReceipt: async h => ({ ok: true, hash: h }), onProgress: () => {}, ...o });
  const rec = n => ({ v: 1, stealth: "0x" + "ab".repeat(20), parts: Array.from({ length: n }, (_, i) => ({ amount: String(3_000_000 + i * 1111), delayMs: 0, state: "PLANNED", depositAddress: null, txHash: null })) });
  { const w = world(), r = rec(2), hooks = []; const ctx = mk(w, { onSigned: i => hooks.push("signed" + i.index), onDeposited: i => hooks.push("dep" + i.index) });
    await PW.runFast(ctx, r, x => w.saves.push(JSON.stringify(x)));
    ok("runFast: 2 parts, one real quote + one relay + one submit per part, both SUCCESS, record saved at every step", r.parts.every(p => p.state === "SUCCESS") && w.relays.length === 2 && w.quotes.length === 2 && w.submits.length === 2 && w.saves.length >= 6 && PW.fastDone(r));
    ok("runFast: guard hooks fire in order (signed before the relay, deposited after the receipt), parts one after the other", hooks.join() === "signed0,dep0,signed1,dep1");
    ok("runFast: the saved record holds no recipient (no stealth -> recipient link kept in the browser)", !w.saves.some(x => x.includes("cd".repeat(20))));
    ok("runFast: refundTo is the stealth address, recipient the typed one, public quotes", w.quotes.every(q => q.refundTo === ctx.stealth && q.recipient === ctx.recipient && q.confidentiality === "public" && q.dry === false)); }
  { const w = world({ quoteFailAt: 2 }), r = rec(2); let err = null; try { await PW.runFast(mk(w), r, () => {}); } catch (e) { err = e.message; }
    ok("runFast: part 2 fails at the quote -> error, part 1 SUCCESS, part 2 NOT_SENT (money still on the stealth address), nothing signed for it", /quote service down/.test(err) && r.parts[0].state === "SUCCESS" && r.parts[1].state === "NOT_SENT" && w.relays.length === 1 && PW.fastDone(r));
    ok("fastSummary says it plainly", PW.fastSummary(r, v => v.toString(), "USDC").some(l => /Part 2 of 2 .* was not sent: the money is still on the stealth address/.test(l))); }
  { const w = world(), r = rec(3); r.parts[0].state = "DEPOSITED"; r.parts[0].depositAddress = "0x" + "e1".repeat(20); r.parts[0].txHash = "0x" + "aa".repeat(32); r.parts[1].state = "SIGNED"; r.parts[1].depositAddress = "0x" + "e2".repeat(20);
    await PW.runFast(mk(w), r, () => {}, { resume: true });
    ok("resume after a closed tab: DEPOSITED part is followed to SUCCESS, SIGNED becomes UNKNOWN, PLANNED becomes NOT_SENT; nothing is signed, quoted or relayed again", r.parts.map(p => p.state).join() === "SUCCESS,UNKNOWN,NOT_SENT" && w.relays.length === 0 && w.quotes.length === 0);
    ok("resume: the UNKNOWN part is reported with its deposit address, not silently dropped", PW.fastSummary(r, v => v.toString(), "X").some(l => /signed, but the deposit was not seen confirmed/.test(l) && l.includes("0x" + "e2".repeat(20))) && PW.fastDone(r)); }
  { const w = world(), r = rec(1); r.parts[0].state = "DEPOSITED"; r.parts[0].depositAddress = "0x" + "e1".repeat(20); const x = world(); x.fetchFn = async u => ({ ok: true, status: 200, json: async () => ({ status: "REFUNDED" }) });
    await PW.runFast(mk(x), r, () => {}, { resume: true });
    ok("a REFUNDED part is reported as refunded to the stealth address", r.parts[0].state === "REFUNDED" && PW.fastSummary(r)[0].includes("refunded") && PW.fastDone(r)); }
  // 1125 F-3: the fast route reads the relayer's answer like the standard route (PW.relayOutcome)
  { const w = world({ relay: () => ({ ok: false, status: 400, json: async () => ({ error: "bad signature", definite: true }) }) }), r = rec(2); let err = null, refused = 0; try { await PW.runFast(mk(w, { onRefused: () => refused++ }), r, () => {}); } catch (e) { err = e; }
    ok("1125 F-3: a definite relayer refusal (400 JSON) -> part NOT_SENT (not 'signed'), guard hook onRefused called, nothing after it started", err && err.message === "bad signature" && refused === 1 && r.parts.map(p => p.state).join() === "NOT_SENT,NOT_SENT" && w.relays.length === 1 && PW.fastDone(r)); }
  { const w = world({ relay: () => ({ ok: false, status: 400, json: async () => ({ error: "a previous attempt for this authorization is still being confirmed" }) }) }), r = rec(1); let refused = 0; try { await PW.runFast(mk(w, { onRefused: () => refused++ }), r, () => {}); } catch {}
    ok("1130 M-1: a plain 400 ('still being confirmed', no definite flag) keeps the part SIGNED and the guard armed", refused === 0 && r.parts[0].state === "SIGNED"); }
  { const w = world({ relay: () => ({ ok: false, status: 500, json: async () => ({ error: "boom" }) }) }), r = rec(1); let refused = 0; try { await PW.runFast(mk(w, { onRefused: () => refused++ }), r, () => {}); } catch {}
    ok("1125 F-3: a 500 is NOT a definite refusal: part stays SIGNED, guard not cleared", refused === 0 && r.parts[0].state === "SIGNED"); }
  { const w = world({ relay: () => ({ ok: false, status: 400, json: async () => ({ error: "Authorization already used" }) }) }), r = rec(2), found = [];
    await PW.runFast(mk(w, { findTx: async a => { found.push(a.nonce); return "0x" + "ab".repeat(32); } }), r, () => {});
    ok("1125 F-3: 'authorization already used' is followed to its transaction (findTx by the nonce), then submit + poll, both parts SUCCESS", found.length === 2 && r.parts.every(p => p.state === "SUCCESS" && p.txHash === "0x" + "ab".repeat(32)) && w.submits.length === 2); }
  { const w = world({ relay: () => ({ ok: false, status: 400, json: async () => ({ error: "authorization already used" }) }) }), r = rec(1); let err = null; try { await PW.runFast(mk(w), r, () => {}); } catch (e) { err = e.message; }
    ok("1125 F-3: 'already used' with no findable transaction -> SIGNED kept, message carries the deposit address", /hash could not be found/.test(err) && err.includes(r.parts[0].depositAddress) && r.parts[0].state === "SIGNED"); }
  // 1125 F-5: mined but without the expected transfer is not called a revert
  { const w = world(), r = rec(1); let err = null; try { await PW.runFast(mk(w, { waitReceipt: async h => ({ ok: false, unexpected: true, hash: h }) }), r, () => {}); } catch (e) { err = e.message; }
    ok("1125 F-5: rc.unexpected -> 'does not contain the expected transfer', not 'reverted'; part stays SIGNED", /does not contain the expected transfer/.test(err) && !/reverted/.test(err) && r.parts[0].state === "SIGNED"); }
  // 1125 F-1 record gate
  ok("1125 F-1: fastOpenRec is true for PLANNED/SIGNED/DEPOSITED parts, false for finished or missing records", PW.fastOpenRec({ parts: [{ state: "SUCCESS" }, { state: "DEPOSITED" }] }) && PW.fastOpenRec({ parts: [{ state: "PLANNED" }] }) && !PW.fastOpenRec({ parts: [{ state: "UNKNOWN" }, { state: "NOT_SENT" }] }) && !PW.fastOpenRec(undefined) && !PW.fastOpenRec({}));
  // ---- native ETH on the fast route: a plain transaction signed by the stealth key, no relayer. Fake chain (parses every raw transaction with viem), same 1Click stub.
  { const { makeEthChain } = await import("./fake_eth_chain.mjs"), E = await import("../web/eth-send.js"), CR = await import("../web/chain-read.js"), { privateKeyToAccount } = await import("viem/accounts");
    const PR = "0x" + "45".repeat(32), SE = privateKeyToAccount(PR).address.toLowerCase(), AMT = 30_000_000_000_000_000n, nos = async () => {};
    const mkc = () => { const c = makeEthChain(); c.set(SE, 10n ** 18n); return c; };
    const api = (c, o = {}) => ({ prepare: ({ to, value }) => E.prepareSend(c.rpc, { priv: PR, chainId: 4663, from: SE, to, value }), send: o.send || (tx => E.sendRaw(c.rpc, tx)), status: tx => E.txStatus(c.rpc, { from: SE, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), balance: async () => c.balOf(SE) });      // 1146 L-4: the balance before signing is the baseline of a later "dead"
    const ectx = (w, c, o = {}) => ({ ...mk(w), from: CHAINS.rh, to: CHAINS.rh, asset: "ETH", priv: PR, stealth: SE, eth: api(c), waitReceipt: (h, expect) => CR.waitFinal(c.rpc, h, { expect: expect || (x => x.ok && x.hash === c.lastHash), sleep: nos, tries: 4, everyMs: 0 }), ...o });
    const erec = (n = 1) => ({ v: 1, stealth: SE, chain: "rh", dest: "rh", asset: "ETH", parts: Array.from({ length: n }, () => ({ amount: AMT.toString(), delayMs: 0, state: "PLANNED", depositAddress: null, txHash: null })) });
    const wc = (c, hash) => (c.lastHash = hash, true);
    const pendF = f => async (u, i) => String(u).includes("/v0/status") ? { ok: true, status: 200, json: async () => ({ status: "PENDING_DEPOSIT" }) } : f(u, i);      // 1Click: nothing deposited at that address
    { const w = world(), c = mkc(), r = erec(), hooks = []; let atSigned = null;
      const ctx = ectx(w, c, { waitReceipt: (h, expect) => CR.waitFinal(c.rpc, h, { expect, sleep: nos, tries: 4, everyMs: 0 }), onSigned: i => { atSigned = { sends: c.sends.length, p: JSON.stringify(i.ethTx) }; hooks.push("signed"); }, onDeposited: () => hooks.push("dep") });
      await PW.runFast(ctx, r, x => w.saves.push(JSON.stringify(x)));
      ok("ETH fast: one part SUCCESS, NO relayer call, one real quote, one submit, ONE raw transaction from the stealth address", r.parts[0].state === "SUCCESS" && w.relays.length === 0 && w.quotes.length === 1 && w.submits.length === 1 && c.sends.length === 1 && c.nonceOf(SE) === 1);
      ok("ETH fast: the quote is ETH <-> ETH on hood (assets from 1Click), refund to the stealth address, public", w.quotes[0].originAsset === "nep141:hood.omft.near" && w.quotes[0].destinationAsset === "nep141:hood.omft.near" && w.quotes[0].refundTo === SE && w.quotes[0].recipient === ctx.recipient && w.quotes[0].amount === AMT.toString());
      ok("ETH fast: the signing hook fired BEFORE anything reached the chain (the caller saves + arms its guard first), then the deposit hook", atSigned.sends === 0 && hooks.join() === "signed,dep");
      const dest = Object.values(w.polls).length && w.submits[0].depositAddress.toLowerCase(), tx = [...c.mined.values()][0];
      ok("ETH fast: the chain got exactly the amount at the quote's deposit address, nothing else moved but gas", tx.to === dest && tx.value === AMT && c.balOf(dest) === AMT && c.balOf(SE) === 10n ** 18n - AMT - 21000n * c.gasPrice * 2n);
      ok("ETH fast: the saved record keeps the hash and nonce (to follow the transfer after a reload) but neither the raw bytes nor the recipient", /"ethTx":\{"hash":"0x[0-9a-f]{64}","nonce":"0"\}/.test(w.saves.find(x => x.includes("ethTx"))) && !w.saves.some(x => x.includes(atSigned.p.slice(8, 40)) || x.includes("cd".repeat(20)) || x.includes('"raw"')));
      ok("ETH fast: the summary names ETH", PW.fastSummary(r, v => E && (Number(v) / 1e18).toString(), "ETH")[0].includes("ETH")); }
    { const w = world(), c = mkc(), r = erec(); let calls = 0; c.refuse = "max fee per gas less than block base fee"; let refused = 0, err = null;
      try { await PW.runFast(ectx(w, c, { onRefused: () => refused++ }), r, () => {}); } catch (e) { err = e; }
      ok("ETH fast: the node refuses the transaction (fee below its floor) -> definite: part NOT_SENT, the guard hook onRefused fired, e.refused", r.parts[0].state === "NOT_SENT" && refused === 1 && err && err.refused === true && /refused the deposit transaction; nothing was sent/.test(err.message) && c.nonceOf(SE) === 0); }
    { const w = world(), c = mkc(), r = erec(); c.set(SE, AMT + 5000n); let signed = 0, err = null;
      try { await PW.runFast(ectx(w, c, { onSigned: () => signed++ }), r, () => {}); } catch (e) { err = e; }
      ok("ETH fast: amount + fee does not fit the balance -> refused BEFORE signing: part NOT_SENT, onSigned never fired, nothing sent", r.parts[0].state === "NOT_SENT" && signed === 0 && c.sends.length === 0 && /Nothing was sent/.test(err.message)); }
    { const w = world(), c = mkc(), r = erec(); c.dropAnswer = 1; const f0 = w.fetchFn; let n = 0;
      await PW.runFast(ectx(w, c, { waitReceipt: (h, expect) => CR.waitFinal(c.rpc, h, { expect, sleep: nos, tries: 4, everyMs: 0 }) }), r, () => {});
      ok("ETH fast: the answer of the broadcast is lost (network error) -> the SAME bytes go again, the chain says 'already known' = sent: one payment, SUCCESS", r.parts[0].state === "SUCCESS" && c.sends.length === 2 && c.sends[0] === c.sends[1] && c.nonceOf(SE) === 1 && c.balOf(c.mined.values().next().value.to) === AMT); }
    { const w = world(), c = mkc(), r = erec(); let err = null;
      const ctx = ectx(w, c, { eth: api(c, { send: async () => { throw new Error("network down"); } }) });
      try { await PW.runFast(ctx, r, () => {}); } catch (e) { err = e; }
      ok("ETH fast: the broadcast never gets through and the chain does not know it -> an error with the hash and deposit address, the part stays SIGNED (unknown), nothing was refused", /could not confirm that the ETH deposit was sent/.test(err.message) && err.message.includes("tx 0x") && r.parts[0].state === "SIGNED" && r.parts[0].ethTx && c.sends.length === 0);
      const x = world(); await PW.runFast({ base: "http://1click", fetchFn: x.fetchFn, sleep: async () => {}, ethStatus: (rc, tx) => E.txStatus(c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }) }, r, () => {}, { resume: true });
      ok("ETH fast resume of that SIGNED part: the chain does not know the hash and the nonce is free -> UNKNOWN (nothing is ever re-sent from a resume), no quote, no send", r.parts[0].state === "UNKNOWN" && c.sends.length === 0 && x.quotes.length === 0 && x.relays.length === 0); }
    // ---- 1144 M-1: a mined transaction, the answer lost, the resend is answered "nonce too low" (what a real node says): never "refused, nothing sent"
    for (const [name, apiOf, wantSent] of [["status says mined", c => api(c), true], ["status unreadable", c => ({ ...api(c), status: async () => { throw new Error("status down"); } }), false]]) {
      const w = world(), c = mkc(), r = erec(); c.dropAnswer = 1; c.nonceFirst = true; let refused = 0, signed = 0, prep = 0, err = null;
      const eth = apiOf(c), p0 = eth.prepare; eth.prepare = async a => { prep++; return p0(a); };
      try { await PW.runFast(ectx(w, c, { eth, onRefused: () => refused++, onSigned: () => signed++, waitReceipt: (h, expect) => CR.waitFinal(c.rpc, h, { expect, sleep: nos, tries: 4, everyMs: 0 }) }), r, () => {}); } catch (e) { err = e; }
      ok("1144 M-1 fast route (" + name + "): lost answer + resend 'nonce too low' -> " + (wantSent ? "sent: the part completes" : "unknown: not refused, guard hook not fired, part stays SIGNED, no 'nothing was sent'") + "; one signature, one transaction on chain",
        prep === 1 && signed === 1 && refused === 0 && c.mined.size === 1 && c.nonceOf(SE) === 1 && (wantSent ? r.parts[0].state === "SUCCESS" && !err : r.parts[0].state === "SIGNED" && err && !err.refused && !/nothing was sent/i.test(err.message) && err.message.includes("tx 0x")), String(err && err.message) + " " + r.parts[0].state); }
    { // hash mismatch and a rate-limit body are not refusals either
      for (const [name, e] of [["hash mismatch", Object.assign(new Error("the node returned another transaction hash than the one signed"), { rpc: true, mismatch: true })], ["rate limit", Object.assign(new Error("429 Too Many Requests: rate limit exceeded"), { rpc: true })], ["nonce too low", Object.assign(new Error("nonce too low: next nonce 5, tx nonce 4"), { rpc: true })], ["nonce has already been used", Object.assign(new Error("nonce has already been used"), { rpc: true })]])
        ok("1144 M-1: eth-send refused() is false for " + name, E.refused(e) === false);
      ok("1144 M-1: refused() is still true for a plain node refusal, false for 'already known' and for a network failure", E.refused(Object.assign(new Error("insufficient funds for gas * price + value"), { rpc: true })) === true && E.refused(Object.assign(new Error("already known"), { rpc: true })) === false && E.refused(new Error("network down")) === false); }
    { // the exact sequence the standard route (web/app.js ethStandard) runs: sendSettled with the same send/status it passes
      const mk1 = async (apiOver = {}) => { const c = mkc(); c.dropAnswer = 1; c.nonceFirst = true; const tx = await E.prepareSend(c.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: AMT }); let signs = 0;
        const out = await E.sendSettled({ send: () => E.sendRaw(c.rpc, tx), status: () => E.txStatus(c.rpc, { from: SE, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), sleep: nos, ...apiOver }); return { c, tx, out }; };
      let x = await mk1(); ok("1144 M-1 standard route: lost answer + resend 'nonce too low' + status mined -> outcome sent (guard cleared only by the receipt later), one tx on chain, nothing signed again", x.out.outcome === "sent" && x.c.mined.size === 1 && x.c.sends.length === 2 && x.c.sends[0] === x.c.sends[1]);
      x = await mk1({ status: async () => { throw new Error("status down"); } }); ok("... status unreadable -> outcome unknown (the caller keeps the guard and never says 'Nothing was sent')", x.out.outcome === "unknown" && x.c.mined.size === 1);
      x = await mk1({ status: async () => "dead" }); ok("... status dead (a lagging node) -> unknown, the guard stays", x.out.outcome === "unknown");
      const c2 = mkc(); c2.refuse = "max fee per gas less than block base fee"; const tx2 = await E.prepareSend(c2.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: AMT });
      const o2 = await E.sendSettled({ send: () => E.sendRaw(c2.rpc, tx2), status: () => E.txStatus(c2.rpc, { from: SE, hash: tx2.hash, nonce: tx2.nonce }, { sleep: nos }), sleep: nos });
      ok("a refusal on the FIRST answer is still a definite refusal (outcome refused, one send, nothing on chain)", o2.outcome === "refused" && c2.sends.length === 1 && c2.mined.size === 0);
      const c3 = mkc(); let n3 = 0; const tx3 = await E.prepareSend(c3.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: AMT });
      const o3 = await E.sendSettled({ send: async () => { n3++; throw n3 === 1 ? new Error("network down") : Object.assign(new Error("max fee per gas less than block base fee"), { rpc: true }); }, status: () => E.txStatus(c3.rpc, { from: SE, hash: tx3.hash, nonce: tx3.nonce }, { sleep: nos }), sleep: nos });
      ok("a refusal AFTER an unclear attempt is believed when the chain says unsent (nonce free, hash unknown) -> refused", o3.outcome === "refused" && n3 === 2);
      const o4 = await (async () => { let k = 0; return E.sendSettled({ send: async () => { k++; throw k === 1 ? new Error("network down") : Object.assign(new Error("insufficient funds"), { rpc: true }); }, status: async () => { throw new Error("down"); }, sleep: nos }); })();
      ok("... (that last pair) a refusal after an unclear attempt with the chain unreadable -> unknown, never refused", o4.outcome === "unknown"); }
    // ---- 1144 I-3: a part that crashed before the broadcast does not wait an hour when nothing can send it any more
    { const w = world(), c = mkc(), r = erec(); let hash = null;
      await PW.runFast(ectx(w, c, { eth: api(c, { send: async () => { throw new Error("died before the broadcast"); } }), onSigned: i => { hash = i.ethTx.hash; } }), r, () => {}).catch(() => {});
      const base = { base: "http://1click", fetchFn: world().fetchFn, sleep: async () => {}, ethStatus: (rc, tx) => E.txStatus(c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }) };
      await PW.runFast({ ...base }, r, () => {}, { resume: true }); ok("1144 I-3: resume without proof that no tab is running it -> UNKNOWN as before", r.parts[0].state === "UNKNOWN");
      r.parts[0].state = "SIGNED"; await PW.runFast(base, r, () => {}, { resume: true });
      ok("1145 M-1: a node not knowing the tx is no proof: even with no tab running the part stays UNKNOWN, never NOT_SENT", r.parts[0].state === "UNKNOWN" && c.sends.length === 0);
      const r2 = erec(); r2.parts[0].state = "SIGNED"; r2.parts[0].depositAddress = "0x" + "e2".repeat(20); r2.parts[0].ethTx = { hash: "0x" + "ab".repeat(32), nonce: "0" };
      await PW.runFast({ ...base, ethStatus: async () => "pending" }, r2, () => {}, { resume: true }); ok("... a pending transaction is still UNKNOWN even then", r2.parts[0].state === "UNKNOWN"); }
    // ---- 1146 L-3: a refusal that may still land is not "nothing was sent" on the fast and standard routes
    for (const text of ["replacement transaction underpriced", "txpool is full", "insufficient funds for gas * price + value", "context deadline exceeded", "weird proxy failure 502"]) {
      const w = world(), c = mkc(), r = erec(); c.refuse = text; let refused = 0, err = null;
      try { await PW.runFast(ectx(w, c, { onRefused: () => refused++ }), r, () => {}); } catch (e) { err = e; }
      ok("1146 L-3 fast route: '" + text + "' is not a definite refusal: part stays SIGNED, guard hook not fired, no 'nothing was sent'", r.parts[0].state === "SIGNED" && refused === 0 && err && !err.refused && !/nothing was sent/i.test(err.message) && err.message.includes("tx 0x"), String(err && err.message));
      const c2 = mkc(); c2.refuse = text; const tx = await E.prepareSend(c2.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: AMT });
      const o = await E.sendSettled({ send: () => E.sendRaw(c2.rpc, tx), status: () => E.txStatus(c2.rpc, { from: SE, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), sleep: nos });
      ok("1146 L-3 standard route (sendSettled with the page's send/status): '" + text + "' -> unknown (the guard stays), even though the node does not know the hash", o.outcome === "unknown" && c2.sends.length === 1, o.outcome); }
    { const text = "transaction underpriced", c2 = mkc(); c2.refuse = text; const tx = await E.prepareSend(c2.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: AMT });
      const o = await E.sendSettled({ send: () => E.sendRaw(c2.rpc, tx), status: () => E.txStatus(c2.rpc, { from: SE, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), sleep: nos });
      ok("1146 L-5: a plain 'transaction underpriced' is a fee refusal (definite, nothing sent) on the routes", o.outcome === "refused"); }
    // ---- 1146 L-4: "dead" on a fast resume is not proof that nothing moved
    { const mkLanded = async () => { const w = world(), c = mkc(), r = erec(); let tx = null;
        await PW.runFast(ectx(w, c, { eth: api(c, { send: async () => { throw new Error("died before the broadcast"); } }), onSigned: i => { tx = i.ethTx; } }), r, () => {}).catch(() => {});
        await E.sendRaw(c.rpc, tx); c.hideReceipt = true; c.hideTx = true; return { w, c, r, tx }; };      // mined, but this node serves neither receipt nor transaction while its nonce count is already up
      const resume = (c, r, over = {}) => { const x = world(); return PW.runFast({ base: "http://1click", fetchFn: pendF(x.fetchFn), sleep: async () => {}, pollMs: 1, ethStatus: (rc, tx) => E.txStatus(c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), ethBalance: async () => c.balOf(SE), ...over }, r, () => {}, { resume: true }).then(() => x); };
      let m = await mkLanded(); ok("1146 L-4 baseline: the part records the balance from before its signing, outside ethTx", /^\d+$/.test(m.r.parts[0].ethBal) && !("bal" in m.r.parts[0].ethTx));
      let x = await resume(m.c, m.r); ok("1146 L-4: lagging node says 'dead', 1Click shows nothing yet, the balance FELL by the amount -> UNKNOWN (guard kept), never NOT_SENT; nothing submitted", m.r.parts[0].state === "UNKNOWN" && x.submits.length === 0, m.r.parts[0].state);
      m = await mkLanded(); const w2 = world(); const f2 = async (a, i) => String(a).includes("/v0/status") ? { ok: true, status: 200, json: async () => ({ status: "SUCCESS" }) } : w2.fetchFn(a, i);
      await PW.runFast({ base: "http://1click", fetchFn: f2, sleep: async () => {}, pollMs: 1, ethStatus: (rc, tx) => E.txStatus(m.c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), ethBalance: async () => m.c.balOf(SE) }, m.r, () => {}, { resume: true });
      ok("1146 L-4: 'dead' but 1Click already has the deposit -> the part is followed (DEPOSITED, 1Click told, swap polled to SUCCESS), not NOT_SENT", m.r.parts[0].state === "SUCCESS" && w2.submits.length === 1 && w2.submits[0].txHash === m.tx.hash, m.r.parts[0].state);
      m = await mkLanded(); x = await resume(m.c, m.r, { ethBalance: undefined }); ok("1146 L-4: no balance reader on the resume -> UNKNOWN (nothing is believed without a number)", m.r.parts[0].state === "UNKNOWN");
      m = await mkLanded(); m.r.parts[0].ethBal = null; m.c.set(SE, 10n ** 18n); x = await resume(m.c, m.r); ok("1146 L-4: a record without a baseline balance -> UNKNOWN", m.r.parts[0].state === "UNKNOWN");
      m = await mkLanded(); x = await resume(m.c, m.r, { fetchFn: async () => { throw new Error("1Click down"); } }); ok("1146 L-4: 1Click unreadable -> UNKNOWN", m.r.parts[0].state === "UNKNOWN");
      m = await mkLanded(); x = await resume(m.c, m.r, { ethBalance: async () => { throw new Error("rpc down"); } }); ok("1146 L-4: balance unreadable -> UNKNOWN", m.r.parts[0].state === "UNKNOWN"); }
    { const w = world(), c = mkc(), r = erec(); let hash = null;
      await PW.runFast(ectx(w, c, { eth: api(c, { send: async tx => { await E.sendRaw(c.rpc, tx); throw new Error("tab died here"); } }), waitReceipt: async () => { throw new Error("tab died here"); }, onSigned: i => { hash = i.ethTx.hash; } }), r, () => {}).catch(() => {});
      ok("tab dies after the broadcast: the record is SIGNED with the hash", r.parts[0].state === "SIGNED" && r.parts[0].ethTx.hash === hash);
      const x = world(); x.fetchFn = ((f) => async (u, i) => String(u).includes("/v0/status") ? { ok: true, status: 200, json: async () => ({ status: "SUCCESS" }) } : f(u, i))(x.fetchFn);
      await PW.runFast({ base: "http://1click", fetchFn: x.fetchFn, sleep: async () => {}, pollMs: 1, ethStatus: (rc, tx) => E.txStatus(c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }) }, r, () => {}, { resume: true });
      ok("ETH fast resume: the saved hash is MINED -> the part is DEPOSITED, 1Click is told, the swap is followed to SUCCESS; nothing is quoted, signed or sent", r.parts[0].state === "SUCCESS" && x.submits.length === 1 && x.submits[0].txHash === hash && x.quotes.length === 0 && new Set(c.sends).size === 1 && c.nonceOf(SE) === 1); }      // the first run re-sent the same bytes once after the error ("already known"); the resume sent nothing
    for (const [name, setup, want] of [["reverted on chain", c => { c.revertNext = true; }, "NOT_SENT"], ["its nonce was taken by another transaction", c => {}, "NOT_SENT"]]) {
      const w = world(), c = mkc(), r = erec(); let hash = null, sent = false;
      await PW.runFast(ectx(w, c, { eth: api(c, { send: async tx => { sent = true; throw new Error("died before the broadcast"); } }), onSigned: i => { hash = i.ethTx.hash; } }), r, () => {}).catch(() => {});
      if (name.startsWith("reverted")) { c.revertNext = true; const raw = (await E.prepareSend(c.rpc, { priv: PR, chainId: 4663, from: SE, to: "0x" + "d1".repeat(20), value: 1n })); r.parts[0].ethTx = { hash: raw.hash, nonce: raw.nonce }; await E.sendRaw(c.rpc, raw); } else c.bump(SE);
      await PW.runFast({ base: "http://1click", fetchFn: pendF(world().fetchFn), sleep: async () => {}, ethStatus: (rc, tx) => E.txStatus(c.rpc, { from: rc.stealth, hash: tx.hash, nonce: tx.nonce }, { sleep: nos }), ethBalance: async () => c.balOf(SE) }, r, () => {}, { resume: true });      // 1146 L-4: "dead" now also needs 1Click to show no deposit (pendF) and a balance that did not fall (ethBalance)
      ok("ETH fast resume: " + name + " -> " + want + " (the money did not move), not UNKNOWN", r.parts[0].state === want && PW.fastDone(r), r.parts[0].state); }
    { const w = world(), c = mkc(), r = erec(); let err = null; c.revertNext = true;
      try { await PW.runFast(ectx(w, c, { waitReceipt: (h, expect) => CR.waitFinal(c.rpc, h, { expect, sleep: nos, tries: 4, everyMs: 0 }), onRefused: () => {} }), r, () => {}); } catch (e) { err = e; }
      ok("ETH fast: the deposit transaction reverts -> 'reverted; nothing moved', e.refused, the part is NOT_SENT (the value stayed)", r.parts[0].state === "NOT_SENT" && err && err.refused === true && /reverted/.test(err.message) && c.balOf(SE) > 10n ** 18n - 10n ** 15n); }
    ok("a stablecoin runFast resume is as before: SIGNED -> UNKNOWN even when an ethStatus hook exists (no ethTx on the part)", await (async () => { const w = world(), r = rec(1); r.parts[0].state = "SIGNED"; r.parts[0].depositAddress = "0x" + "e2".repeat(20); await PW.runFast({ ...mk(w), ethStatus: async () => { throw new Error("must not be asked"); } }, r, () => {}, { resume: true }); return r.parts[0].state === "UNKNOWN"; })());
  }
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
  await fastUnit();
  await realQuotes();
  console.log("-- browser E2E on anvil fork of Robinhood Chain with a local mock of 1Click --");
  await startMock();
  const anvil = spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(APORT), "--block-time", "1", "--silent"], { stdio: "inherit" }); procs.push(anvil);
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
  await R.goto(SITE + "/stealth/app.html?chain=rh"); await sleep(300);
  await R.click("#btn-keys"); await until(async () => !(await R.eval("document.getElementById('recv-out').hidden")), "keys derived", 15000, 150);
  const meta = (await R.text("meta")).trim();
  const pay = async amt => {
    await Y.goto(SITE + "/stealth/app.html?chain=rh&to=" + encodeURIComponent(meta)); await Y.type("amount", amt); await Y.click("#btn-pay");
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

  // ---- A. UI: three ways to send (the Zcash one needs a cross-origin isolated page, which this test site is not), guards
  await openW();
  const routes = await R.eval("[...document.querySelectorAll('#wd-route option')].map(o => o.value + '|' + o.textContent).join('\\n')");
  ok("UI: standard + private fast offered on rh; maximum privacy (Zcash) is not offered without cross-origin isolation", !(await R.eval("document.getElementById('wd-priv-wrap').hidden")) && routes.split("\n").map(x => x.split("|")[0]).join() === "std,fast", routes.replace(/\n/g, " ; "));
  ok("UI: each label carries its ETA computed from the code constants", routes.includes(PW.standardEtaLabel()) && routes.includes(PW.fastEtaLabel()), routes.replace(/\n/g, " ; "));
  const stealthFull = await R.text("wd-from");
  ok("UI: payout chain list = this chain only", (await R.eval("[...document.querySelectorAll('#wd-dest option')].map(o => o.value).join()")) === "rh");
  const pickRoute = v => R.eval(`(() => { const s = document.getElementById('wd-route'); s.value = ${JSON.stringify(v)}; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  ok("UI: standard shows its note and the Send button, fast opens the panel with the honest line and the Preview button", /Send without gas/.test(await R.text("btn-wd")) && (await R.eval("document.getElementById('wd-priv-opts').hidden")));
  await pickRoute("fast"); ok("UI: fast: options panel opens, button says Preview, the note says the link is broken by the swap, not by cryptography", !(await R.eval("document.getElementById('wd-priv-opts').hidden")) && /Preview/.test(await R.text("btn-wd")) && /not by cryptography/.test(await R.text("wd-route-note")));
  const q0 = mock.quotes.length;
  await R.type("wd-to", recvA); await R.click("#btn-wd");
  await until(async () => await hintBad(), "guard: key wallet", 8000, 100);
  ok("guard: destination == key wallet refused in private mode, no quote requested", /Refused: that is the wallet your keys came from/.test(await R.text("pay-hint")) && mock.quotes.length === q0);
  await R.type("wd-to", payerA); await R.click("#btn-wd");     // the indexer now records the REAL payer (the signer) for a gasless payment, not the relayer (tx.from)
  await until(async () => /that paid you/.test(await R.text("pay-hint")), "guard: payer", 8000, 100);
  ok("guard: destination == real payer refused in private mode, no quote requested", mock.quotes.length === q0);

  // ---- B. preview (dry quote) -> confirm -> relayer -> submit -> status SUCCESS (4.95 < splitMin: one part)
  const sBefore = await bal(stealthFull), w0 = walletTotal(R), dl0 = R.dialogs.length;
  await R.type("wd-to", destAddr); await R.click("#btn-wd");
  await until(async () => !(await R.eval("document.getElementById('wd-quote').hidden")), "preview shown", 20000, 150);
  const qt = await R.text("wd-quote");
  ok("preview: shows what the recipient gets, the fee, the ETA from the constants and the honest line", /Recipient gets≈ 4\.9\d+ USDG/.test(qt.replace(/\s+/g, " ").replace("gets ≈", "gets≈")) && /Fee/.test(qt) && qt.includes(PW.fastEtaLabel()) && /not by cryptography/.test(qt), qt.replace(/\n/g, " | ").slice(0, 260));
  ok("preview: only a dry quote was requested, nothing sent (stealth balance unchanged, relayer idle)", mock.quotes.length === q0 + 1 && mock.quotes.at(-1).dry === true && (await bal(stealthFull)) === sBefore && mock.submits.length === 0);
  ok("preview: button now asks to confirm", /Confirm/.test(await R.text("btn-wd")));
  await R.eval("(() => { const q = [0], orig = Math.random.bind(Math); Math.random = () => q.length ? q.shift() : orig(); return true; })()");      // one part (4.95 < splitMin), random delay scripted to 0
  await R.click("#btn-wd");
  await until(async () => { const h = await R.text("pay-hint"); if (await hintBad()) throw new Error("private withdraw: " + h); return /^Done privately:/.test(h); }, "private withdraw done", 120000, 300)
    .catch(async e => { console.log("  hint:", await R.text("pay-hint"), "| errors:", R.errors.join(";"), "| relayer log:", fs.existsSync(path.join(tmp, "r.log")) ? fs.readFileSync(path.join(tmp, "r.log"), "utf8").slice(-500) : "", "| mock:", JSON.stringify(mock.log)); throw e; });
  const real = mock.quotes.filter(x => !x.dry); const rq = real[0];
  ok("flow: one real quote (dry:false) after the preview dry quote", real.length === 1 && mock.quotes.length === q0 + 2);
  ok("quote fields: USDG(hood) -> same asset on the same chain, EXACT_INPUT, slippage 100, ORIGIN_CHAIN deposit, DESTINATION_CHAIN recipient", rq.originAsset === CHAINS.rh.oneClick.assetId && rq.destinationAsset === CHAINS.rh.oneClick.assetId && rq.swapType === "EXACT_INPUT" && rq.slippageTolerance === 100 && rq.depositType === "ORIGIN_CHAIN" && rq.recipientType === "DESTINATION_CHAIN");
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
  ok("hint says Done privately: 4.95 USDG ... Robinhood Chain", /Done privately: 4\.95 USDG sent through NEAR Intents to 0x[0-9a-fA-F]{6}… on Robinhood Chain\./.test(await R.text("pay-hint")), (await R.text("pay-hint")).split("\n")[0]);
  ok("after a confirmed deposit the double-send guard and the resume record are cleared (and the record never held the recipient)", await R.eval("(() => { const g = JSON.parse(localStorage.getItem('stealth-pending-wd') || '{}'); return Object.values(g).every(v => Number(v) < Date.now()) && !localStorage.getItem('stealth-fast-wd'); })()"));
  ok("/v0/auth/* was never called", !mock.log.some(l => /AUTH/.test(l)));

  // ---- C. two parts from a second, larger payment (the page's random numbers are scripted: 2 parts, unequal weights, no delay)
  await pay("6"); await rpc("anvil_mine", ["0x4"]);
  await R.click('[data-pane="payments"]');
  await until(async () => /, 2 are yours/.test(await scan()), "second payment visible", 40000, 500);
  await R.eval("[...document.querySelectorAll('#pay-list button')].filter(b => /^Withdraw/.test(b.textContent)).at(-1).click(); true");
  const st2 = await R.text("wd-from"); ok("second stealth address differs from the first", st2.toLowerCase() !== stealthFull.toLowerCase());
  const depsBefore = Object.keys(mock.deposits).length, rqBefore = mock.quotes.filter(x => !x.dry).length;
  await pickRoute("fast"); await R.type("wd-to", destAddr); await R.click("#btn-wd");
  await until(async () => !(await R.eval("document.getElementById('wd-quote').hidden")), "split preview", 20000, 150);
  await R.eval("(() => { const q = [0.99, 0.2, 0.9, 0, 0], orig = Math.random.bind(Math); Math.random = () => q.length ? q.shift() : orig(); return true; })()");
  const tSplit = Date.now(); await R.click("#btn-wd");
  const fin = await until(async () => { const h = await R.text("pay-hint"); return /^Done privately:/.test(h) || (await hintBad()) ? h : null; }, "split finished", 120000, 300);
  const deps = Object.keys(mock.deposits).slice(depsBefore); const got = await Promise.all(deps.map(bal)); const parts = mock.quotes.filter(x => !x.dry).slice(rqBefore).map(x => BigInt(x.amount));
  console.log("  split hint:", fin.split("\n")[0].slice(0, 200), "| quotes:", parts.join("+"), "| deposits got:", got.join("+"), "| took", Date.now() - tSplit, "ms");
  ok("split: both parts delivered through the relayer, sum == 5.95 USDG, each >= 1 USDG, one deposit address each", /^Done privately/.test(fin) && got.length === 2 && got[0] + got[1] === 5_950_000n && parts.every(p => p >= 1_000_000n) && new Set(deps).size === 2, fin.replace(/\n/g, " | ").slice(0, 300));
  ok("split: the summary names both parts as sent", /Part 1 of 2/.test(fin) && /Part 2 of 2/.test(fin) && !/not sent/.test(fin));

  // ---- D. a closed tab: a saved record with one part handed to NEAR Intents, one signed and one never started; the reloaded page follows the first, reports the others, and keeps no recipient
  const depD = Object.keys(mock.deposits)[0]; mock.deposits[depD].state = "PROCESSING";
  const recD = { v: 1, stealth: stealthFull.toLowerCase(), chain: "rh", dest: "rh", startedAt: Date.now(), parts: [
    { amount: "2000000", delayMs: 0, state: "DEPOSITED", depositAddress: depD, txHash: "0x" + "ab".repeat(32) }, { amount: "1500000", delayMs: 0, state: "SIGNED", depositAddress: "0x" + "ee".repeat(20), txHash: null }, { amount: "1450000", delayMs: 0, state: "PLANNED", depositAddress: null, txHash: null }] };
  await R.eval(`localStorage.setItem('stealth-fast-wd', ${JSON.stringify(JSON.stringify({ [stealthFull.toLowerCase()]: recD }))}); true`);
  const qBeforeD = mock.quotes.length; await R.goto(SITE + "/stealth/app.html?chain=rh");
  const rt = await until(async () => { const t = await R.text("fast-resume"); return /was not sent/.test(t) ? t : null; }, "resume text", 30000, 300);
  ok("closed tab: the DEPOSITED part is followed to its end, the signed one is reported UNKNOWN with its deposit address, the never-started one NOT_SENT", /Part 1 of 3 .*was sent to the recipient/.test(rt) && /Part 2 of 3 .*deposit was not seen confirmed/.test(rt) && rt.includes("0x" + "ee".repeat(20)) && /Part 3 of 3 .*money is still on the stealth address/.test(rt), rt.replace(/\n/g, " | ").slice(0, 400));
  ok("closed tab: nothing was quoted, signed or relayed again; the record is gone once nothing is open", mock.quotes.length === qBeforeD && (await R.eval("!localStorage.getItem('stealth-fast-wd')")));

  // ---- E. native ETH next to USDG: pay ETH (a normal payETH transaction from the payer's wallet), see it, withdraw it on the standard route (a plain transaction signed by the stealth key, no relayer)
  const realQ0 = mock.quotes.filter(x => !x.dry).length, ETHA = "nep141:hood.omft.near", ethBal = a => rpc("eth_getBalance", [a, "latest"]).then(BigInt), stealthGas = () => rpc("eth_gasPrice").then(BigInt);
  await rpc("anvil_setBalance", [payerA, toHex(10n ** 18n)]); Y.allowTx = true;
  await Y.goto(SITE + "/stealth/app.html?chain=rh&to=" + encodeURIComponent(meta));
  ok("pay: the token choice on Robinhood Chain is USDG / ETH", (await Y.eval("[...document.querySelectorAll('#token option')].map(o => o.value + '|' + o.textContent).join()")) === "TOKEN|USDG,NATIVE|ETH");
  const payEth = async amt => {
    await Y.goto(SITE + "/stealth/app.html?chain=rh&to=" + encodeURIComponent(meta)); await Y.eval("(() => { const s = document.getElementById('token'); s.value = 'NATIVE'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()");
    await Y.type("amount", amt); await until(async () => (await Y.eval("document.getElementById('amount-get').value")) === amt, "amounts linked", 5000, 100);
    await Y.click("#btn-pay"); await until(async () => /^Paid\./.test(await Y.text("send-hint")) || /bad/.test(await Y.eval("document.getElementById('send-hint').className")), "ETH payer finished", 90000, 300);
    ok("pay ETH " + amt + ": paid with one normal transaction from the wallet (payETH), receipt proven by Paid(stealth, ETH, exact amount)", /^Paid\./.test(await Y.text("send-hint")), (await Y.text("send-hint")).slice(0, 80)); };
  const ethWei = x => BigInt(Math.round(Number(x) * 1e18));
  await payEth("0.02"); await rpc("anvil_mine", ["0x4"]);
  await R.goto(SITE + "/stealth/app.html?chain=rh"); await R.click("#btn-keys"); await until(async () => !(await R.eval("document.getElementById('recv-out').hidden")), "keys derived again", 15000, 150); await R.click('[data-pane="payments"]');      // section D reloaded the page: the keys are derived again
  await until(async () => { return /, 3 are yours/.test(await scan()); }, "ETH payment visible to scan", 40000, 500);
  const rows = await R.eval("[...document.querySelectorAll('#pay-list .pay')].map(r => r.textContent).join('\\n')");
  ok("scan: the ETH payment is shown as 0.02 ETH with its real balance read by eth_getBalance (18 decimals), with a Withdraw ETH button; the USDG ones are listed as before", /0\.02 ETH/.test(rows) && /now holds 0\.02 ETH/.test(rows) && /Withdraw ETH/.test(rows), rows.replace(/\n/g, " | ").slice(0, 300));
  const openEth = () => R.eval("[...document.querySelectorAll('#pay-list button')].find(b => /^Withdraw ETH/.test(b.textContent)).click(); true");
  await openEth();
  const ethFrom = await R.text("wd-from"), dest2 = privateKeyToAccount(generatePrivateKey()).address, w1 = walletTotal(R);
  ok("withdraw ETH: the box says ETH, the route list offers Standard (pays its own fee) and Private fast, the destination list is Robinhood ETH, the button says Send ETH",
    (await R.eval("[...document.querySelectorAll('.wd-sym')].map(e => e.textContent).join()")) === "ETH,ETH" && /pays its own network fee/.test(await R.eval("document.getElementById('wd-route').options[0].textContent")) && (await R.eval("[...document.querySelectorAll('#wd-route option')].map(o => o.value).join()")) === "std,fast" && /Robinhood Chain \(ETH\)/.test(await R.eval("document.getElementById('wd-dest').options[0].textContent")) && /Send ETH/.test(await R.text("btn-wd")) && /network fee is paid from this address/.test(await R.text("wd-gas-note")));
  const balBefore = await ethBal(ethFrom), gp = await stealthGas(), listed = JSON.parse(fs.readFileSync(path.join(HERE, "sanctions/evm.json"), "utf8")).addresses[0], nonceS = await rpc("eth_getTransactionCount", [ethFrom, "latest"]);
  await R.type("wd-to", listed); await R.click("#btn-wd"); await until(async () => await hintBad(), "ETH sanctions refusal", 15000, 100);
  ok("standard ETH withdraw: a sanctioned recipient is refused by the page BEFORE anything is signed (ETH never touches the relayer, which screens USDG), nothing was sent", /sanctions list/.test(await R.text("pay-hint")) && (await rpc("eth_getTransactionCount", [ethFrom, "latest"])) === nonceS && (await ethBal(listed)) === 0n);
  const netM = R.mark(); await R.type("wd-to", dest2); await R.click("#btn-wd");
  await until(async () => { const h = await R.text("pay-hint"); if (await hintBad()) throw new Error("ETH std withdraw: " + h); return /^Done: /.test(h) || /Done: /.test(h); }, "ETH standard withdraw done", 90000, 300);
  const gotE = await ethBal(dest2), left = await ethBal(ethFrom), hint = await R.text("pay-hint");
  ok("standard ETH withdraw 'all': the recipient got the balance minus the kept-back network fee (nothing else), the stealth address paid its own gas and keeps only the unused margin", gotE > 0n && gotE < balBefore && balBefore - gotE < 10n ** 15n && left < 10n ** 15n && gotE + left < balBefore && hint.includes("Done: "), `got ${gotE} left ${left} before ${balBefore} gp ${gp}`);
  ok("standard ETH withdraw: 0 wallet prompts (the stealth key signed in the page), no relayer call, no domain-separator read, no 1Click call", walletTotal(R) === w1 && !R.net.slice(netM).some(n => /\/relay(\/pay)?$/.test(n.url) && n.method === "POST") && mock.quotes.filter(x => !x.dry).length === realQ0);
  ok("standard ETH withdraw: the double-send guard and the record are cleared by the confirmed receipt", await R.eval(`(() => { const k = ${JSON.stringify(ethFrom.toLowerCase())}, g = JSON.parse(localStorage.getItem('stealth-pending-wd') || '{}'), e = JSON.parse(localStorage.getItem('stealth-eth-wd') || '{}'); return !(k in g) && !(k in e); })()`));
  await sleep(1500); await until(async () => /Done: /.test(await R.text("pay-hint")) || true, "x", 100, 50);
  // an amount that does not fit with the fee is refused before anything is signed
  await R.click('[data-pane="payments"]'); await payEth("0.03"); await rpc("anvil_mine", ["0x4"]);
  await until(async () => /, 4 are yours/.test(await scan()), "second ETH payment visible", 40000, 500);
  await R.eval("[...document.querySelectorAll('#pay-list .pay')].filter(r => /now holds 0\\.03 ETH/.test(r.textContent))[0].querySelector('button').click(); true");
  const ethFrom2 = await R.text("wd-from"), nonce0 = await rpc("eth_getTransactionCount", [ethFrom2, "latest"]);
  await R.type("wd-to", dest2); await R.type("wd-amt", "0.03"); await R.click("#btn-wd");
  await until(async () => await hintBad(), "amount + fee refused", 15000, 100);
  ok("withdraw ETH: the exact full balance as an amount (no room for the fee) is refused with both numbers, before anything is signed", /plus the network fee/.test(await R.text("pay-hint")) && (await rpc("eth_getTransactionCount", [ethFrom2, "latest"])) === nonce0);

  // ---- F. ETH on the private-fast route (NEAR Intents mock): ETH in as a plain transaction to the quote's deposit address, ETH out
  const qF = mock.quotes.length, subF = mock.submits.length;
  await R.type("wd-amt", ""); await pickRoute("fast"); const destF = privateKeyToAccount(generatePrivateKey()).address;
  await R.eval("(() => { const h = document.getElementById('pay-hint'); h.textContent = ''; h.className = 'hint'; return true; })()");
  await R.type("wd-to", destF); await R.click("#btn-wd");
  await until(async () => !(await R.eval("document.getElementById('wd-quote').hidden")), "ETH preview shown", 30000, 150);
  const qtF = (await R.text("wd-quote")).replace(/\s+/g, " ");
  ok("ETH fast preview: a dry quote ETH -> ETH on hood; it shows the ETH amount the recipient gets, the fee in ETH, the network fee of the deposit that is NOT included, and 'one part'", mock.quotes.length === qF + 1 && mock.quotes.at(-1).dry === true && mock.quotes.at(-1).originAsset === ETHA && mock.quotes.at(-1).destinationAsset === ETHA && /Recipient gets\s*≈ 0\.0\d+ ETH/.test(qtF) && /Fee\s*≈ 0\.000\d+ \(/.test(qtF) && /Not included: the network fee of the deposit transfer/.test(qtF) && /Sent in one part, after a random wait of up to 3 min/.test(qtF), qtF.slice(0, 400));
  const balF = await ethBal(ethFrom2);
  await R.eval("(() => { const q = [0], orig = Math.random.bind(Math); Math.random = () => q.length ? q.shift() : orig(); return true; })()");      // the random wait before the quote scripted to 0
  await R.click("#btn-wd");
  await until(async () => { const h = await R.text("pay-hint"); if (await hintBad()) throw new Error("ETH fast: " + h); return /^Done privately:/.test(h); }, "ETH fast withdraw done", 120000, 300)
    .catch(async e => { console.log("  hint:", await R.text("pay-hint"), "| errors:", R.errors.join(";")); throw e; });
  const rF = mock.quotes.filter(x => !x.dry).at(-1), depF = rF.originAsset === ETHA ? Object.keys(mock.deposits).at(-1) : null, hintF = await R.text("pay-hint");
  ok("ETH fast: the real quote is ETH <-> ETH, refund to the stealth address, recipient as typed, one deposit", rF.originAsset === ETHA && rF.destinationAsset === ETHA && rF.refundTo.toLowerCase() === ethFrom2.toLowerCase() && rF.recipient.toLowerCase() === destF.toLowerCase() && mock.submits.length === subF + 1);
  ok("ETH fast: the quote's deposit address received EXACTLY the quoted amount in ETH (a plain transfer from the stealth address), and the stealth address kept only dust", (await ethBal(depF)) === BigInt(rF.amount) && BigInt(rF.amount) < balF && balF - BigInt(rF.amount) < 10n ** 15n && (await ethBal(ethFrom2)) < 10n ** 15n);
  ok("ETH fast: the answer says Done privately in ETH with 18-decimal text; 0 wallet prompts; the record and the guard are gone", /Done privately: 0\.0\d+ ETH sent through NEAR Intents/.test(hintF) && walletTotal(R) === w1 && await R.eval(`(() => { const k = ${JSON.stringify(ethFrom2.toLowerCase())}, g = JSON.parse(localStorage.getItem('stealth-pending-wd') || '{}'); return !(k in g) && localStorage.getItem('stealth-fast-wd:' + k) == null; })()`), hintF);
  Y.allowTx = false;

  ok("no JS exceptions / console errors on either page", R.errors.length === 0 && Y.errors.length === 0 && R.console.length === 0 && Y.console.length === 0, [...R.errors, ...Y.errors, ...R.console, ...Y.console].join(" | ").slice(0, 300));
  console.log("wallet calls receiver:", JSON.stringify(R.counts), " payer:", JSON.stringify(Y.counts));
  console.log(fails ? "RESULT FAIL " + fails : "RESULT PASS");
  done(fails ? 1 : 0);
} catch (e) { console.log("ERROR", e && e.stack || e); done(2); }
