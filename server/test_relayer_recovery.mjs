/* Offline tests for audit 1160 (relayer.mjs): stuck sends, restart, wedged nonce, fee ceiling, budget, fee marker, start-up refusals, lock file, client address.
   No anvil, no network, no funds: a fake JSON-RPC node (below) holds the chain; the relayer runs as a child process against it (each scenario its own env / state file).
   Run: node test_relayer_recovery.mjs      (a few minutes' worth of seconds: STUCK_S and the poll gaps are 1 s or less) */
import { spawn, spawnSync } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import { fileURLToPath } from "url";
import { parseTransaction, recoverTransactionAddress, keccak256, parseAbi, decodeFunctionData, encodeAbiParameters, toHex, getAddress, hexToBigInt, parseSignature, encodeFunctionResult, decodeAbiParameters } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { clientIp } from "./relay-util.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url)), ME = fileURLToPath(import.meta.url);
const CC = JSON.parse(fs.readFileSync(path.join(HERE, "chains.json"), "utf8")).rh;
const TOKEN = getAddress(CC.token), SP = getAddress("0x" + "99".repeat(20)), GWEI = 1_000_000_000n;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hx = n => "0x" + BigInt(n).toString(16);
const key = a => String(a).toLowerCase();

// ---------------------------------------------------------------- fake node
function makeNode() {
  const c = { baseFee: GWEI, tip: GWEI / 10n, latest: new Map(), pool: new Map(), mined: new Map(), sends: [], hangSend: false, mining: false, block: 16, calls: {}, hideInput: false };
  const nonceOf = a => c.latest.get(key(a)) ?? 0;
  const poolOf = a => [...c.pool.values()].filter(t => t.from === key(a));
  const pendingOf = a => { let n = nonceOf(a); while (poolOf(a).some(t => t.nonce === n)) n++; return n; };
  const rpcErr = (m, code = -32000) => Object.assign(new Error(m), { rpcCode: code });
  const fee = t => t.maxFeePerGas ?? t.gasPrice;
  const tipOf = t => t.maxPriorityFeePerGas ?? t.gasPrice;
  c.mine = () => {            // mine, per sender in nonce order, every pool transaction whose max fee covers the base fee
    for (const from of new Set([...c.pool.values()].map(t => t.from))) {
      for (;;) {
        const t = poolOf(from).find(x => x.nonce === nonceOf(from)); if (!t || fee(t) < c.baseFee) break;
        const eff = t.maxFeePerGas !== undefined ? (c.baseFee + tipOf(t) < t.maxFeePerGas ? c.baseFee + tipOf(t) : t.maxFeePerGas) : t.gasPrice;
        c.pool.delete(t.hash); c.latest.set(from, t.nonce + 1); c.block++; c.mined.set(t.hash, { ...t, eff, block: c.block, ok: true });
      }
    }
  };
  setInterval(() => { if (c.mining) c.mine(); }, 100).unref();
  const eth = (words) => "0x" + words;
  c.rpc = async (method, p = []) => {
    c.calls[method] = (c.calls[method] || 0) + 1;
    switch (method) {
      case "eth_chainId": return hx(CC.id);
      case "eth_blockNumber": return hx(c.block);
      case "eth_getBlockByNumber": return { number: hx(c.block), hash: "0x" + "bb".repeat(32), parentHash: "0x" + "aa".repeat(32), timestamp: hx(Math.floor(Date.now() / 1000)), baseFeePerGas: hx(c.baseFee), gasLimit: hx(30_000_000), gasUsed: "0x0", transactions: [], miner: "0x" + "00".repeat(20), nonce: "0x0000000000000000", difficulty: "0x0", totalDifficulty: "0x0", extraData: "0x", sha3Uncles: "0x" + "00".repeat(32), logsBloom: "0x" + "00".repeat(256), stateRoot: "0x" + "00".repeat(32), receiptsRoot: "0x" + "00".repeat(32), transactionsRoot: "0x" + "00".repeat(32), size: "0x1", uncles: [] };
      case "eth_maxPriorityFeePerGas": return hx(c.tip);
      case "eth_gasPrice": return hx(c.baseFee + c.tip);
      case "eth_getBalance": return hx(10n ** 18n);
      case "eth_getCode": return "0x";
      case "eth_estimateGas": return hx(150_000);
      case "eth_getTransactionCount": return hx(p[1] === "pending" ? pendingOf(p[0]) : nonceOf(p[0]));
      case "eth_call": {
        const data = p[0].data || p[0].input, sel = data.slice(0, 10);
        if (sel === "0x70a08231") return "0x" + (10n ** 12n).toString(16).padStart(64, "0");   // balanceOf
        if (sel === "0xe94a0102") return "0x" + "0".repeat(64);                                                                 // authorizationState: unused
        const d = decodeFunctionData({ abi: parseAbi(["function paymentNonce(address token, address stealthAddress, bytes ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient) view returns (bytes32)"]), data });
        const [token, stealth, eph, tag, f, feeTo] = d.args;
        return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "bytes1" }, { type: "uint256" }, { type: "address" }],
          [keccak256(toHex("StealthPay.payWithAuthorization")), BigInt(CC.id), SP, token, stealth, keccak256(eph), tag, f, feeTo]));
      }
      case "eth_sendRawTransaction": {
        const raw = p[0]; c.sends.push(raw); const t = parseTransaction(raw), hash = keccak256(raw), from = key(await recoverTransactionAddress({ serializedTransaction: raw }));
        if (c.hangSend) await new Promise(() => {});
        if (t.nonce < nonceOf(from)) throw rpcErr("nonce too low");
        if (c.pool.has(hash)) throw rpcErr("already known");
        const old = poolOf(from).find(x => x.nonce === t.nonce);
        if (old && !(fee(t) * 100n >= fee(old) * 110n && tipOf(t) * 100n >= tipOf(old) * 110n)) throw rpcErr("replacement transaction underpriced");
        if (old) c.pool.delete(old.hash);
        c.pool.set(hash, { hash, from, nonce: t.nonce, to: key(t.to), input: t.data || "0x", gas: t.gas, value: t.value || 0n, maxFeePerGas: t.maxFeePerGas, maxPriorityFeePerGas: t.maxPriorityFeePerGas, gasPrice: t.gasPrice, type: t.type, t: Date.now() });
        if (c.mining) c.mine();
        return hash;
      }
      case "eth_getTransactionByHash": {
        const t = c.pool.get(p[0]) || c.mined.get(p[0]); if (!t) return null;
        return { hash: t.hash, from: t.from, to: t.to, nonce: hx(t.nonce), gas: hx(t.gas), value: hx(t.value), input: c.hideInput ? "0x" : t.input, type: t.type === "legacy" ? "0x0" : "0x2", chainId: hx(CC.id), ...(t.maxFeePerGas !== undefined ? { maxFeePerGas: hx(t.maxFeePerGas), maxPriorityFeePerGas: hx(t.maxPriorityFeePerGas) } : { gasPrice: hx(t.gasPrice) }),
          blockNumber: c.mined.has(p[0]) ? hx(t.block) : null, blockHash: c.mined.has(p[0]) ? "0x" + "bb".repeat(32) : null, transactionIndex: c.mined.has(p[0]) ? "0x0" : null, v: "0x1", r: "0x1", s: "0x1", yParity: "0x1" };
      }
      case "eth_getTransactionReceipt": {
        const t = c.mined.get(p[0]); if (!t) return null;
        return { transactionHash: t.hash, status: "0x1", gasUsed: hx(150_000), cumulativeGasUsed: hx(150_000), effectiveGasPrice: hx(t.eff), blockNumber: hx(t.block), blockHash: "0x" + "bb".repeat(32), transactionIndex: "0x0", from: t.from, to: t.to, logs: [], logsBloom: "0x" + "00".repeat(256), type: "0x2", contractAddress: null };
      }
      default: throw rpcErr("method not supported by the fake node: " + method, -32601);
    }
  };
  c.srv = http.createServer((q, s) => { let b = ""; q.on("data", d => b += d); q.on("end", async () => {
    const one = async j => { try { return { jsonrpc: "2.0", id: j.id, result: await c.rpc(j.method, j.params) }; } catch (e) { return { jsonrpc: "2.0", id: j.id, error: { code: e.rpcCode || -32000, message: e.message } }; } };
    const j = JSON.parse(b); const out = Array.isArray(j) ? await Promise.all(j.map(one)) : await one(j); s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify(out)); }); });
  c.listen = () => new Promise(r => c.srv.listen(0, "127.0.0.1", () => { c.url = "http://127.0.0.1:" + c.srv.address().port; r(); }));
  c.nonceOf = nonceOf; c.pendingOf = pendingOf; c.poolOf = poolOf;
  return c;
}

// ---------------------------------------------------------------- child (the relayer under test)
const RECEIVE = { ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
async function payBody(R, amount = 2_000_000n, fee = 50_000n) {
  const payer = privateKeyToAccount(generatePrivateKey()), stealth = privateKeyToAccount(generatePrivateKey()).address, eph = "0x02" + "11".repeat(32), tag = "0x12", feeTo = R.account.address;
  const nonce = R.localPaymentNonce(TOKEN, stealth, eph, tag, fee, feeTo), vb = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const sig = parseSignature(await payer.signTypedData({ domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: RECEIVE, primaryType: "ReceiveWithAuthorization",
    message: { from: payer.address, to: SP, value: amount, validAfter: 0n, validBefore: vb, nonce } }));
  return { token: TOKEN, amount: String(amount), stealth, eph, viewTag: tag, fee: String(fee), feeRecipient: feeTo, auth: { from: payer.address, validAfter: "0", validBefore: String(vb), v: Number(sig.v ?? 27 + sig.yParity), r: sig.r, s: sig.s } };
}
async function child() {
  const mode = process.env.CHILD_MODE, R = await import("./relayer.mjs"), say = (k, v) => console.log("T:" + k + " " + JSON.stringify(v, (_, x) => typeof x === "bigint" ? x.toString() : x));
  if (mode === "pay") { try { say("hash", await R.relayPay(await payBody(R), "1.1.1.1", {})); } catch (e) { say("error", { name: e.name, message: e.message }); } }
  if (mode === "restart") say("reattached", R.reattachAll());
  if (mode === "wedge") { for (let i = 0; i < Number(process.env.WEDGE_CALLS || 4); i++) { say("unwedge", await R.unwedge().catch(e => "err " + e.message)); await sleep(Number(process.env.WEDGE_EVERY_MS || 700)); } }
  if (mode === "feepair") {
    const stealth = privateKeyToAccount(generatePrivateKey()), to = privateKeyToAccount(generatePrivateKey()).address, vb = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const T = { TransferWithAuthorization: RECEIVE.ReceiveWithAuthorization };
    const mk = async (dst, value, nonce) => { const m = { from: stealth.address, to: dst, value, validAfter: 0n, validBefore: vb, nonce }, sg = parseSignature(await stealth.signTypedData({ domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: T, primaryType: "TransferWithAuthorization", message: m }));
      return { value: String(value), validAfter: "0", validBefore: String(vb), nonce, v: Number(sg.v ?? 27 + sg.yParity), r: sg.r, s: sg.s }; };
    const body = { from: stealth.address, to, ...(await mk(to, 2_000_000n, "0x" + "01".repeat(32))), feeAuth: await mk(R.account.address, 50_000n, "0x" + "02".repeat(32)) };
    say("start", 1); try { say("hash", await R.relay(body, "1.1.1.1", {})); } catch (e) { say("error", { name: e.name, message: e.message }); }
  }
  if (process.env.LINGER_MS) await sleep(Number(process.env.LINGER_MS));
  process.exit(0);
}
if (process.argv[2] === "child") { await child(); }

// ---------------------------------------------------------------- parent
const rows = []; let fails = 0;
const ok = (name, pass, extra = "") => { rows.push(pass); if (!pass) fails++; console.log((pass ? "PASS " : "FAIL ") + name + (!pass && extra ? "   <-- " + extra : "")); };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-recovery-")), procs = [];
process.on("exit", () => { for (const p of procs) try { p.kill("SIGKILL"); } catch {} try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} });
const KEY = generatePrivateKey(), RELAYER = privateKeyToAccount(KEY).address;
let seq = 0;
function env(node, name, extra = {}) {
  const dir = path.join(tmp, name); fs.mkdirSync(dir, { recursive: true });
  return { dir, state: path.join(dir, "state.json"), log: path.join(dir, "r.log"), env: { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: node.url, STEALTHPAY: SP, RELAYER_KEY: KEY, STEALTH_RELAY_STATE: path.join(dir, "state.json"), STEALTH_RELAY_LOG: path.join(dir, "r.log"),
    STEALTH_RELAY_PAY_FEE_MIN: "50000", STEALTH_RELAY_PAY_FEE: "50000", STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", STEALTH_RELAY_MAX_FEE_WEI: "1000000000000", STEALTH_RELAY_STUCK_S: "1", STEALTH_RELAY_POLL_GAP_MS: "100", STEALTH_RELAY_GONE_GAP_MS: "200",
    STEALTH_RELAY_GAP_GRACE_MS: "0", STEALTH_RELAY_BUMP_PCT: "30", ...extra } };
}
function run(e, mode, extra = {}) {            // child process, async: the parent keeps serving the fake node
  const p = spawn("nice", ["-n", "10", "node", ME, "child"], { env: { ...e.env, CHILD_MODE: mode, ...extra }, stdio: ["ignore", "pipe", "pipe"] }); procs.push(p);
  const h = { p, out: "", err: "", exit: new Promise(r => p.on("exit", (code) => r(code))) };
  p.stdout.on("data", d => h.out += d); p.stderr.on("data", d => h.err += d);
  h.get = k => { const m = new RegExp("^T:" + k + " (.*)$", "m").exec(h.out); return m ? JSON.parse(m[1]) : undefined; };
  h.wait = async (k, ms = 20000) => { for (const t0 = Date.now(); Date.now() - t0 < ms; await sleep(50)) { const v = h.get(k); if (v !== undefined) return v; } return undefined; };
  return h;
}
const waitFor = async (f, ms = 20000) => { for (const t0 = Date.now(); Date.now() - t0 < ms; await sleep(50)) { try { const v = await f(); if (v) return v; } catch {} } return false; };
const stateOf = e => { try { return JSON.parse(fs.readFileSync(e.state, "utf8")); } catch { return null; } };
const logOf = e => { try { return fs.readFileSync(e.log, "utf8"); } catch { return ""; } };
const priceOf = t => t.maxFeePerGas ?? t.gasPrice;

// ---- M-1 (1): the replacement is priced from the MARKET, not from the stuck transaction
{ const node = makeNode(); await node.listen(); const e = env(node, "m1a", { STEALTH_RELAY_MAX_REPLACE: "3" });
  const c = run(e, "pay", { LINGER_MS: "20000" }); const hash = (await c.wait("hash"))?.hash;
  const p0 = node.poolOf(RELAYER)[0], price0 = p0 && priceOf(p0);
  node.baseFee = 5n * GWEI; node.tip = GWEI / 2n;                       // the fee market moved up 5x after signing
  const rep = await waitFor(() => node.poolOf(RELAYER).find(t => t.hash !== hash && t.nonce === p0.nonce));
  const market = 5n * GWEI * 12n / 10n + GWEI / 2n;                   // viem: baseFee x 1.2 + tip
  ok("M-1 a send is accepted by the node and stays pending", !!hash && !!p0 && node.nonceOf(RELAYER) === 0);
  ok("M-1 the replacement is priced from the CURRENT market (>= market x 1.3), far above the stuck price x 1.3", !!rep && priceOf(rep) >= market * 13n / 10n && priceOf(rep) > price0 * 13n / 10n * 2n, rep ? `${priceOf(rep)} vs market ${market} stuck ${price0}` : "no replacement");
  ok("M-1 same payload, same nonce, higher tip", !!rep && rep.input === p0.input && rep.maxPriorityFeePerGas > p0.maxPriorityFeePerGas);
  node.mining = true;
  ok("M-1 the replacement is mined and the day's gas is reconciled to the real cost", await waitFor(() => stateOf(e) && stateOf(e).unsure.length === 0 && stateOf(e).gas === String(150_000n * [...node.mined.values()][0].eff), 15000), JSON.stringify(stateOf(e)).slice(0, 200));
  c.p.kill("SIGKILL"); node.srv.close(); }

// ---- M-1 (2): bounded retries, each one a higher bid; then the watcher gives up (the periodic check takes over)
{ const node = makeNode(); await node.listen(); const e = env(node, "m1b", { STEALTH_RELAY_MAX_REPLACE: "3", STEALTH_RELAY_WEDGE_S: "100000" });
  const c = run(e, "pay", { LINGER_MS: "30000" }); const hash = (await c.wait("hash"))?.hash;
  await waitFor(() => /ALERT receipt wait failed pay .*still unconfirmed/.test(logOf(e)), 25000);
  const reps = (logOf(e).match(/ replacement pay /g) || []).length, sends = node.sends.length;
  ok("M-1 exactly MAX_REPLACE (3) replacements, then the watcher stops and alerts", !!hash && reps === 3 && sends === 4, `replacements ${reps} sends ${sends}`);
  const prices = node.sends.map(r => priceOf(parseTransaction(r)));
  ok("M-1 every replacement bids more than the previous one", prices.every((x, i) => i === 0 || x > prices[i - 1]), prices.join());
  c.p.kill("SIGKILL"); node.srv.close(); }

// ---- M-1 (3): restart. The process dies with a send pending; the next one re-attaches, replaces at the market fee, and reconciles the reserve it read from the state file
{ const node = makeNode(); await node.listen(); const e = env(node, "m1c");
  const a = run(e, "pay", { LINGER_MS: "60000" }); const hash = (await a.wait("hash"))?.hash; await waitFor(() => { const s = stateOf(e); return s && s.unsure.length === 1 && s.unsure[0][1].rsv; });
  const rec = stateOf(e).unsure[0][1]; a.p.kill("SIGKILL"); await a.exit;
  ok("M-1 the persisted unsure record carries the reserve, its day and the counter", /^\d+$/.test(rec.rsv) && Number.isInteger(rec.d) && rec.chg && rec.chg[0] === "perPayer", JSON.stringify(rec));
  node.baseFee = 4n * GWEI;
  const b = run(e, "restart", { LINGER_MS: "30000" });
  ok("M-1 the new process re-attaches one watcher (stale lock of the dead pid is taken over)", (await b.wait("reattached")) === 1, b.err.slice(-200));
  const rep = await waitFor(() => node.poolOf(RELAYER).find(t => t.hash !== hash));
  ok("M-1 after the restart the stuck send is replaced at the new market fee", !!rep && priceOf(rep) >= (4n * GWEI * 12n / 10n + GWEI / 10n) * 13n / 10n, rep ? String(priceOf(rep)) : "none");
  node.mining = true;
  const done = await waitFor(() => { const s = stateOf(e); return s && s.unsure.length === 0 && s.gas === String(150_000n * [...node.mined.values()][0].eff); }, 15000);
  ok("M-1 reserve reconciled after the restart: the day's gas equals the real cost, the unsure record is gone", !!done, JSON.stringify(stateOf(e)).slice(0, 250));
  b.p.kill("SIGKILL"); node.srv.close(); }

// ---- M-1 (4): periodic check, transaction in the pool and recorded: re-sent at the market fee with the same payload
{ const node = makeNode(); await node.listen(); const e = env(node, "m1d", { STEALTH_RELAY_WEDGE_S: "1", STEALTH_RELAY_MAX_REPLACE: "1" });
  const a = run(e, "pay", { LINGER_MS: "60000" }); const hash = (await a.wait("hash"))?.hash; await waitFor(() => stateOf(e)?.unsure.length === 1);
  const p0 = node.poolOf(RELAYER)[0]; a.p.kill("SIGKILL"); await a.exit; node.baseFee = 4n * GWEI;
  const b = run(e, "wedge", { LINGER_MS: "5000", WEDGE_CALLS: "5", WEDGE_EVERY_MS: "600" });       // no re-attach: only the periodic check sees it
  const rep = await waitFor(() => node.poolOf(RELAYER).find(t => t.hash !== hash));
  ok("M-1 the periodic check re-sends the stuck pool transaction (same payload) at the market fee", !!rep && rep.input === p0.input && priceOf(rep) >= (4n * GWEI * 12n / 10n) * 13n / 10n, rep ? String(priceOf(rep)) : "none");
  ok("M-1 it logs the wedge ALERT", /ALERT wedged nonce 0 /.test(logOf(e)));
  node.mining = true; await waitFor(() => node.nonceOf(RELAYER) === 1, 10000); await b.exit;
  ok("M-1 the nonce is free again", node.nonceOf(RELAYER) === 1);
  node.srv.close(); }

// ---- M-1 (5): a pending nonce we know nothing about (another process on the same key) is replaced by a self-transfer at the market fee
{ const node = makeNode(); await node.listen(); const e = env(node, "m1e", { STEALTH_RELAY_WEDGE_S: "1" });
  const acct = privateKeyToAccount(KEY), ser = await acct.signTransaction({ chainId: CC.id, nonce: 0, gas: 21000n, to: acct.address, value: 0n, type: "eip1559", maxFeePerGas: GWEI * 11n / 10n, maxPriorityFeePerGas: GWEI / 100n });
  await node.rpc("eth_sendRawTransaction", [ser]); node.baseFee = 3n * GWEI;
  const b = run(e, "wedge", { LINGER_MS: "500", WEDGE_CALLS: "6", WEDGE_EVERY_MS: "600" });
  const fill = await waitFor(() => node.poolOf(RELAYER).find(t => t.to === key(RELAYER) && priceOf(t) > GWEI * 11n / 10n));
  ok("M-1 unknown pending nonce: replaced by a self-transfer at >= market x 1.3", !!fill && fill.input === "0x" && priceOf(fill) >= (3n * GWEI * 12n / 10n + GWEI / 10n) * 13n / 10n, fill ? String(priceOf(fill)) : "none");
  node.mining = true; await b.exit;
  const s = stateOf(e);
  ok("M-1/L-2 the fill is charged to the day's gas (21000 x its max fee)", node.nonceOf(RELAYER) === 1 && !!s && s.gas === String(21000n * priceOf(fill)), JSON.stringify(s && s.gas));
  node.srv.close(); }

// ---- L-2: hard fee ceiling
{ const node = makeNode(); await node.listen(); node.baseFee = 100n * GWEI;
  const e = env(node, "l2a", { STEALTH_RELAY_MAX_FEE_WEI: String(10n * GWEI) });
  const c = run(e, "pay", { LINGER_MS: "300" }); const err = await c.wait("error"); await c.exit;
  ok("L-2 market fee above the ceiling: nothing is signed or sent, Upstream (503) and no gas charged", err && err.name === "Upstream" && node.sends.length === 0 && (stateOf(e)?.gas ?? "0") === "0", JSON.stringify(err) + " sends " + node.sends.length);
  ok("L-2 the ceiling raises an ALERT line the watchdog knows", /ALERT fee ceiling exceeded: market/.test(logOf(e)));
  node.srv.close(); }
{ const node = makeNode(); await node.listen();
  const ceilDefault = (b) => { const r = spawnSync("node", ["--input-type=module", "-e", `process.env.RELAYER_KEY="${KEY}"; process.env.STEALTH_RELAY_STATE="${path.join(tmp, "cd" + b + ".json")}"; process.env.STEALTH_RELAY_LOG="${path.join(tmp, "cd.log")}"; const R = await import("${"file://" + path.join(HERE, "relayer.mjs")}"); console.log("ok")`], { encoding: "utf8", env: { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: node.url, STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "50000", STEALTH_RELAY_GAS_BUDGET_WEI: b, STEALTH_RELAY_MAX_FEE_WEI: "" } }); return r; };
  const src = fs.readFileSync(path.join(HERE, "relayer.mjs"), "utf8");
  ok("L-2 default ceiling = budget / 4 / 250000 (Base 0.0002 ETH -> 0.2 gwei, RH 0.01 ETH -> 10 gwei)", /GAS_BUDGET_WEI_PER_DAY \/ CEIL_DAY_SHARE \/ CEIL_REF_GAS/.test(src) && 200000000000000n / 4n / 250000n === 200_000_000n && 10000000000000000n / 4n / 250000n === 10n * GWEI);
  ok("L-2 a budget too small for a non-zero ceiling stops the start", ceilDefault("1000").status === 1 && /fee ceiling is 0/.test(ceilDefault("1000").stderr));
  node.srv.close(); }
{ // replacement refused by the daily budget (charged, not free), and the reserve is left untouched
  const node = makeNode(); await node.listen();
  const e = env(node, "l2b", { STEALTH_RELAY_GAS_BUDGET_WEI: "300000000000000", STEALTH_RELAY_MAX_REPLACE: "2" });
  const c = run(e, "pay", { LINGER_MS: "12000" }); const hash = (await c.wait("hash"))?.hash, err = !hash && (await c.wait("error"));
  node.baseFee = 6n * GWEI;
  await waitFor(() => /ALERT stuck transaction not replaced: gas budget/.test(logOf(e)), 15000);
  ok("L-2 a replacement that would take the day past the budget is refused (nothing re-sent, ALERT)", !!hash && node.sends.length === 1 && /ALERT stuck transaction not replaced: gas budget/.test(logOf(e)), JSON.stringify(err) + " sends " + node.sends.length + " " + logOf(e).slice(-300));
  c.p.kill("SIGKILL"); node.srv.close(); }

// ---- L-1: the collected-fee marker is durable together with the unsure record, BEFORE the fee is sent
{ const node = makeNode(); await node.listen(); node.hangSend = true;
  const idx = http.createServer((q, s) => { s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify({ known: true })); }); await new Promise(r => idx.listen(0, "127.0.0.1", r));
  const e = env(node, "l1", { STEALTH_RELAY_FEE_MIN: "50000", STEALTH_INDEXER: "http://127.0.0.1:" + idx.address().port, STEALTH_RELAY_LOCK_MS: "60000" });
  const c = run(e, "feepair", { LINGER_MS: "60000" });
  const s = await waitFor(() => { const j = stateOf(e); return j && j.unsure.length && j; }, 15000);
  ok("L-1 with the fee send still on the wire, the state file already holds the unsure record AND the feePaid marker for the same hash", !!s && s.feePaid.length === 1 && s.unsure.length === 1 && s.feePaid[0][1].h === s.unsure[0][1].h && s.feePaid[0][0] === s.unsure[0][0],
    JSON.stringify(s && { u: s.unsure.length, f: s.feePaid.length }));
  c.p.kill("SIGKILL"); await c.exit;
  idx.close(); node.srv.close(); }
{ const node = makeNode(); await node.listen(); 
  const idx = http.createServer((q, s) => { s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify({ known: true })); }); await new Promise(r => idx.listen(0, "127.0.0.1", r));
  const refuse = node.rpc; node.rpc = async (m, p) => { if (m === "eth_sendRawTransaction") throw Object.assign(new Error("insufficient funds for gas * price + value"), { rpcCode: -32000 }); return refuse(m, p); };
  const e = env(node, "l1b", { STEALTH_RELAY_FEE_MIN: "50000", STEALTH_INDEXER: "http://127.0.0.1:" + idx.address().port });
  const c = run(e, "feepair", { LINGER_MS: "800" }); await c.wait("error"); await c.exit; const s = stateOf(e);
  ok("L-1 a fee send refused outright by the node takes its marker back (nothing collected)", !!s && s.feePaid.length === 0 && s.unsure.length === 0, JSON.stringify(s && { u: s.unsure.length, f: s.feePaid.length }));
  idx.close(); node.srv.close(); }

// ---- L-3: start-up refusals
{ const base = { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: "http://127.0.0.1:1", RELAYER_KEY: KEY, STEALTH_RELAY_LOG: path.join(tmp, "l3.log") };
  const go = (extra, name) => spawnSync("node", ["--input-type=module", "-e", `await import("file://${path.join(HERE, "relayer.mjs")}"); console.log("started")`], { encoding: "utf8", timeout: 20000, env: { ...base, STEALTH_RELAY_STATE: path.join(tmp, name + ".json"), ...extra } });
  const a = go({ STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "0" }, "l3a"), b = go({ STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "50000" }, "l3b"), c = go({ STEALTH_RELAY_PAY_FEE_MIN: "0" }, "l3c");
  ok("L-3 pay enabled and PAY_FEE_MIN=0: refuses to start (exit 1, clear message)", a.status === 1 && /PAY_FEE_MIN must be above 0/.test(a.stderr), a.stderr.slice(0, 160));
  ok("L-3 pay enabled with the product value ($0.05 = 50000): starts", b.status === 0 && /started/.test(b.stdout), b.stderr.slice(0, 160));
  ok("L-3 pay disabled (no STEALTHPAY): a zero pay floor is irrelevant, starts", c.status === 0);
  const d = go({ STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "50000", STEALTH_RELAY_REQUIRE_WITHDRAW_FEE: "1" }, "l3d"), f = go({ STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "50000", STEALTH_RELAY_REQUIRE_WITHDRAW_FEE: "1", STEALTH_RELAY_FEE_MIN: "50000" }, "l3f");
  ok("L-3 REQUIRE_WITHDRAW_FEE=1 with FEE_MIN=0 refuses; with a fee floor it starts; default (unset) leaves the withdraw fee off", d.status === 1 && /REQUIRE_WITHDRAW_FEE/.test(d.stderr) && f.status === 0); }

// ---- I-3: lock file
{ const base = { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: "http://127.0.0.1:1", RELAYER_KEY: KEY, STEALTH_RELAY_LOG: path.join(tmp, "i3.log"), STEALTH_RELAY_STATE: path.join(tmp, "i3.json"), STEALTHPAY: SP, STEALTH_RELAY_PAY_FEE_MIN: "50000" };
  const code = `await import("file://${path.join(HERE, "relayer.mjs")}"); console.log("started"); await new Promise(r => setTimeout(r, 4000));`;
  const first = spawn("node", ["--input-type=module", "-e", code], { env: base, stdio: ["ignore", "pipe", "pipe"] }); procs.push(first); let o1 = ""; first.stdout.on("data", d => o1 += d);
  await waitFor(() => /started/.test(o1), 10000);
  const second = spawnSync("node", ["--input-type=module", "-e", `await import("file://${path.join(HERE, "relayer.mjs")}"); console.log("started")`], { encoding: "utf8", timeout: 20000, env: base });
  ok("I-3 a second process on the same state file refuses to start while the first lives", second.status === 1 && /another relayer process holds/.test(second.stderr) && !/started/.test(second.stdout), second.stderr.slice(0, 160));
  first.kill("SIGKILL"); await new Promise(r => first.on("exit", r));
  ok("I-3 the SIGKILLed first process leaves a stale lock file", fs.existsSync(path.join(tmp, "i3.json.lock")));
  const third = spawnSync("node", ["--input-type=module", "-e", `await import("file://${path.join(HERE, "relayer.mjs")}"); console.log("started")`], { encoding: "utf8", timeout: 20000, env: base });
  ok("I-3 a stale lock of a dead pid is taken over", third.status === 0 && /started/.test(third.stdout), third.stderr.slice(0, 160));
  ok("I-3 a clean exit removes the lock", !fs.existsSync(path.join(tmp, "i3.json.lock"))); }

// ---- M-2: client address
{ ok("M-2 clientIp: a client-sent X-Forwarded-For ahead of nginx's own value is ignored (rightmost hop)", clientIp("127.0.0.1", "9.9.9.9, 1.2.3.4") === "1.2.3.4");
  ok("M-2 clientIp: nginx overwrite (one hop) -> that hop; IPv6 hop", clientIp("127.0.0.1", "1.2.3.4") === "1.2.3.4" && clientIp("::ffff:127.0.0.1", "2001:db8::1") === "2001:db8::1");
  ok("M-2 clientIp: a non-loopback peer ignores the header", clientIp("8.8.8.8", "1.2.3.4") === "8.8.8.8" && clientIp("::1", "") === "::1");
  ok("M-2 clientIp: junk in the rightmost hop gets its own bucket, never an allow-listed address", clientIp("127.0.0.1", "9.9.9.9, <script>") === "-" && clientIp("127.0.0.1", "9.9.9.9,") === "9.9.9.9");
  // end to end over HTTP: allow-listed 9.9.9.9; a spoofed leftmost value must not be treated as allow-listed
  const node = makeNode(); await node.listen(); const e = env(node, "m2", { STEALTH_RELAY_ALLOW_KEYS: "9.9.9.9", STEALTH_RELAY_PORT: String(39000 + Math.floor(Math.random() * 900)) });
  const srv = spawn("node", [path.join(HERE, "relayer.mjs")], { env: e.env, stdio: "ignore" }); procs.push(srv); await sleep(1500);
  const post = (xff) => fetch("http://127.0.0.1:" + e.env.STEALTH_RELAY_PORT + "/stealth-api/relay", { method: "POST", headers: xff ? { "x-forwarded-for": xff } : {}, body: "{}" }).then(r => r.status);
  await post("9.9.9.9, 1.2.3.4"); await post("6.6.6.6, 9.9.9.9"); await post("1.2.3.4"); const spoof = (logOf(e).match(/allow-listed request/g) || []).length;
  await post("9.9.9.9"); const real = (logOf(e).match(/allow-listed request/g) || []).length;
  ok("M-2 over HTTP: 'X-Forwarded-For: <allow-listed>, <real>' and a plain real address are NOT allow-listed; only nginx's single overwritten value 9.9.9.9 is (nginx setting it is the allow-list)", spoof === 1 && real === 2, `spoof ${spoof} real ${real}`);
  // a header sent by a client straight to the relayer's loopback port is the proxy's job to overwrite; the documented configs do
  const conf = ["deploy/stealth-rh.conf", "deploy/stealth-base.conf"].map(f => fs.readFileSync(path.join(HERE, f), "utf8").replace(/^#.*$/gm, ""));
  const relayerBlocks = c => c.split(/\nlocation /).filter(b => /127\.0\.0\.1:38(84|94)/.test(b));
  ok("M-2 every relayer location in both nginx configs sets X-Forwarded-For to $remote_addr and none appends", conf.every(c => relayerBlocks(c).length === 3 && relayerBlocks(c).every(b => /proxy_set_header X-Forwarded-For \$remote_addr;/.test(b)) && !/proxy_add_x_forwarded_for/.test(c)));
  ok("M-2 the allow-listed address is not in the repo's docs or configs", spawnSync("grep", ["-rlE", "195\\.201\\.164\\.", HERE, "--exclude-dir=node_modules", "--exclude=test_relayer_recovery.mjs"], { encoding: "utf8" }).stdout.trim() === "");
  srv.kill("SIGKILL"); node.srv.close(); }

console.log(fails ? "\nFAILED " + fails + " of " + rows.length : "\nALL PASS " + rows.length); process.exit(fails ? 1 : 0);
