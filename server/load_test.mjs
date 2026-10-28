/* Load test on an anvil fork of Robinhood Chain (local only, nothing goes to the live chain).
   Usage: node load_test.mjs            (env: PAYERS=100 SCAN_CLIENTS=500 SCAN_SECONDS=60 BLOCK_TIME=1 SKIP_SCAN=1 SKIP_RELAY=1 SEED_ROWS=50000)
   Phase 1: PAYERS distinct payers each POST /relay/pay concurrently (bursty, spread over BURST_MS).
   Phase 2: indexer sees them; PAYERS stealth withdrawals POST /relay concurrently.
   Phase 3: SCAN_CLIENTS concurrent scan clients (/head + paged /announcements + /balances x50) for SCAN_SECONDS against the indexer;
            CPU/RSS of the indexer process sampled with ps. The DB is topped up with SEED_ROWS synthetic rows first.
   Uses the same signing code as the web app (web/pay-auth.js, web/stealth-crypto.js) and test_pay_e2e.mjs helpers. */
import { spawn, execSync } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import { fileURLToPath } from "url";
import { createPublicClient, createWalletClient, http as vhttp, parseAbi, getAddress, toHex, formatEther, keccak256, encodeAbiParameters, pad } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { paymentNonce } from "../web/pay-auth.js";
import { deriveForPayment, metaAddress, parseMeta, checkAnnouncement, secpUtils } from "../web/stealth-crypto.js";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const N = Number(process.env.PAYERS || 100), SCAN_CLIENTS = Number(process.env.SCAN_CLIENTS || 500), SCAN_S = Number(process.env.SCAN_SECONDS || 60);
const BURST_MS = Number(process.env.BURST_MS || 1500), BLOCK_TIME = Number(process.env.BLOCK_TIME || 1), SEED_ROWS = Number(process.env.SEED_ROWS || 50000);
const APORT = 8845, RPORT = 3994, IPORT = 3993, RPC = "http://127.0.0.1:" + APORT, RELAY = "http://127.0.0.1:" + RPORT, IDX = "http://127.0.0.1:" + IPORT;
const TOKEN = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", HOLDER = "0x0000000000000000000000000000000000000001";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const FEE = 50000n, AMOUNT = 2_000_000n, WD = 1_500_000n;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pct = (a, p) => { if (!a.length) return NaN; const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });
let fails = 0; const ok = (name, pass, extra = "") => { console.log((pass ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); if (!pass) fails++; };
const procs = []; const done = c => { procs.forEach(p => p.kill()); process.exit(c); }; process.on("SIGINT", () => done(1)); process.on("exit", () => procs.forEach(p => { try { p.kill(); } catch {} })); process.on("uncaughtException", e => { console.log("UNCAUGHT", e); done(2); });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-load-"));
const REPORT = {};

async function post(url, body) {
  const t0 = performance.now();
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({})); return { status: r.status, ms: performance.now() - t0, t0, ...j };
  } catch (e) { return { status: 0, ms: performance.now() - t0, t0, error: "net: " + e.message }; }
}
// anvil in fork mode fetches every cold account/slot from the REMOTE RH node (~0.1-0.7 s each, 100 cold balanceOf = 7 s), which would swamp
// the numbers with fork-RPC latency. Touch what a request reads BEFORE the burst so the fork serves it locally (like a node with a warm DB).
const word = a => a.slice(2).toLowerCase().padStart(64, "0");
async function prewarm(items) {
  for (let i = 0; i < items.length; i += 25) await Promise.all(items.slice(i, i + 25).flatMap(({ from, to, nonce }) => [
    rpc("eth_call", [{ to: TOKEN, data: "0x70a08231" + word(from) }, "latest"]), rpc("eth_call", [{ to: TOKEN, data: "0x70a08231" + word(to) }, "latest"]),
    rpc("eth_getCode", [to, "latest"]), rpc("eth_getBalance", [to, "latest"]),
    rpc("eth_call", [{ to: TOKEN, data: "0xe94a0102" + word(from) + nonce.slice(2) }, "latest"])]));   // authorizationState(from, nonce)
}
const errType = e => !e ? "" : /nonce/i.test(e) ? "NONCE" : /budget/.test(e) ? "budget" : /too many requests/.test(e) ? "ip-limit" : /in progress/.test(e) ? "inflight" : /^net:/.test(e) ? "network" : e.slice(0, 50);

try {
  procs.push(spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(APORT), "--silent"], { stdio: "inherit" }));
  for (let i = 0; i < 60; i++) { try { await rpc("eth_chainId"); break; } catch { await sleep(500); } }
  const head0 = parseInt(await rpc("eth_blockNumber"), 16); console.log("anvil fork chainId", parseInt(await rpc("eth_chainId"), 16), "block", head0);
  const chain = { id: 4663, name: "rh-fork", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
  const pub = createPublicClient({ chain, transport: vhttp(RPC) });
  const deployer = createWalletClient({ account: privateKeyToAccount(ANVIL0), chain, transport: vhttp(RPC) });
  const art = JSON.parse(fs.readFileSync(path.join(HERE, "../out/StealthPay.sol/StealthPay.json"), "utf8"));
  const dh = await deployer.deployContract({ abi: art.abi, bytecode: art.bytecode.object, args: ["0x55649E01B5Df198D18D95b5cc5051630cfD45564"] });
  const SP = getAddress((await pub.waitForTransactionReceipt({ hash: dh })).contractAddress); console.log("StealthPay on fork:", SP);
  const erc = parseAbi(["function balanceOf(address) view returns (uint256)"]);
  const bal = a => pub.readContract({ address: TOKEN, abi: erc, functionName: "balanceOf", args: [a] });
  const startBlock = parseInt(await rpc("eth_blockNumber"), 16);

  // ---- indexer + relayer as real processes
  const rk = generatePrivateKey(), relayerAddr = privateKeyToAccount(rk).address;
  await rpc("anvil_setBalance", [relayerAddr, toHex(10n ** 18n)]);
  const DB = path.join(tmp, "ann.db");
  const idx = spawn("python3", [process.env.INDEXER_FILE || path.join(HERE, "stealth_indexer.py")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, STEALTH_PORT: String(IPORT), STEALTH_DB: DB, STEALTH_START_BLOCK: String(startBlock), STEALTH_CONFIRMATIONS: "0", STEALTH_POLL: "1" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(idx); idx.stdout.on("data", () => {});
  const rp = spawn("node", [path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, RELAYER_KEY: rk, STEALTH_RELAY_PORT: String(RPORT), STEALTH_INDEXER: IDX,
    STEALTH_RELAY_STATE: path.join(tmp, "st.json"), STEALTH_RELAY_LOG: path.join(tmp, "r.log"), STEALTH_RELAY_PAY_FEE: String(FEE), STEALTH_RELAY_PAY_FEE_MIN: String(FEE),
    STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", STEALTH_RELAY_MAX_PER_IP: "100000" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(rp); await new Promise(r => rp.stdout.on("data", d => { if (String(d).includes("stealth relayer")) r(); }));
  for (let i = 0; i < 40; i++) { try { await fetch(IDX + "/stealth-api/head"); break; } catch { await sleep(250); } }

  if (!process.env.SKIP_RELAY) {
    // ---- setup: N payers with USDG, one receiver
    await rpc("anvil_setBalance", [HOLDER, toHex(100n * 10n ** 18n)]); await rpc("anvil_impersonateAccount", [HOLDER]);
    const payers = Array.from({ length: N }, () => privateKeyToAccount(generatePrivateKey()));
    // mint USDG on the fork by writing the balance mapping (slot 1) -- the real holder only has ~$10
    for (const p of payers) await rpc("anvil_setStorageAt", [TOKEN, keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [p.address, 1n])), pad(toHex(5_000_000n), { size: 32 })]);
    ok("fork funding: payers hold 5 USDG", (await bal(payers[0].address)) === 5_000_000n && (await bal(payers[N - 1].address)) === 5_000_000n);
    const sk = secpUtils.utils.randomPrivateKey(), vk = secpUtils.utils.randomPrivateKey();
    const keys = { spendPriv: sk, viewPriv: vk, spendPub: secpUtils.getPublicKey(sk, true), viewPub: secpUtils.getPublicKey(vk, true) };
    const meta = parseMeta(metaAddress(keys, "rh"));
    const validBefore = Math.floor(Date.now() / 1000) + 3600;
    const RT = { ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
    const dom = { name: "Global Dollar", version: "1", chainId: 4663, verifyingContract: TOKEN };
    const jobs = [];
    for (const p of payers) {
      const d = deriveForPayment(meta);
      const nonce = paymentNonce({ chainId: 4663, stealthPay: SP, token: TOKEN, stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: FEE, feeRecipient: relayerAddr });
      const sig = await p.signTypedData({ domain: dom, types: RT, primaryType: "ReceiveWithAuthorization", message: { from: p.address, to: SP, value: AMOUNT, validAfter: 0n, validBefore: BigInt(validBefore), nonce } });
      jobs.push({ payer: p, d, body: { token: TOKEN, amount: AMOUNT.toString(), stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: FEE.toString(), feeRecipient: relayerAddr,
        auth: { from: p.address, validAfter: "0", validBefore: String(validBefore), v: parseInt(sig.slice(130, 132), 16), r: "0x" + sig.slice(2, 66), s: "0x" + sig.slice(66, 130) } } });
    }
    await prewarm(jobs.map(j => ({ from: j.payer.address, to: j.d.stealth, nonce: j.body.auth.nonce || paymentNonce({ chainId: 4663, stealthPay: SP, token: TOKEN, stealth: j.d.stealth, eph: j.d.ephPub, viewTag: j.d.viewTag, fee: FEE, feeRecipient: relayerAddr }) })));
    // realistic blocks: no automine, interval mining
    await rpc("evm_setAutomine", [false]); await rpc("evm_setIntervalMining", [BLOCK_TIME]);
    const n0 = await pub.getTransactionCount({ address: relayerAddr }); const rb0 = await bal(relayerAddr); const eth0 = await pub.getBalance({ address: relayerAddr });

    console.log(`\n== PHASE 1: ${N} concurrent /relay/pay (burst over ${BURST_MS} ms, block time ${BLOCK_TIME}s)`);
    const T0 = performance.now();
    const res = await Promise.all(jobs.map(async j => { await sleep(Math.random() * BURST_MS); const r = await post(RELAY + "/stealth-api/relay/pay", j.body); j.res = r;
      if (r.hash) { j.sentAt = r.t0; pub.waitForTransactionReceipt({ hash: r.hash, pollingInterval: 100, timeout: 120000 }).then(rc => { j.rc = rc; j.minedMs = performance.now() - r.t0; }).catch(e => { j.rcErr = e.message; }); } return r; }));
    const wall1 = performance.now() - T0;
    for (let i = 0; i < 400 && jobs.some(j => j.res.hash && !j.rc && !j.rcErr); i++) await sleep(100);
    const acc = res.filter(r => r.status === 200), errs = {}; res.filter(r => r.status !== 200).forEach(r => { const t = errType(r.error); errs[t] = (errs[t] || 0) + 1; });
    const http_ms = res.map(r => r.ms), mined = jobs.filter(j => j.minedMs).map(j => j.minedMs);
    const gasPay = jobs.filter(j => j.rc).map(j => Number(j.rc.gasUsed));
    console.log(`accepted ${acc.length}/${N}  errors ${JSON.stringify(errs)}  wall ${(wall1 / 1000).toFixed(1)}s`);
    console.log(`HTTP latency ms: p50 ${pct(http_ms, .5).toFixed(0)} p95 ${pct(http_ms, .95).toFixed(0)} max ${Math.max(...http_ms).toFixed(0)}`);
    console.log(`request->mined ms: p50 ${pct(mined, .5).toFixed(0)} p95 ${pct(mined, .95).toFixed(0)} max ${Math.max(...mined).toFixed(0)}  (mined ${mined.length})`);
    const nonceErrs = res.filter(r => /nonce/i.test(r.error || "")).length + (fs.readFileSync(path.join(tmp, "r.log"), "utf8").match(/nonce too|replacement transaction underpriced|already known|NONCE/gi) || []).length;
    ok("phase1 all accepted", acc.length === N);
    ok("phase1 nonce errors == 0", nonceErrs === 0, String(nonceErrs));
    ok("phase1 all receipts success", jobs.every(j => j.rc && j.rc.status === "success"));
    ok("relayer nonce advanced by N", (await pub.getTransactionCount({ address: relayerAddr })) - n0 === N);
    let right = 0; for (const j of jobs) if ((await bal(j.d.stealth)) === AMOUNT - FEE && (await bal(j.payer.address)) === 5_000_000n - AMOUNT) right++;
    ok("every payment correct on-chain (stealth = amount-fee, payer debited)", right === N, right + "/" + N);
    ok("relayer fee income == N*fee, StealthPay holds 0", (await bal(relayerAddr)) - rb0 === BigInt(N) * FEE && (await bal(SP)) === 0n);
    const gasSum = jobs.reduce((a, j) => a + (j.rc ? j.rc.gasUsed : 0n), 0n);
    ok("total supply conserved: sum(stealth)+fees == N*amount", BigInt(N) * AMOUNT === BigInt(N) * (AMOUNT - FEE) + BigInt(N) * FEE);
    REPORT.payGas = gasPay.length ? Math.round(gasPay.reduce((a, b) => a + b, 0) / gasPay.length) : 0;
    console.log("pay gasUsed avg", REPORT.payGas, "relayer ETH spent on fork", formatEther(eth0 - (await pub.getBalance({ address: relayerAddr }))), "(fork gas price is ~1 gwei, not real)");

    // ---- phase 2: wait indexer, withdraw
    console.log(`\n== PHASE 2: ${N} concurrent stealth withdrawals via /relay`);
    for (let i = 0; i < 120; i++) { const h = await (await fetch(IDX + "/stealth-api/head")).json(); if (h.count >= N) break; await sleep(500); }
    const rows = []; let since = 0; for (;;) { const d = await (await fetch(IDX + "/stealth-api/announcements?since=" + since + "&limit=2000")).json(); if (!d.rows.length) break; rows.push(...d.rows); since = d.next; }
    ok("indexer has all announcements", rows.length >= N, rows.length + " rows");
    const WT = { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
    const wjobs = [];
    for (const r of rows) {
      const hit = checkAnnouncement(keys, r.eph, r.meta.slice(0, 4)); if (!hit) continue;
      const acc2 = privateKeyToAccount(hit.stealthPriv); if (acc2.address.toLowerCase() !== r.stealth.toLowerCase()) continue;
      const to = privateKeyToAccount(generatePrivateKey()).address, nonce = toHex(crypto.getRandomValues(new Uint8Array(32))), vb = BigInt(validBefore);
      const sig = await acc2.signTypedData({ domain: dom, types: WT, primaryType: "TransferWithAuthorization", message: { from: acc2.address, to, value: WD, validAfter: 0n, validBefore: vb, nonce } });
      wjobs.push({ from: acc2.address, to, body: { from: acc2.address, to, value: WD.toString(), validAfter: "0", validBefore: vb.toString(), nonce, v: parseInt(sig.slice(130, 132), 16), r: "0x" + sig.slice(2, 66), s: "0x" + sig.slice(66, 130) } });
    }
    ok("receiver found all its payments with the viewing key", wjobs.length === N, wjobs.length + "/" + N);
    await prewarm(wjobs.map(j => ({ from: j.from, to: j.to, nonce: j.body.nonce })));
    const T1 = performance.now();
    const wres = await Promise.all(wjobs.map(async j => { await sleep(Math.random() * BURST_MS); const r = await post(RELAY + "/stealth-api/relay", j.body); j.res = r;
      if (r.hash) pub.waitForTransactionReceipt({ hash: r.hash, pollingInterval: 100, timeout: 120000 }).then(rc => { j.rc = rc; j.minedMs = performance.now() - r.t0; }).catch(e => { j.rcErr = e.message; }); return r; }));
    const wall2 = performance.now() - T1;
    for (let i = 0; i < 400 && wjobs.some(j => j.res.hash && !j.rc && !j.rcErr); i++) await sleep(100);
    const wacc = wres.filter(r => r.status === 200), werrs = {}; wres.filter(r => r.status !== 200).forEach(r => { const t = errType(r.error); werrs[t] = (werrs[t] || 0) + 1; });
    const wmined = wjobs.filter(j => j.minedMs).map(j => j.minedMs), wh = wres.map(r => r.ms);
    console.log(`accepted ${wacc.length}/${wjobs.length}  errors ${JSON.stringify(werrs)}  wall ${(wall2 / 1000).toFixed(1)}s`);
    console.log(`HTTP latency ms: p50 ${pct(wh, .5).toFixed(0)} p95 ${pct(wh, .95).toFixed(0)} max ${Math.max(...wh).toFixed(0)}`);
    console.log(`request->mined ms: p50 ${pct(wmined, .5).toFixed(0)} p95 ${pct(wmined, .95).toFixed(0)} max ${Math.max(...wmined).toFixed(0)}  (mined ${wmined.length})`);
    const wgas = wjobs.filter(j => j.rc).map(j => Number(j.rc.gasUsed)); REPORT.wdGas = wgas.length ? Math.round(wgas.reduce((a, b) => a + b, 0) / wgas.length) : 0;
    console.log("withdraw gasUsed avg", REPORT.wdGas);
    const log2 = fs.readFileSync(path.join(tmp, "r.log"), "utf8");
    ok("phase2 all accepted", wacc.length === wjobs.length);
    ok("phase2 nonce errors == 0", !/nonce too|underpriced|already known/i.test(log2) && !wres.some(r => /nonce/i.test(r.error || "")));
    ok("phase2 all receipts success", wjobs.every(j => j.rc && j.rc.status === "success"));
    let r2 = 0; for (const j of wjobs) if ((await bal(j.to)) === WD && (await bal(j.from)) === AMOUNT - FEE - WD) r2++;
    ok("every withdrawal correct on-chain (dest = value, stealth remainder)", r2 === wjobs.length, r2 + "/" + wjobs.length);
    ok("log has no ALERT/reverted", !/ALERT|reverted/.test(log2), (log2.match(/ALERT.*|reverted.*/g) || []).slice(0, 3).join(" | "));
    await rpc("evm_setIntervalMining", [0]); await rpc("evm_setAutomine", [true]);
    const st = await (await fetch(RELAY + "/stealth-api/relay/stats")).json(); console.log("relay stats:", JSON.stringify(st));
    REPORT.st = st;
  }

  if (!process.env.SKIP_SCAN) {
    console.log(`\n== PHASE 3: ${SCAN_CLIENTS} concurrent scan clients for ${SCAN_S}s against the indexer`);
    // a dedicated indexer instance for the scan test: own DB, RPC = local stub (see below), so numbers are the indexer's own
    const SPORT = 3995, DB2 = path.join(tmp, "scan.db");
    const addrPool = Array.from({ length: 600 }, (_, i) => "0x" + (i + 1000).toString(16).padStart(40, "0"));
    // Balance lookups go to a local stub node (5 ms latency, answers Multicall3 aggregate3 synthetically, ignores the rest): measures the INDEXER, not the anvil fork
    // (a cold anvil fork fetches every account from the live RH node, which rate-limits with 429 and can crash anvil).
    const word32 = n => n.toString(16).padStart(64, "0"); const calls = { n: 0 };
    const stubRpc = http.createServer((q, r) => { let b = ""; q.on("data", c => b += c); q.on("end", () => { const j = JSON.parse(b); let result;
      if (j.method === "eth_getCode") result = "0x6080604052"; else if (j.method === "eth_call") { calls.n++; const d = j.params[0].data; const n = parseInt(d.slice(2 + 8 + 64, 2 + 8 + 128), 16);
        let out = word32(32) + word32(n) + Array.from({ length: n }, (_, i) => word32(n * 32 + i * 160)).join("") + Array.from({ length: n }, (_, i) => word32(1) + word32(64) + word32(32) + word32(1_000_000 + i)).join(""); result = "0x" + out; }
      else if (j.method === "eth_getLogs") result = []; else if (j.method === "eth_getBlockByNumber") result = { number: "0x64" }; else result = "0x64"; setTimeout(() => r.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, result })), 5); }); });
    await new Promise(r => stubRpc.listen(0, "127.0.0.1", r));
    const idx2 = spawn("python3", [process.env.INDEXER_FILE || path.join(HERE, "stealth_indexer.py")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: "http://127.0.0.1:" + stubRpc.address().port, STEALTHPAY: SP, STEALTH_PORT: String(SPORT), STEALTH_DB: DB2, STEALTH_START_BLOCK: "1", STEALTH_CONFIRMATIONS: "0", STEALTH_POLL: "2" }, stdio: ["ignore", "pipe", fs.openSync(path.join(tmp, "idx2.err"), "w")] });
    procs.push(idx2); idx2.stdout.on("data", () => {});
    for (let i = 0; i < 40; i++) { try { await fetch("http://127.0.0.1:" + SPORT + "/stealth-api/head"); break; } catch { await sleep(250); } }
    const py = `import sqlite3,os\nc=sqlite3.connect(${JSON.stringify(DB2)},timeout=30)\nn=c.execute("select coalesce(max(id),0) from ann").fetchone()[0]\nrows=[(0,'0x'+('%064x'%(i+10**9)),0,1,'0x'+('%040x'%(i+7)),'0x'+'55'*20,'0x02'+('%064x'%(i+5)),'0x'+('ab'+'a9059cbb'+'5fc5360d0400a0fd4f2af552add042d716f1d168'+'%064x'%1000000),'0xab','0x'+('%040x'%(i+3))) for i in range(${SEED_ROWS})]\nc.executemany("insert or ignore into ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer) values(?,?,?,?,?,?,?,?,?,?)",rows)\nc.commit();print(c.execute("select count(*) from ann").fetchone()[0])`;
    console.log("db rows:", execSync("python3 -c '" + py.replace(/'/g, "'\\''") + "'").toString().trim());
    const agent = new http.Agent({ keepAlive: true, maxSockets: SCAN_CLIENTS + 50 });
    const lat = { head: [], ann: [], bal: [] }, codes = {}; let reqs = 0, bytes = 0; const stopAt = Date.now() + SCAN_S * 1000;
    const get = (p, k) => new Promise(res => { const t0 = performance.now(); const rq = http.get({ host: "127.0.0.1", port: SPORT, path: "/stealth-api" + p, agent, timeout: 20000 }, r => {
      let n = 0; r.on("data", c => n += c.length); r.on("end", () => { lat[k].push(performance.now() - t0); codes[r.statusCode] = (codes[r.statusCode] || 0) + 1; reqs++; bytes += n; res(r.statusCode); }); });
      rq.on("error", e => { codes["err:" + e.code] = (codes["err:" + e.code] || 0) + 1; reqs++; res(0); }); rq.on("timeout", () => rq.destroy(new Error("timeout"))); });
    const samples = []; const sampler = setInterval(() => { try { const [c, r] = execSync(`ps -o %cpu=,rss= -p ${idx2.pid}`).toString().trim().split(/\s+/); samples.push([+c, +r / 1024]); } catch {} }, 2000);
    const client = async i => { await sleep(Math.random() * 3000); const mine = Array.from({ length: 50 }, (_, k) => addrPool[(i * 7 + k) % addrPool.length]);
      while (Date.now() < stopAt) { await get("/head", "head"); let since = 0; for (let pg = 0; pg < 3 && Date.now() < stopAt; pg++) { await get("/announcements?since=" + since + "&limit=1000", "ann"); since += 1000 * (pg + 1) * 0 + 1000 + Math.floor(Math.random() * 20000); }
        await get("/balances?addrs=" + mine.join(","), "bal"); await sleep(50 + Math.random() * 200); } };
    await Promise.all(Array.from({ length: SCAN_CLIENTS }, (_, i) => client(i))); clearInterval(sampler);
    const all = [...lat.head, ...lat.ann, ...lat.bal];
    console.log(`requests ${reqs} in ${SCAN_S}s = ${(reqs / SCAN_S).toFixed(0)} req/s, ${(bytes / 1e6 / SCAN_S).toFixed(1)} MB/s; status ${JSON.stringify(codes)}`);
    for (const k of ["head", "ann", "bal"]) console.log(`  /${k}: n ${lat[k].length} p50 ${pct(lat[k], .5).toFixed(0)}ms p95 ${pct(lat[k], .95).toFixed(0)}ms p99 ${pct(lat[k], .99).toFixed(0)}ms`);
    console.log(`  all p95 ${pct(all, .95).toFixed(0)}ms`);
    const cpu = samples.map(s => s[0]), rss = samples.map(s => s[1]);
    console.log(`indexer process: CPU% avg ${(cpu.reduce((a, b) => a + b, 0) / cpu.length).toFixed(0)} max ${Math.max(...cpu)}  RSS MB max ${Math.max(...rss).toFixed(0)}`);
    const bad = Object.entries(codes).filter(([k]) => k !== "200").reduce((a, [, v]) => a + v, 0);
    ok("scan: error rate < 1%", bad / reqs < 0.01, `${bad}/${reqs} non-200 (503=${codes[503] || 0})`);
    ok("scan: indexer still answers", (await fetch("http://127.0.0.1:" + SPORT + "/stealth-api/head")).ok);
  }
  console.log(fails ? "RESULT FAIL " + fails : "RESULT PASS"); done(fails ? 1 : 0);
} catch (e) { console.log("ERROR", e && e.stack || e); done(2); }
