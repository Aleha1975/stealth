/* One-command end-to-end suite on an anvil FORK of Robinhood Chain (4663). Run: node test_fork_e2e.mjs   (needs anvil + python3; network only to the RH RPC for the fork)
   Starts ONE anvil fork at a fixed block (state cached by anvil in ~/.foundry/cache, so reruns hardly touch the public RPC), runs the real
   relayer.mjs (two instances: main + flood-limited) and the real stealth_indexer.py against it on free ports, tears everything down and removes
   its temp dir. Uses the already DEPLOYED StealthPay v3 on the fork; balances are faked with anvil_setStorageAt / anvil_setBalance; every key is
   freshly generated: nothing is ever sent to the live chain. Prints a PASS/FAIL table; exit code 0 only if every row passes.
     A) happy paths   B) negative / abuse   C) "you pay 10" leaves exactly 10 (UI amount math + on-chain debit) */
import { spawn, spawnSync } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import net from "net"; import httpServer from "http"; import { fileURLToPath } from "url";
import { createPublicClient, createWalletClient, http, parseAbi, parseEventLogs, keccak256, encodeAbiParameters, toHex, getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { paymentNonce as jsPaymentNonce, payAmounts, splitSig } from "../web/pay-auth.js";
import { deriveForPayment, metaAddress, parseMeta, checkAnnouncement, decodeMetadata, keysFromSignature, signKeyRequestWith, keyRequestDigest, addressOf, addressFromPriv, secpUtils, unhex, hex } from "../web/stealth-crypto.js";
import { CHAINS } from "../web/chains.js";
import { postRelay } from "../web/relay-post.js";
import { keccak } from "../web/stealth-crypto.js";
import { makeFailBudget, failWeight, isLowS, SECP_N, ipKey, Refusal } from "./relay-util.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FORK_URL = "https://rpc.mainnet.chain.robinhood.com", FORK_BLOCK = 101173445;     // fixed block: anvil caches the state it fetches
const CH = CHAINS.rh, TOKEN = CH.token.address, SP = getAddress(CH.stealthPay), ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564";
const ZERO = "0x0000000000000000000000000000000000000000";
const FEE = 50000n, U = 1_000_000n;                                                   // $0.05 relayer fee, 6-decimals token
const sleep = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise(r => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const usd = v => (Number(v) / 1e6).toFixed(6);

// ---- result table
const rows = []; let group = "";
const sect = g => { group = g; console.log("\n== " + g); };
const ok = (name, pass, extra = "") => { rows.push({ g: group[0], name, pass: !!pass, extra }); console.log((pass ? "PASS " : "FAIL ") + name + (extra && !pass ? "   <-- " + extra : "")); };
const eq = (name, a, b) => ok(name, String(a) === String(b), "got " + a + " expected " + b);

const procs = []; let tmp = null;
const cleanup = () => { for (const p of procs) { try { p.kill("SIGKILL"); } catch {} } if (tmp) try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} };
process.on("SIGINT", () => { cleanup(); process.exit(130); });
const finish = code => { cleanup(); process.exit(code); };

try {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-fork-e2e-"));
  const [APORT, RPORT, R2PORT, IPORT] = [await freePort(), await freePort(), await freePort(), await freePort()];
  const RPC = "http://127.0.0.1:" + APORT, RELAY = "http://127.0.0.1:" + RPORT + "/stealth-api", RELAY2 = "http://127.0.0.1:" + R2PORT + "/stealth-api", IDX = "http://127.0.0.1:" + IPORT + "/stealth-api";
  const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });

  // ---- upstream proxy for the fork. The public RH node prunes state older than a few minutes ("historical state ... is not available"), so a fork
  // at a fixed block loses lazily-fetched slots mid-run. This tiny local proxy (a) sends the user-agent the node requires, (b) caches identical
  // requests (the node is rate limited), (c) retries a pruned state read at "latest": untouched slots of fresh random addresses and static contract
  // state (token implementation, domain, StealthPay code) are the same there, and everything the test changes lives in anvil's own overlay.
  const upCache = new Map(); const STATE_IDX = { eth_getStorageAt: 2, eth_getBalance: 1, eth_getCode: 1, eth_getTransactionCount: 1, eth_getProof: 2, eth_call: 1 };
  const up = async (o) => { const r = await fetch(FORK_URL, { method: "POST", headers: { "content-type": "application/json", "user-agent": "curl/8.7.1" }, body: JSON.stringify(o) }); return r.json(); };
  const one = async (o) => {
    const key = JSON.stringify([o.method, o.params]); if (upCache.has(key)) return { ...upCache.get(key), id: o.id };
    let j = await up(o);
    if (j.error && /historical state|not available|missing trie/i.test(JSON.stringify(j.error)) && STATE_IDX[o.method] !== undefined) { const params = [...o.params]; params[STATE_IDX[o.method]] = "latest"; j = await up({ ...o, params }); }
    if (!j.error) upCache.set(key, j); return { ...j, id: o.id };
  };
  const proxy = httpServer.createServer((q, r) => { let b = ""; q.on("data", c => b += c); q.on("end", async () => { try { const j = JSON.parse(b); const out = Array.isArray(j) ? await Promise.all(j.map(one)) : await one(j); r.writeHead(200, { "content-type": "application/json" }); r.end(JSON.stringify(out)); } catch (e) { r.writeHead(502); r.end(String(e)); } }); });
  const PPORT = await freePort(); await new Promise(r => proxy.listen(PPORT, "127.0.0.1", r)); procs.push({ kill: () => proxy.close() });
  // ---- anvil (one process, low priority)
  const anvil = spawn("nice", ["-n", "10", "anvil", "--fork-url", "http://127.0.0.1:" + PPORT, "--fork-block-number", String(FORK_BLOCK), "--retries", "8", "--port", String(APORT), "--silent"], { stdio: "ignore" });
  procs.push(anvil);
  for (let i = 0; i < 120; i++) { try { await rpc("eth_chainId"); break; } catch { await sleep(500); } }
  eq("fork up: chainId 4663", parseInt(await rpc("eth_chainId"), 16), 4663);
  const chain = { id: 4663, name: "rh-fork", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
  const pub = createPublicClient({ chain, transport: http(RPC) });
  const erc = parseAbi(["function balanceOf(address) view returns (uint256)", "function authorizationState(address,bytes32) view returns (bool)"]);
  const spAbi = parseAbi(["struct Authorization { address from; uint256 validAfter; uint256 validBefore; uint8 v; bytes32 r; bytes32 s; }",
    "function payWithAuthorization(address token, uint256 amount, address stealthAddress, bytes ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient, Authorization auth)",
    "function paymentNonce(address token, address stealthAddress, bytes ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient) view returns (bytes32)"]);
  const bal = a => pub.readContract({ address: TOKEN, abi: erc, functionName: "balanceOf", args: [a] });
  const eth = a => pub.getBalance({ address: a });
  const nonceOf = a => pub.getTransactionCount({ address: a });
  const mine = async n => rpc("anvil_mine", ["0x" + n.toString(16)]);
  // fake balances: USDG keeps balances in a mapping at slot 1 of its proxy (found by probing a real holder)
  const fund = async (a, v) => { await rpc("anvil_setStorageAt", [TOKEN, keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [a, 1n])), "0x" + v.toString(16).padStart(64, "0")]); await rpc("anvil_setBalance", [a, toHex(10n ** 18n)]); };
  const fundTok = async (a, v) => { await rpc("anvil_setStorageAt", [TOKEN, keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [a, 1n])), "0x" + v.toString(16).padStart(64, "0")]); };
  const probe = privateKeyToAccount(generatePrivateKey()).address; await fundTok(probe, 12345n);
  eq("fake USDG balance via storage write works", await bal(probe), 12345n);
  eq("deployed StealthPay v3 present on fork with our token", (await pub.getCode({ address: SP }))?.length > 100 && (await pub.readContract({ address: SP, abi: parseAbi(["function TOKEN() view returns (address)"]), functionName: "TOKEN" })).toLowerCase() === TOKEN.toLowerCase() ? "yes" : "no", "yes");

  // ---- processes
  const sanctioned = privateKeyToAccount(generatePrivateKey()).address;
  const sanctFile = path.join(tmp, "evm.json"); fs.writeFileSync(sanctFile, JSON.stringify({ published: "test", addresses: [sanctioned.toLowerCase()] }));
  const startRelayer = async (name, port, env) => {
    const rk = generatePrivateKey(), addr = privateKeyToAccount(rk).address; await rpc("anvil_setBalance", [addr, toHex(10n ** 18n)]);
    const logf = path.join(tmp, name + ".log");
    const p = spawn("nice", ["-n", "10", "node", path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_ENV_ONLY: "1", STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, RELAYER_KEY: rk, STEALTH_RELAY_PORT: String(port),
      STEALTH_RELAY_STATE: path.join(tmp, name + ".json"), STEALTH_RELAY_LOG: logf, STEALTH_SANCTIONS_FILE: sanctFile, STEALTH_INDEXER: "http://127.0.0.1:" + IPORT,
      STEALTH_RELAY_PAY_FEE: String(FEE), STEALTH_RELAY_PAY_FEE_MIN: String(FEE), STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", STEALTH_RELAY_MAX_PER_IP: "1000", STEALTH_RELAY_FAIL_PER_IP: "100000", STEALTH_RELAY_FAIL_PER_MIN: "100000", STEALTH_RELAY_GONE_GAP_MS: "1500", STEALTH_RELAY_REFUSED_LOG_PER_MIN: "100000", ...env }, stdio: ["ignore", "pipe", "inherit"] });
    procs.push(p); await new Promise(r => p.stdout.on("data", d => { if (String(d).includes("stealth relayer")) r(); }));
    return { addr, logf, p, state: path.join(tmp, name + ".json"), log: () => fs.readFileSync(logf, "utf8") };
  };
  const R1 = await startRelayer("r1", RPORT, { STEALTH_RELAY_FEE_MIN: String(FEE), STEALTH_RELAY_STUCK_S: "3" });
  const R2 = await startRelayer("r2", R2PORT, { STEALTH_RELAY_MAX_PER_IP: "3", STEALTH_RELAY_PAY_PER_PAYER: "2" });
  const stats = await (await fetch(RELAY + "/relay/stats")).json();
  ok("relayer up: pay enabled, StealthPay v3, fee 0.05", stats.pay_enabled && stats.stealthpay === SP && stats.pay_fee === String(FEE) && stats.relayer === R1.addr, JSON.stringify(stats).slice(0, 120));
  const idx = spawn("nice", ["-n", "10", "python3", "-B", path.join(HERE, "stealth_indexer.py")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTH_DB: path.join(tmp, "i.db"), STEALTH_PORT: String(IPORT), STEALTHPAY: SP.toLowerCase(),
    STEALTH_CONFIRMATIONS: "2", STEALTH_START_BLOCK: String(FORK_BLOCK + 1), STEALTH_POLL: "1" }, stdio: "ignore" }); procs.push(idx);

  const post = (base, p, b, ip = "9.9.9.9") => fetch(base + p, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip }, body: typeof b === "string" ? b : JSON.stringify(b) }).then(async r => ({ status: r.status, ...(await r.json()) }));
  let ipn = 10; const nip = () => "10.0." + Math.floor(++ipn / 250) + "." + (ipn % 250);          // a fresh client IP per request (per-IP caps are tested separately)

  // ---- typed-data helpers (viem, i.e. what a real wallet signs)
  const dom = o => ({ name: CH.token.domainName, version: CH.token.domainVersion, chainId: 4663, verifyingContract: TOKEN, ...o });
  const RT = { ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
  const TT = { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
  const now = () => Math.floor(Date.now() / 1000);
  const rnd32 = () => hex(secpUtils.utils.randomPrivateKey());
  // B's keys: derived from ONE signed EIP-712 message (web/stealth-crypto.js), exactly as the app does
  const bEoa = generatePrivateKey(), bAddr = privateKeyToAccount(bEoa).address;
  const bSig = signKeyRequestWith(unhex(bEoa), bAddr);
  const keys = keysFromSignature(bSig, bAddr), meta = metaAddress(keys, "rh");
  const newDest = () => deriveForPayment(parseMeta(meta));                                  // fresh one-time address for B
  // payer-side signature for payWithAuthorization (fee taken out of amount). o: domain override, validBefore, amountSigned
  const payAuth = async (payer, d, amount, fee, feeTo, o = {}) => {
    const nonce = jsPaymentNonce({ chainId: 4663, stealthPay: SP, token: TOKEN, stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee, feeRecipient: feeTo });
    const validBefore = o.validBefore ?? now() + 3600;
    const sig = splitSig(await payer.signTypedData({ domain: dom(o.domain), types: RT, primaryType: "ReceiveWithAuthorization", message: { from: payer.address, to: SP, value: o.signed ?? amount, validAfter: 0n, validBefore: BigInt(validBefore), nonce } }));
    return { nonce, validBefore, sig };
  };
  const payBody = (payer, d, amount, fee, feeTo, a, o = {}) => ({ token: TOKEN, amount: amount.toString(), stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: fee.toString(), feeRecipient: feeTo,
    auth: { from: payer.address, validAfter: "0", validBefore: String(a.validBefore), v: a.sig.v, r: a.sig.r, s: a.sig.s }, ...o });
  // payer calls StealthPay.payWithAuthorization himself (own gas, fee 0)
  const payOwnGas = async (payer, d, amount) => {
    const a = await payAuth(payer, d, amount, 0n, ZERO);
    const w = createWalletClient({ account: payer, chain, transport: http(RPC) });
    const h = await w.writeContract({ address: SP, abi: spAbi, functionName: "payWithAuthorization", args: [TOKEN, amount, d.stealth, d.ephPub, d.viewTag, 0n, ZERO, { from: payer.address, validAfter: 0n, validBefore: BigInt(a.validBefore), v: a.sig.v, r: a.sig.r, s: a.sig.s }] });
    return pub.waitForTransactionReceipt({ hash: h });
  };
  const newPayer = async (amt = 1000n * U) => { const pk = generatePrivateKey(), acc = privateKeyToAccount(pk); await fund(acc.address, amt); await rpc("anvil_setBalance", [acc.address, "0x0"]); return acc; };

  // ===================================================================================== A) happy paths
  sect("A) happy paths");
  const ka = secpUtils.getPublicKey(keys.spendPriv, true);
  ok("B: keys derive from the signed message and are stable", hex(ka) === hex(keys.spendPub) && hex(keysFromSignature(signKeyRequestWith(unhex(bEoa), bAddr), bAddr).viewPub) === hex(keys.viewPub));
  ok("B: wrong account for the signature is rejected", (() => { try { keysFromSignature(bSig, privateKeyToAccount(generatePrivateKey()).address); return false; } catch { return true; } })());
  const A = await newPayer(), C = privateKeyToAccount(generatePrivateKey()).address;
  const d1 = newDest(), d2 = newDest();
  eq("JS paymentNonce == contract paymentNonce", jsPaymentNonce({ chainId: 4663, stealthPay: SP, token: TOKEN, stealth: d1.stealth, eph: d1.ephPub, viewTag: d1.viewTag, fee: FEE, feeRecipient: R1.addr }),
    await pub.readContract({ address: SP, abi: spAbi, functionName: "paymentNonce", args: [TOKEN, d1.stealth, d1.ephPub, d1.viewTag, FEE, R1.addr] }));
  // A pays 10 gasless through the relayer; C) the amounts come from the UI math
  const am = payAmounts({ src: "amount", text: "10", decimals: 6, fee: FEE });
  const a0 = await bal(A.address), r0 = await bal(R1.addr), rn0 = await nonceOf(R1.addr);
  const au1 = await payAuth(A, d1, am.send, FEE, R1.addr);
  const p1 = await post(RELAY, "/relay/pay", payBody(A, d1, am.send, FEE, R1.addr, au1), nip());
  ok("A1 gasless pay accepted by /relay/pay", p1.status === 200 && /^0x[0-9a-f]{64}$/.test(p1.hash || ""), JSON.stringify(p1));
  const rc1 = await pub.waitForTransactionReceipt({ hash: p1.hash });
  ok("A1 mined success, sent by relayer, payer has 0 ETH", rc1.status === "success" && rc1.from.toLowerCase() === R1.addr.toLowerCase() && (await eth(A.address)) === 0n);
  eq("A1 payer debited exactly 10.000000", usd(a0 - await bal(A.address)), "10.000000");
  eq("A1 stealth got 9.950000 (10 - 0.05 fee)", usd(await bal(d1.stealth)), "9.950000");
  eq("A1 relayer earned exactly 0.05", usd((await bal(R1.addr)) - r0), "0.050000");
  eq("A1 StealthPay holds nothing", await bal(SP), 0n);
  const ev1 = parseEventLogs({ abi: parseAbi(["event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)"]), logs: rc1.logs, eventName: "Announcement" })[0]?.args;
  ok("A1 Announcement: stealth, ephemeral key, view tag, amount", ev1 && ev1.stealthAddress === d1.stealth && ev1.ephemeralPubKey.toLowerCase() === d1.ephPub && ev1.metadata.slice(0, 4) === d1.viewTag && decodeMetadata(ev1.metadata).amount === 9_950_000n);
  // A pays via payWithAuthorization with own gas (now A gets ETH for it)
  await rpc("anvil_setBalance", [A.address, toHex(10n ** 18n)]);
  const a1 = await bal(A.address);
  const rc2 = await payOwnGas(A, d2, 5n * U);
  ok("A2 payWithAuthorization with own gas mined", rc2.status === "success" && rc2.from.toLowerCase() === A.address.toLowerCase());
  eq("A2 payer debited exactly 5.000000", usd(a1 - await bal(A.address)), "5.000000");
  eq("A2 stealth got the full 5.000000 (fee 0)", usd(await bal(d2.stealth)), "5.000000");
  // extra stealth payments (own gas, cheap) that the negative tests will withdraw from
  const W = {}; for (const k of ["rep", "dom", "dom2", "exp", "amt", "feelow", "nofee", "sanc", "par", "stuck", "drop", "nonce", "after", "dup", "dup2", "alk", "ntl", "rd", "lst", "pl1", "pl2"]) { W[k] = newDest(); await payOwnGas(A, W[k], 3n * U); }
  await mine(3);
  // B scans announcements through the indexer
  let annRows = []; for (let i = 0; i < 90; i++) { try { annRows = (await (await fetch(IDX + "/announcements?since=0&limit=2000")).json()).rows; } catch {} if (annRows.length >= 2 + Object.keys(W).length) break; await sleep(500); }
  const found = annRows.filter(r => r.scheme === 1).map(r => ({ r, hit: checkAnnouncement(keys, r.eph, r.meta.slice(0, 4)) })).filter(x => x.hit);
  const byStealth = s => found.find(x => x.hit.stealth.toLowerCase() === s.toLowerCase());
  const f1 = byStealth(d1.stealth), f2 = byStealth(d2.stealth);
  ok("A3 B finds both payments by scanning (view tag + keys)", !!f1 && !!f2 && found.length === 2 + Object.keys(W).length, "found " + found.length + " of " + annRows.length);
  ok("A3 view tag, amount, ephemeral key match", f1 && f2 && f1.r.meta.slice(0, 4) === d1.viewTag && f2.r.meta.slice(0, 4) === d2.viewTag && decodeMetadata(f1.r.meta).amount === 9_950_000n && decodeMetadata(f2.r.meta).amount === 5_000_000n && f1.r.eph.toLowerCase() === d1.ephPub && f2.r.eph.toLowerCase() === d2.ephPub);
  ok("A3 indexer payer: gasless = signer (not relayer); own gas = signer", f1 && f2 && f1.r.payer === A.address.toLowerCase() && f2.r.payer === A.address.toLowerCase(), String(f1?.r.payer));
  ok("A3 stealth key re-derived by B controls the address", f1 && addressFromPriv(unhex(f1.hit.stealthPriv)).toLowerCase() === d1.stealth.toLowerCase());
  const known = a => fetch(IDX + "/known?addr=" + a).then(r => r.json()).then(j => j.known);
  ok("A3 indexer /known: both stealth addresses known", (await known(d1.stealth)) && (await known(d2.stealth)));
  const stPriv = s => privateKeyToAccount(byStealth(s).hit.stealthPriv);                      // B's stealth account (signs EIP-3009 transfers)
  // B withdraws stealth -> C through the relayer: value + feeAuth (0.05) from the stealth address
  const wbody = async (s, to, value, fee, o = {}) => {
    const acc = stPriv(s), vb = o.validBefore ?? now() + 3600, n1 = rnd32(), n2 = rnd32(); const D = dom(o.domain);
    const sg = async (toA, v, n) => { const x = splitSig(await acc.signTypedData({ domain: D, types: TT, primaryType: "TransferWithAuthorization", message: { from: acc.address, to: toA, value: v, validAfter: 0n, validBefore: BigInt(vb), nonce: n } })); return { v: x.v, r: x.r, s: x.s }; };
    const main = await sg(to, o.signedValue ?? value, n1);
    const b = { from: acc.address, to, value: value.toString(), validAfter: "0", validBefore: String(vb), nonce: n1, ...main };
    if (fee !== null) { const f = await sg(o.feeTo ?? R1.addr, o.feeSigned ?? fee, n2); b.feeAuth = { value: fee.toString(), validAfter: "0", validBefore: String(vb), nonce: n2, ...f }; }
    return b;
  };
  for (const [name, d, total] of [["S1", d1, 9_950_000n], ["S2", d2, 5_000_000n]]) {
    const c0 = await bal(C), r0 = await bal(R1.addr);
    const body = await wbody(d.stealth, C, total - FEE, FEE);
    const w = await post(RELAY, "/relay", body, nip());
    ok("A4 withdraw " + name + " -> C accepted", w.status === 200 && !!w.hash && !!w.feeHash, JSON.stringify(w));
    if (w.hash) { await pub.waitForTransactionReceipt({ hash: w.hash }); await pub.waitForTransactionReceipt({ hash: w.feeHash }); }
    eq("A4 " + name + " C received exactly " + usd(total - FEE), usd((await bal(C)) - c0), usd(total - FEE));
    eq("A4 " + name + " relayer fee exactly 0.05, stealth emptied", usd((await bal(R1.addr)) - r0) + "/" + usd(await bal(d.stealth)), "0.050000/0.000000");
  }
  // A5 the state file / stats stay consistent after the happy paths
  ok("A5 relayer state persisted (per-payer, per-from counters)", (() => { const j = JSON.parse(fs.readFileSync(R1.state, "utf8")); return j.perPayer[A.address] === 1 && j.perFrom[d1.stealth] === 1 && j.perFrom[d2.stealth] === 1; })());

  // ===================================================================================== B) negative / abuse
  sect("B) negative / abuse");
  const snap = async (extra = []) => ({ n: await nonceOf(R1.addr), e: await eth(R1.addr), t: await bal(R1.addr), ex: await Promise.all(extra.map(bal)) });
  const same = (a, b) => a.n === b.n && a.e === b.e && a.t === b.t && a.ex.every((x, i) => x === b.ex[i]);
  const refused = async (name, resP, re, st0, extra = []) => { const r = await resP; const s1 = await snap(extra); ok(name, r.status === 400 && re.test(r.error || "") && same(st0, s1), JSON.stringify(r).slice(0, 140)); };

  // B1 replay of the same pay authorization (payload accepted above in A1)
  { const s0 = await snap([d1.stealth]); const rp = await post(RELAY, "/relay/pay", payBody(A, d1, am.send, FEE, R1.addr, au1), nip()); ok("B1 replay of a used pay authorization: the original hash comes back (audit 1099 L-1), nothing moves", rp.status === 200 && rp.hash === p1.hash && same(s0, await snap([d1.stealth])), JSON.stringify(rp)); }
  // B1b replay of a withdrawal
  { const dd = newDest(); await payOwnGas(A, dd, 3n * U); await mine(3); for (let i = 0; i < 60 && !(await known(dd.stealth)); i++) await sleep(500);
    const x = checkAnnouncement(keys, dd.ephPub, dd.viewTag); const acc = privateKeyToAccount(x.stealthPriv);
    const vb = now() + 3600, n1 = rnd32(), n2 = rnd32();
    const sg = async (to, v, n) => { const q = splitSig(await acc.signTypedData({ domain: dom(), types: TT, primaryType: "TransferWithAuthorization", message: { from: acc.address, to, value: v, validAfter: 0n, validBefore: BigInt(vb), nonce: n } })); return { v: q.v, r: q.r, s: q.s }; };
    const body = { from: acc.address, to: C, value: String(U), validAfter: "0", validBefore: String(vb), nonce: n1, ...(await sg(C, U, n1)), feeAuth: { value: FEE.toString(), validAfter: "0", validBefore: String(vb), nonce: n2, ...(await sg(R1.addr, FEE, n2)) } };
    const w1 = await post(RELAY, "/relay", body, nip()); await pub.waitForTransactionReceipt({ hash: w1.hash }); await pub.waitForTransactionReceipt({ hash: w1.feeHash });
    const s0 = await snap([acc.address]); const rw = await post(RELAY, "/relay", body, nip()); ok("B1b replay of a used withdrawal: the original hashes come back (audit 1099 L-1), nothing moves", rw.status === 200 && rw.hash === w1.hash && rw.feeHash === w1.feeHash && same(s0, await snap([acc.address])), JSON.stringify(rw));
    // a replay under a fresh nonce is a different authorization and is refused as before (here: the address is empty)
    const rn = await post(RELAY, "/relay", { ...body, nonce: rnd32() }, nip()); ok("B1b a changed nonce is not a replay: refused (signature no longer matches)", rn.status === 400 && /signature does not match/.test(rn.error), JSON.stringify(rn)); }

  // B2 wrong chainId / wrong verifyingContract in the signed domain (relayer pre-check for pay; contract-level for both)
  { const dd = newDest(); const s0 = await snap();
    const aw = await payAuth(A, dd, 2n * U, FEE, R1.addr, { domain: { chainId: 1 } });
    await refused("B2 pay: signature over chainId 1 refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, FEE, R1.addr, aw), nip()), /signature does not match/, s0);
    const av = await payAuth(A, dd, 2n * U, FEE, R1.addr, { domain: { verifyingContract: "0x000000000000000000000000000000000000dEaD" } });
    await refused("B2 pay: signature over wrong verifyingContract refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, FEE, R1.addr, av), nip()), /signature does not match/, s0);
    // contract level (bypassing the relayer): estimateGas must revert
    const direct = async au => pub.estimateContractGas({ address: SP, abi: spAbi, functionName: "payWithAuthorization", args: [TOKEN, 2n * U, dd.stealth, dd.ephPub, dd.viewTag, FEE, R1.addr, { from: A.address, validAfter: 0n, validBefore: BigInt(au.validBefore), v: au.sig.v, r: au.sig.r, s: au.sig.s }], account: R1.addr }).then(() => false, () => true);
    ok("B2 contract itself rejects wrong chainId / wrong verifyingContract", (await direct(aw)) && (await direct(av)));
    const okAu = await payAuth(A, dd, 2n * U, FEE, R1.addr); ok("B2 control: the same payload with the right domain is accepted by the contract", !(await direct(okAu)));
    const w = await newDest(), s1 = await snap([W.dom.stealth, W.dom2.stealth]);
    await refused("B2 withdraw: signature over chainId 1 refused", post(RELAY, "/relay", await wbody(W.dom.stealth, C, 2n * U, FEE, { domain: { chainId: 1 } }), nip()), /.+/, s1, [W.dom.stealth, W.dom2.stealth]);
    await refused("B2 withdraw: signature over wrong verifyingContract refused", post(RELAY, "/relay", await wbody(W.dom2.stealth, C, 2n * U, FEE, { domain: { verifyingContract: "0x000000000000000000000000000000000000dEaD" } }), nip()), /.+/, s1, [W.dom.stealth, W.dom2.stealth]); }
  // B3 expired validBefore
  { const dd = newDest(); const s0 = await snap();
    const ae = await payAuth(A, dd, 2n * U, FEE, R1.addr, { validBefore: now() - 10 });
    await refused("B3 pay: expired validBefore refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, FEE, R1.addr, ae), nip()), /expires/, s0);
    const as = await payAuth(A, dd, 2n * U, FEE, R1.addr, { validBefore: now() + 10 });
    await refused("B3 pay: validBefore within 30 s refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, FEE, R1.addr, as), nip()), /expires/, s0);
    const s1 = await snap([W.exp.stealth]);
    await refused("B3 withdraw: expired validBefore refused", post(RELAY, "/relay", await wbody(W.exp.stealth, C, 2n * U, FEE, { validBefore: now() - 10 }), nip()), /expires/, s1, [W.exp.stealth]); }
  // B4 amount mismatch vs what was signed
  { const dd = newDest(); const s0 = await snap();
    const ag = await payAuth(A, dd, 2n * U, FEE, R1.addr);
    await refused("B4 pay: amount differs from the signed amount (+1) refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U + 1n, FEE, R1.addr, ag), nip()), /signature does not match/, s0);
    await refused("B4 pay: signed 2.00, body claims 20.00 refused", post(RELAY, "/relay/pay", payBody(A, dd, 20n * U, FEE, R1.addr, ag), nip()), /signature does not match/, s0);
    const s1 = await snap([W.amt.stealth]);
    await refused("B4 withdraw: main amount differs from signed refused", post(RELAY, "/relay", await wbody(W.amt.stealth, C, 2n * U, FEE, { signedValue: 1n * U }), nip()), /.+/, s1, [W.amt.stealth]);
    await refused("B4 withdraw: fee amount differs from signed refused", post(RELAY, "/relay", await wbody(W.amt.stealth, C, 2n * U, FEE, { feeSigned: FEE - 1n }), nip()), /.+/, s1, [W.amt.stealth]);
    await refused("B4 withdraw: more than the address holds refused", post(RELAY, "/relay", await wbody(W.amt.stealth, C, 5n * U, FEE), nip()), /holds less/, s1, [W.amt.stealth]); }
  // B5 fee below the minimum
  { const dd = newDest(); const s0 = await snap();
    const lo = await payAuth(A, dd, 2n * U, FEE - 1n, R1.addr);
    await refused("B5 pay: fee 0.049999 (below minimum) refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, FEE - 1n, R1.addr, lo), nip()), /fee out of range/, s0);
    const z = await payAuth(A, dd, 2n * U, 0n, ZERO);
    await refused("B5 pay: zero fee refused", post(RELAY, "/relay/pay", payBody(A, dd, 2n * U, 0n, ZERO, z), nip()), /fee out of range/, s0);
    const s1 = await snap([W.feelow.stealth, W.nofee.stealth]);
    await refused("B5 withdraw: feeAuth below minimum refused", post(RELAY, "/relay", await wbody(W.feelow.stealth, C, 2n * U, FEE - 1n), nip()), /fee below the minimum/, s1, [W.feelow.stealth, W.nofee.stealth]);
    await refused("B5 withdraw: no feeAuth at all refused", post(RELAY, "/relay", await wbody(W.nofee.stealth, C, 2n * U, null), nip()), /fee authorization required/, s1, [W.feelow.stealth, W.nofee.stealth]);
    await refused("B5 withdraw: fee paid to someone else (not the relayer) refused", post(RELAY, "/relay", await wbody(W.nofee.stealth, C, 2n * U, FEE, { feeTo: C }), nip()), /.+/, s1, [W.feelow.stealth, W.nofee.stealth]); }
  // B6 sanctioned recipient (test address injected into the sanctions list file the relayer watches)
  { const dd = newDest(); const s0 = await snap([sanctioned]);
    const as = await payAuth(A, dd, 2n * U, FEE, R1.addr);
    await refused("B6 pay: sanctioned stealth/recipient refused before any gas", post(RELAY, "/relay/pay", payBody(A, { ...dd, stealth: sanctioned }, 2n * U, FEE, R1.addr, as), nip()), /sanctions/, s0, [sanctioned]);
    const s1 = await snap([W.sanc.stealth, sanctioned]);
    await refused("B6 withdraw: sanctioned destination refused before any gas", post(RELAY, "/relay", await wbody(W.sanc.stealth, sanctioned, 2n * U, FEE), nip()), /sanctions/, s1, [W.sanc.stealth, sanctioned]);
    ok("B6 sanctioned payer wallet refused too", await (async () => { const r = await post(RELAY, "/relay/pay", payBody({ address: sanctioned }, dd, 2n * U, FEE, R1.addr, as), nip()); return r.status === 400 && /sanctions/.test(r.error); })());
    const g = await (await fetch(RELAY + "/relay/screen?addr=" + sanctioned)).json(); ok("B6 /relay/screen reports listed=true", g.listed === true); }
  // B7 two parallel withdrawals from the SAME stealth address: exactly one may succeed
  { const P = W.par.stealth, s0 = await snap(), p0 = await bal(P), c0 = await bal(C);
    const [b1, b2] = [await wbody(P, C, 29n * U / 10n, FEE), await wbody(P, C, 29n * U / 10n, FEE)];
    const rs = await Promise.all([post(RELAY, "/relay", b1, nip()), post(RELAY, "/relay", b2, nip())]);
    const good = rs.filter(r => r.status === 200), bad = rs.filter(r => r.status === 400);
    ok("B7 exactly one of two parallel withdrawals accepted", good.length === 1 && bad.length === 1, JSON.stringify(rs).slice(0, 200));
    if (good[0]) { await pub.waitForTransactionReceipt({ hash: good[0].hash }); await pub.waitForTransactionReceipt({ hash: good[0].feeHash }); }
    await sleep(500);
    eq("B7 no double spend: stealth left 0.05 - ... = 3.00 - 2.90 - 0.05", usd(await bal(P)), usd(3n * U - 29n * U / 10n - FEE));
    eq("B7 C received exactly one 2.90", usd((await bal(C)) - c0), "2.900000");
    eq("B7 relayer earned exactly one fee", usd((await bal(R1.addr)) - (s0.t)), "0.050000");
    const st = JSON.parse(fs.readFileSync(R1.state, "utf8"));
    ok("B7 relayer state consistent: one perFrom, lock released", st.perFrom[P] === 1);
    const again = await post(RELAY, "/relay", await wbody(P, C, 2n * U, FEE), nip());
    ok("B7 later request sees the real balance (lock released, not stuck 'in progress')", again.status === 400 && /holds less/.test(again.error), JSON.stringify(again)); }
  // B8 relayer recovery: stale local nonce, stuck tx (replacement), dropped tx (nonce gap)
  { // (a) somebody else used the relayer key: cached nonce is stale -> must recover without failing the user
    await rpc("anvil_impersonateAccount", [R1.addr]); await pub.waitForTransactionReceipt({ hash: await rpc("eth_sendTransaction", [{ from: R1.addr, to: R1.addr, value: "0x0" }]) });
    const c0 = await bal(C), n0 = await nonceOf(R1.addr);
    const w = await post(RELAY, "/relay", await wbody(W.nonce.stealth, C, 2n * U, FEE), nip());
    ok("B8a stale relayer nonce: request still succeeds (one internal retry)", w.status === 200, JSON.stringify(w));
    if (w.hash) { await pub.waitForTransactionReceipt({ hash: w.hash }); await pub.waitForTransactionReceipt({ hash: w.feeHash }); }
    eq("B8a C received 2.00 and relayer nonce advanced by 2", usd((await bal(C)) - c0) + "/" + ((await nonceOf(R1.addr)) - n0), "2.000000/2");
    // (b) stuck: node does not mine -> relayer replaces the tx (same nonce, higher fee); after mining the replacement lands
    await rpc("evm_setAutomine", [false]);
    const dd = newDest(); await rpc("evm_setAutomine", [true]); await payOwnGas(A, dd, 3n * U); await mine(3); for (let i = 0; i < 60 && !(await known(dd.stealth)); i++) await sleep(500);
    const x = checkAnnouncement(keys, dd.ephPub, dd.viewTag), acc = privateKeyToAccount(x.stealthPriv);
    const vb = now() + 3600, n1 = rnd32(), n2 = rnd32();
    const sg = async (to, v, n) => { const q = splitSig(await acc.signTypedData({ domain: dom(), types: TT, primaryType: "TransferWithAuthorization", message: { from: acc.address, to, value: v, validAfter: 0n, validBefore: BigInt(vb), nonce: n } })); return { v: q.v, r: q.r, s: q.s }; };
    const mk = async (value) => ({ from: acc.address, to: C, value: String(value), validAfter: "0", validBefore: String(vb), nonce: n1, ...(await sg(C, value, n1)), feeAuth: { value: FEE.toString(), validAfter: "0", validBefore: String(vb), nonce: n2, ...(await sg(R1.addr, FEE, n2)) } });
    const bStuck = await mk(2n * U), cc0 = await bal(C);
    await rpc("evm_setAutomine", [false]);
    const ws = await post(RELAY, "/relay", bStuck, nip());
    ok("B8b stuck: relayer accepted while node mines nothing", ws.status === 200, JSON.stringify(ws));
    let rep = false; for (let i = 0; i < 40 && !rep; i++) { rep = /replacement/.test(R1.log()); if (!rep) await sleep(500); }
    ok("B8b stuck tx replaced by the relayer (same nonce, higher fee)", rep);
    await rpc("evm_setAutomine", [true]); await mine(2);
    await sleep(1500);
    eq("B8b after mining, money moved exactly once: C +2.00", usd((await bal(C)) - cc0), "2.000000");
    { const sj = await fetch(RELAY + "/relay/status?hash=" + ws.hash).then(r => r.json());     // the client polled the ORIGINAL hash: the relayer says where it went
      ok("B8b GET /relay/status follows the replacement: new hash, status success", sj.status === "success" && /^0x[0-9a-f]{64}$/.test(sj.hash) && sj.hash !== ws.hash.toLowerCase(), JSON.stringify(sj));
      ok("B8b /relay/status rejects a bad hash", (await fetch(RELAY + "/relay/status?hash=0x12")).status === 400); }
    // (c) dropped tx: the node forgets it -> nonce gap must be closed and the next withdrawal must work
    const nD = await nonceOf(R1.addr);
    await rpc("evm_setAutomine", [false]);
    const wd = await post(RELAY, "/relay", await wbody(W.drop.stealth, C, 2n * U, FEE), nip());
    ok("B8c dropped: first request accepted (then dropped by the node)", wd.status === 200, JSON.stringify(wd));
    for (const h of [wd.feeHash, wd.hash]) if (h) await rpc("anvil_dropTransaction", [h]).catch(() => {});
    let gap = false; for (let i = 0; i < 60 && !gap; i++) { gap = /nonce gap filled|dropped/.test(R1.log()); if (!gap) await sleep(500); }
    ok("B8c relayer noticed the dropped tx and closed the nonce gap", gap, R1.log().split("\n").slice(-4).join(" | ").slice(0, 200));
    await rpc("evm_setAutomine", [true]); await mine(1);
    const c1 = await bal(C), w2 = await post(RELAY, "/relay", await wbody(W.after.stealth, C, 2n * U, FEE), nip());
    ok("B8c next withdrawal after the drop is accepted", w2.status === 200, JSON.stringify(w2));
    let mined = false; if (w2.hash) { try { await pub.waitForTransactionReceipt({ hash: w2.hash, timeout: 8000 }); mined = true; } catch {} }
    ok("B8c ...and actually mines (no stuck nonce gap)", mined && (await bal(C)) - c1 === 2n * U, usd((await bal(C)) - c1));
    const retry = await post(RELAY, "/relay", await wbody(W.drop.stealth, C, 2n * U, FEE), nip());
    ok("B8c dropped withdrawal can be retried by the user (quota released)", retry.status === 200, JSON.stringify(retry)); }
  // B9 high-s signature on the key-derivation message must not give another key set
  { const SECP_N = secpUtils.CURVE.n, sBig = BigInt("0x" + bSig.slice(66, 130)), vv = parseInt(bSig.slice(130), 16);
    const hi = bSig.slice(0, 66) + (SECP_N - sBig).toString(16).padStart(64, "0") + (vv === 27 ? "1c" : "1b");           // (r, n-s, v^1): same signer, other bytes
    const recAddr = sig => addressOf(secpUtils.Signature.fromCompact(unhex(sig).slice(0, 64)).addRecoveryBit(unhex(sig)[64] - 27).recoverPublicKey(keyRequestDigest(bAddr)).toRawBytes(true));
    ok("B9 the malleated (high-s) signature is a valid signature of the same account", recAddr(hi).toLowerCase() === bAddr.toLowerCase() && recAddr(bSig).toLowerCase() === bAddr.toLowerCase() && hi !== bSig);
    let k2 = null, err = null; try { k2 = keysFromSignature(hi, bAddr); } catch (e) { err = e; }
    ok("B9 high-s signature rejected or normalised to the SAME keys", err !== null || (hex(k2.spendPriv) === hex(keys.spendPriv) && hex(k2.viewPriv) === hex(keys.viewPriv)), "different key set from a malleated signature");
    // existing users keep their keys: the pre-fix derivation (hash of r||s as given) equals the new one for every normal low-s signature
    const oldKeys = (sg) => { const rs = unhex(sg).slice(0, 64), d = t => { const h = BigInt(hex(keccak(new Uint8Array([...rs, ...new TextEncoder().encode(t)])))) % SECP_N; return hex(unhex((h || 1n).toString(16).padStart(64, "0"))); }; return [d("deepyield-stealth/spend/v1"), d("deepyield-stealth/view/v1")]; };
    let stable = true; for (let i = 0; i < 20; i++) { const pk = generatePrivateKey(), ad = privateKeyToAccount(pk).address, sg = signKeyRequestWith(unhex(pk), ad), k = keysFromSignature(sg, ad), o = oldKeys(sg); if (hex(k.spendPriv) !== o[0] || hex(k.viewPriv) !== o[1]) stable = false; }
    ok("B9 keys from normal low-s signatures are unchanged vs the old derivation (20 random accounts)", stable);
    { const rs = unhex(hi).slice(0, 64); ok("B9 control: without normalisation the high-s variant WOULD give other keys", oldKeys(hi)[0] !== oldKeys(bSig)[0] && rs.length === 64); }
    const v01 = bSig.slice(0, 130) + (vv - 27).toString(16).padStart(2, "0");
    ok("B9 v = 0/1 vs 27/28 gives the same keys", hex(keysFromSignature(v01, bAddr).spendPriv) === hex(keys.spendPriv)); }
  // B10 flooding: per-IP and per-payer caps, garbage flood, oversize body (second relayer with low caps)
  { const stealthFor = () => newDest(); const payers = [await newPayer(), await newPayer(), await newPayer(), await newPayer(), await newPayer()];
    const one = async (payer, ip) => { const dd = stealthFor(), au = await payAuth(payer, dd, 2n * U, FEE, R2.addr); return post(RELAY2, "/relay/pay", payBody(payer, dd, 2n * U, FEE, R2.addr, au), ip); };
    const res = []; for (let i = 0; i < 5; i++) res.push(await one(payers[i], "7.7.7.7"));
    ok("B10 per-IP cap (3/day): first 3 accepted, 4th and 5th refused", res.slice(0, 3).every(r => r.status === 200) && res.slice(3).every(r => r.status === 400 && /too many requests/.test(r.error)), JSON.stringify(res.map(r => r.status)));
    const other = await one(payers[4], "7.7.7.8"); ok("B10 a different IP is not affected", other.status === 200, JSON.stringify(other));
    const q = [await one(payers[0], "8.8.8.1"), await one(payers[0], "8.8.8.2")];       // payers[0] already paid once through 7.7.7.7
    ok("B10 per-payer cap (2/day): the third payment of one wallet is refused", q[0].status === 200 && q[1].status === 400 && /too many payments/.test(q[1].error), JSON.stringify(q.map(r => r.error || r.status)));
    const n0 = await nonceOf(R2.addr), e0 = await eth(R2.addr), t0 = Date.now();
    const junk = await Promise.all(Array.from({ length: 60 }, (_, i) => post(RELAY2, i % 2 ? "/relay/pay" : "/relay", { garbage: i, from: "0x1", auth: {} }, "6.6.6." + i).catch(() => ({ status: 0 }))));
    const st2 = await fetch(RELAY2 + "/relay/stats").then(r => r.json());
    ok("B10 60 garbage requests: all 400, no gas spent, relayer still answers", junk.every(r => r.status === 400) && (await nonceOf(R2.addr)) === n0 && (await eth(R2.addr)) === e0 && !!st2.relayer, junk.map(r => r.status).join(",").slice(0, 60) + " " + (Date.now() - t0) + "ms");
    const big = await fetch(RELAY2 + "/relay/pay", { method: "POST", body: "x".repeat(20000) }).then(r => "http " + r.status, e => "closed");
    ok("B10 oversize body (20 KB) is cut off", /closed|http 4/.test(big) && !!(await fetch(RELAY2 + "/relay/stats").then(r => r.json())).relayer, big);
    ok("B10 relayer fee recipient must be the relayer (cannot redirect fees)", (await post(RELAY2, "/relay/pay", payBody(payers[1], stealthFor(), 2n * U, FEE, payers[1].address, await payAuth(payers[1], stealthFor(), 2n * U, FEE, payers[1].address)), "5.5.5.5")).error === "fee recipient must be the relayer"); }

  // B11 audit 1087: duplicate in-flight authorization, no refund on revert, IPv6 /64, log injection, routing by pathname
  { await rpc("evm_setAutomine", [true]); await mine(1);
    const c0 = await bal(C), body = await wbody(W.dup.stealth, C, 2n * U, FEE);
    await rpc("evm_setAutomine", [false]);
    const d1 = await post(RELAY, "/relay", body, nip()), d2 = await post(RELAY, "/relay", body, nip());
    ok("B11a the same authorization sent twice while unmined returns the SAME hashes (no second transaction)", d1.status === 200 && d2.status === 200 && d1.hash === d2.hash && d1.feeHash === d2.feeHash, JSON.stringify([d1, d2]).slice(0, 200));
    const stp = JSON.parse(fs.readFileSync(R1.state, "utf8"));
    ok("B11a ...and the duplicate used no extra allowance", stp.perFrom[W.dup.stealth] === 1, JSON.stringify(stp.perFrom[W.dup.stealth]));
    await rpc("evm_setAutomine", [true]); await mine(2);
    for (const h of [d1.feeHash, d1.hash]) await pub.waitForTransactionReceipt({ hash: h, timeout: 15000 }).catch(() => {});
    await sleep(800);
    eq("B11a money moved exactly once: C +2.00", usd((await bal(C)) - c0), "2.000000");
    const d3 = await post(RELAY, "/relay", body, nip()); ok("B12 L-1: a repeat AFTER mining gets the original hashes (dedupe kept 24 h), nothing moves again", d3.status === 200 && d3.hash === d1.hash && d3.feeHash === d1.feeHash && (await bal(C)) - c0 === 2n * U, JSON.stringify(d3));
    // revert must not give the allowance back: the payer empties the wallet after the relayer accepted the payment, so it reverts on chain
    const P = await newPayer(2n * U), dA = newDest(), aA = await payAuth(P, dA, 2n * U, FEE, R1.addr);
    await rpc("evm_setAutomine", [false]);
    const pbody = payBody(P, dA, 2n * U, FEE, R1.addr, aA);
    const pa = await post(RELAY, "/relay/pay", pbody, nip());
    ok("B11b the payment passes the simulation (unmined)", pa.status === 200, JSON.stringify(pa).slice(0, 200));
    await fundTok(P.address, 0n); await rpc("evm_setAutomine", [true]); await mine(2);
    let rv = false; for (let i = 0; i < 40 && !rv; i++) { rv = /reverted pay/.test(R1.log()); if (!rv) await sleep(500); }
    ok("B11b the payment reverted on chain", rv);
    { const pa2 = await post(RELAY, "/relay/pay", pbody, nip()); ok("B12 L-1: a pay retry after the (reverted) inclusion gets the original hash, not an error", pa2.status === 200 && pa2.hash === pa.hash, JSON.stringify(pa2)); }
    await sleep(500); const st3 = JSON.parse(fs.readFileSync(R1.state, "utf8"));
    ok("B11b the revert did NOT refund the payer's daily allowance (still 1)", st3.perPayer[P.address] === 1, JSON.stringify(st3.perPayer[P.address]));
    // IPv6: addresses of one /64 count as one network (R2 allows 3 per network)
    const v6 = async i => { const payer = await newPayer(), dd = newDest(), au = await payAuth(payer, dd, 2n * U, FEE, R2.addr); return post(RELAY2, "/relay/pay", payBody(payer, dd, 2n * U, FEE, R2.addr, au), "2001:db8:aaaa:bbbb:" + (i + 1) + "::" + (i + 7)); };
    const v6r = []; for (let i = 0; i < 4; i++) v6r.push(await v6(i));
    ok("B11c IPv6: 4 addresses in one /64 share the per-network cap (3 ok, 4th refused)", v6r.slice(0, 3).every(r => r.status === 200) && v6r[3].status === 400 && /too many requests/.test(v6r[3].error), JSON.stringify(v6r.map(r => r.status)));
    // log injection: a forged ALERT line must not become a line of its own
    await post(RELAY, "/relay/pay", { token: TOKEN, amount: "x\n2099-01-01T00:00:00.000Z ALERT forged line", stealth: C, eph: "0x02" + "11".repeat(32), viewTag: "0x11", fee: "0", feeRecipient: ZERO, auth: { from: C, r: "0x" + "11".repeat(32), s: "0x" + "11".repeat(32), v: 27, validBefore: "9999999999" } }, nip());
    const lg = R1.log().split("\n");
    ok("B11d log injection: no log line starts with the forged timestamp, the attempt is on one line", !lg.some(l => l.startsWith("2099-")) && lg.some(l => / refused .*forged line/.test(l)));
    // routing by the parsed pathname, not by the end of the raw URL
    const r1 = await fetch(RELAY + "/relay?x=/relay/pay", { method: "POST", body: "{}" }), r2 = await fetch(RELAY + "/relay/pay?x=/relay", { method: "POST", body: "{}" }), r3 = await fetch(RELAY + "/relay/stats?x=1");
    ok("B11e POST with a query string is not routed (404); GET /relay/stats with a query still works", r1.status === 404 && r2.status === 404 && r3.status === 200, [r1.status, r2.status, r3.status].join()); }

  // B12 audit 1099: log tokens (M-1), failure budgets (M-2), no-RPC validation, nonce-retry without a second send (L-2), RPC errors are not "dropped" (L-3)
  { const knownWait = async a => { for (let i = 0; i < 60 && !(await known(a)); i++) await sleep(500); };
    const pyCount = (lines) => Number(spawnSync("python3", ["-B", "-c", "import sys,importlib.util\nspec=importlib.util.spec_from_file_location('w',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\nprint(sum(1 for l in sys.stdin.read().splitlines() if m.LOG_TEMPLATE.match(l)))", path.join(HERE, "stealth_watch.py")], { input: lines.join("\n"), encoding: "utf8" }).stdout);
    // M-1: hostile tokens in the request must not become watchdog lines
    await post(RELAY, "/relay", "ALERT", nip()); await post(RELAY, "/relay", { from: "ALERT", to: C }, nip()); await post(RELAY, "/relay", { from: C, to: C, endRecipient: "reverted" }, nip());
    await post(RELAY, "/relay/pay", { token: TOKEN, amount: "ALERT", stealth: C, eph: "0x02" + "11".repeat(32), viewTag: "0x11", fee: "0", feeRecipient: ZERO, auth: { from: C, r: "0x" + "11".repeat(32), s: "0x" + "11".repeat(32), v: 27, validBefore: "9999999999" } }, nip());
    await post(RELAY, "/relay", '{"from":"ALERT relayer balance low"}', nip());
    const refusedLn = R1.log().split("\n").filter(l => / refused /.test(l)), hostile = refusedLn.filter(l => /A_LERT|rev_erted/.test(l));
    ok("B12 M-1 hostile ALERT / reverted tokens are broken up in the log (no raw ALERT or reverted in any refused line)", hostile.length >= 2 && refusedLn.every(l => !/ALERT|reverted/i.test(l.replace(/A_LERT|rev_erted/gi, ""))), hostile.length + " lines");
    eq("B12 M-1 the watchdog's fixed templates match none of the refused lines", pyCount(refusedLn), 0);
    eq("B12 M-1 ...but still match the real ones (ALERT relayer balance low / reverted main)", pyCount(["2026-10-29T10:00:00.000Z ALERT relayer balance low: 0.1 ETH", "2026-10-29T10:00:00.000Z reverted main 0x" + "ab".repeat(32), "2026-10-29T10:00:00.000Z refused 1.2.3.4 \"ALERT relayer balance low\"", "2026-10-29T10:00:00.000Z ALERT anything the client typed"]), 2);
    // M-2 / I-5 / status: unknown hashes cost no RPC, anchored route
    { const sj = await fetch(RELAY + "/relay/status?hash=0x" + "ab".repeat(32)); ok("B12 M-2 /relay/status answers only for hashes the relayer sent", sj.status === 400 && /unknown hash/.test((await sj.json()).error)); }
    { const sl = await fetch(RELAY + "/relay/sanctions-list"), j = await sl.json();
      ok("B12 GET /relay/sanctions-list: lowercase address array + updated/count + cache header, includes the test entry", sl.status === 200 && /max-age/.test(sl.headers.get("cache-control") || "") && j.count === j.addresses.length && j.addresses.includes(sanctioned.toLowerCase()) && j.addresses.every(a => a === a.toLowerCase()) && "updated" in j, JSON.stringify(j).slice(0, 150)); }
    ok("B12 I-5 a path that only ENDS in /relay/stats is not routed", (await fetch(RELAY.replace("/stealth-api", "/x/stealth-api") + "/relay/stats")).status === 404);
    // M-2 state writes: a failing request writes nothing synchronously and leaves no zero keys behind
    const p3 = await freePort(), R3 = await startRelayer("r3", p3, { STEALTH_RELAY_FAIL_PER_IP: "5", STEALTH_RELAY_REFUSED_LOG_PER_MIN: "20" }), RELAY3 = "http://127.0.0.1:" + p3 + "/stealth-api";
    { const P0 = await newPayer(0n), dd = newDest(), au = await payAuth(P0, dd, 2n * U, FEE, R3.addr), body = payBody(P0, dd, 2n * U, FEE, R3.addr, au);
      const r = await post(RELAY3, "/relay/pay", body, "3.3.3.3");
      ok("B12 M-2 a request that fails after the counters were taken: 400 and NO synchronous state write", r.status === 400 && /holds less/.test(r.error) && !fs.existsSync(R3.state), JSON.stringify(r));
      await sleep(2500);
      const j = fs.existsSync(R3.state) ? JSON.parse(fs.readFileSync(R3.state, "utf8")) : null;
      ok("B12 M-2 ...the state is flushed a moment later, and the counters of the failed request are gone (no zero keys)", j && !("3.3.3.3" in j.perIp) && !(P0.address in j.perPayer), JSON.stringify(j).slice(0, 160)); }
    // per-network failure budget (5/hour on R3), independent of nginx; the /64 is one network
    { const junk = ip => post(RELAY3, "/relay", { garbage: 1 }, ip);
      const a = []; for (let i = 0; i < 6; i++) a.push(await junk("4.4.4.4"));
      ok("B12 M-2 per-IP failure budget: 5 failures answered 400, the 6th is refused with 429 before any work", a.slice(0, 5).every(r => r.status === 400) && a[5].status === 429 && /too many failed/.test(a[5].error), a.map(r => r.status).join());
      ok("B12 M-2 ...another network is not affected", (await junk("4.4.4.5")).status === 400);
      const b = []; for (let i = 0; i < 5; i++) b.push(await junk("2001:db8:9:9:" + (i + 1) + "::1")); b.push(await junk("2001:db8:9:9:ffff::5"));
      ok("B12 M-2 IPv6: failures from different addresses of one /64 share the budget", b.slice(0, 5).every(r => r.status === 400) && b[5].status === 429, b.map(r => r.status).join());
      const many = []; for (let i = 0; i < 30; i++) many.push(await junk("5.5." + i + ".1"));
      const nref = R3.log().split("\n").filter(l => / refused /.test(l)).length;
      ok("B12 M-2 refusal log lines are rate limited (30 more failures: still at most 20 'refused' lines in the minute), requests still answered", many.every(r => r.status === 400) && nref <= 20 && nref >= 10, "lines " + nref); }
    // global failure rate (audit 1107 M-1): only RPC-COSTLY failures (passed the offline checks: here a signed payment from an empty wallet) count; offline junk does not
    { const p5 = await freePort(), R5 = await startRelayer("r5", p5, { STEALTH_RELAY_FAIL_PER_MIN: "8" }), RELAY5 = "http://127.0.0.1:" + p5 + "/stealth-api";
      for (let i = 0; i < 40; i++) await post(RELAY5, "/relay", { garbage: 1 }, "6.0.1." + i);
      const junkFresh = await post(RELAY5, "/relay", { garbage: 1 }, "6.0.9.9"), junkAgain = await post(RELAY5, "/relay", { garbage: 1 }, "6.0.1.0");
      ok("B12 1107 M-1 40 offline-rejected junk requests from 40 networks do not trip the global ceiling: a failed-before network and a fresh one are both still answered 400", junkFresh.status === 400 && junkAgain.status === 400, junkFresh.status + "/" + junkAgain.status);
      const costly = async ip => { const P0 = await newPayer(0n), dd = newDest(), au = await payAuth(P0, dd, 2n * U, FEE, R5.addr); return post(RELAY5, "/relay/pay", payBody(P0, dd, 2n * U, FEE, R5.addr, au), ip); };
      for (let i = 0; i < 10; i++) await costly("6.1.1." + i);
      const again = await post(RELAY5, "/relay", { garbage: 1 }, "6.1.1.0"), fresh = await post(RELAY5, "/relay", { garbage: 1 }, "6.1.2.1");
      ok("B12 M-2 global failure rate (costly failures): a network that already failed is refused (429), a clean one is still served (400)", again.status === 429 && /busy/.test(again.error) && fresh.status === 400, again.status + "/" + fresh.status); }
    // fault-injecting RPC in front of anvil, for R4: counts calls, can fail receipt reads, can answer a send with an error AFTER it was accepted
    const fault = { calls: 0, failReads: false, dupErr: null, failCalls: false, hide: 0 };
    const fwd = async o => { fault.calls++; if (fault.failCalls && o.method === "eth_call") return { jsonrpc: "2.0", id: o.id, error: { code: -32603, message: "internal error" } };
      if (fault.hide > 0 && /^eth_getTransaction(Receipt|ByHash)$/.test(o.method)) { fault.hide--; return { jsonrpc: "2.0", id: o.id, result: null }; }   // 1107 L-2: our own transaction is "not visible yet" on this backend
      if (fault.failReads && /^eth_getTransaction(Receipt|ByHash)$/.test(o.method)) return { jsonrpc: "2.0", id: o.id, error: { code: -32005, message: "rate limited" } };
      const j = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(o) }).then(r => r.json());
      if (o.method === "eth_sendRawTransaction" && fault.dupErr && !j.error) return { jsonrpc: "2.0", id: o.id, error: { code: -32000, message: fault.dupErr } };
      return j; };
    const fproxy = httpServer.createServer((q, r) => { let b = ""; q.on("data", c => b += c); q.on("end", async () => { try { const j = JSON.parse(b); const out = Array.isArray(j) ? await Promise.all(j.map(fwd)) : await fwd(j); r.writeHead(200, { "content-type": "application/json" }); r.end(JSON.stringify(out)); } catch (e) { r.writeHead(502); r.end(String(e)); } }); });
    const fpPort = await freePort(); await new Promise(r => fproxy.listen(fpPort, "127.0.0.1", r)); procs.push({ kill: () => fproxy.close() });
    const p4 = await freePort(), R4 = await startRelayer("r4", p4, { STEALTH_RPC: "http://127.0.0.1:" + fpPort, STEALTH_RELAY_STUCK_S: "3", STEALTH_RELAY_GONE_GAP_MS: "1000" }), RELAY4 = "http://127.0.0.1:" + p4 + "/stealth-api";
    await rpc("evm_setAutomine", [true]); await mine(1);
    for (const k of ["alk", "ntl", "rd", "lst", "pl1", "pl2"]) await knownWait(W[k].stealth);
    // cheap validation: bad signature / expired authorization are refused with ZERO RPC calls (and no address lock taken)
    { const c0 = fault.calls, bad = await post(RELAY4, "/relay", await wbody(W.alk.stealth, C, 2n * U, null, { domain: { chainId: 1 } }), nip());
      const P = await newPayer(), dd = newDest(), au = await payAuth(P, dd, 2n * U, FEE, R4.addr, { domain: { chainId: 1 } }), badPay = await post(RELAY4, "/relay/pay", payBody(P, dd, 2n * U, FEE, R4.addr, au), nip());
      const exp = await post(RELAY4, "/relay", await wbody(W.alk.stealth, C, 2n * U, null, { validBefore: now() + 5 }), nip());
      ok("B12 M-2 forged signature / expired authorization: refused with no RPC call at all (withdraw and pay)", bad.status === 400 && /signature does not match/.test(bad.error) && badPay.status === 400 && /signature does not match/.test(badPay.error) && exp.status === 400 && /expires too soon/.test(exp.error) && fault.calls === c0, fault.calls - c0 + " calls; " + bad.error + " | " + badPay.error + " | " + exp.error); }
    // audit 1102 L-3: a high-s signature (valid for ecrecover, rejected by the token) is refused offline, with ZERO RPC calls (withdraw main, withdraw fee, pay)
    { const flip = x => ({ ...x, s: "0x" + (SECP_N - BigInt(x.s)).toString(16).padStart(64, "0"), v: x.v === 27 ? 28 : 27 });
      const c0 = fault.calls, w0 = await wbody(W.alk.stealth, C, 2n * U, null), w1 = await wbody(W.alk.stealth, C, 2n * U, 100000n);
      const hs = await post(RELAY4, "/relay", { ...w0, ...flip(w0) }, nip()), hf = await post(RELAY, "/relay", { ...w1, feeAuth: { ...w1.feeAuth, ...flip(w1.feeAuth) } }, nip());
      const P = await newPayer(), dd = newDest(), au = await payAuth(P, dd, 2n * U, FEE, R4.addr), hp = await post(RELAY4, "/relay/pay", payBody(P, dd, 2n * U, FEE, R4.addr, { ...au, sig: flip(au.sig) }), nip());
      ok("B12 1102 L-3 high-s signature (main, fee via the fee-enabled relayer, pay): refused offline; the R4 calls make no RPC", [hs, hf, hp].every(x => x.status === 400 && /high s/.test(x.error)) && fault.calls === c0, fault.calls - c0 + " calls; " + hs.error + " | " + hf.error + " | " + hp.error);
      ok("B12 1102 L-3 isLowS unit: n/2 ok, n/2+1 and 0 rejected", isLowS("0x" + (SECP_N / 2n).toString(16)) && !isLowS("0x" + (SECP_N / 2n + 1n).toString(16)) && !isLowS("0x" + "0".repeat(64)));
      // M-1: a self-signed payment from an EMPTY wallet costs ONE cheap read (balanceOf), not five
      const E0 = await newPayer(0n), de = newDest(), ae = await payAuth(E0, de, 2n * U, FEE, R4.addr), c1 = fault.calls, pe = await post(RELAY4, "/relay/pay", payBody(E0, de, 2n * U, FEE, R4.addr, ae), nip());
      ok("B12 1102 M-1 pay from an empty wallet: refused after exactly one RPC read", pe.status === 400 && /holds less/.test(pe.error) && fault.calls - c1 === 1, fault.calls - c1 + " calls; " + pe.error); }
    // L-2: the node accepted our transaction but the answer was an error ("already known" / "nonce too low"): no second send, the ORIGINAL hash is returned
    for (const [k, err] of [["alk", "already known"], ["ntl", "nonce too low"], ["lst", "upstream request timeout"]]) {
      const c0 = await bal(C), n0 = await nonceOf(R4.addr); fault.dupErr = err;
      const w = await post(RELAY4, "/relay", await wbody(W[k].stealth, C, 2n * U, null), nip()); fault.dupErr = null;
      let rc = null; if (w.hash) rc = await pub.waitForTransactionReceipt({ hash: w.hash, timeout: 15000 }).catch(() => null);
      await sleep(1200);
      ok("B12 L-2 '" + err + "' after an accepted send: success with the original hash, exactly one transaction, money moved once", w.status === 200 && rc && rc.status === "success" && (await nonceOf(R4.addr)) - n0 === 1 && (await bal(C)) - c0 === 2n * U && !/reverted/.test(R4.log()), JSON.stringify(w) + " nonce+" + ((await nonceOf(R4.addr)) - n0)); }
    // L-3: an RPC error while asking for the receipt is "unknown", not "dropped": no gap fill, no replacement of a live transaction
    { const c0 = await bal(C), n0 = await nonceOf(R4.addr);
      await rpc("evm_setAutomine", [false]); fault.failReads = true;
      const w = await post(RELAY4, "/relay", await wbody(W.rd.stealth, C, 2n * U, null), nip());
      await sleep(9000);
      const lg = R4.log();
      ok("B12 L-3 receipt reads failing (RPC errors): the live transaction is NOT treated as dropped (no 'dropped', no gap fill), nonce untouched", w.status === 200 && !/dropped|nonce gap filled/.test(lg) && (await nonceOf(R4.addr)) === n0, JSON.stringify(w) + " " + lg.split("\n").slice(-3).join(" | ").slice(0, 200));
      fault.failReads = false; await rpc("evm_setAutomine", [true]); await mine(2);
      const rc = await pub.waitForTransactionReceipt({ hash: w.hash, timeout: 15000 }).catch(() => null); await sleep(800);
      ok("B12 L-3 ...and it still executes exactly once", rc && rc.status === "success" && (await bal(C)) - c0 === 2n * U, usd((await bal(C)) - c0)); }
    // 1107 M-1: an RPC outage answers 503 "network busy" and consumes NO failure budget (35 > the 30/hour per-network budget), so honest users are not locked out afterwards
    { const P = await newPayer(), ip = "9.8.7.6"; fault.failCalls = true; const codes = [];
      for (let i = 0; i < 35; i++) { const dd = newDest(), au = await payAuth(P, dd, 2n * U, FEE, R4.addr); const r = await post(RELAY4, "/relay/pay", payBody(P, dd, 2n * U, FEE, R4.addr, au), ip); codes.push(r.status + (r.status === 503 && /network busy/.test(r.error) ? "" : "!")); }
      fault.failCalls = false;
      const dd = newDest(), au = await payAuth(P, dd, 2n * U, FEE, R4.addr), after = await post(RELAY4, "/relay/pay", payBody(P, dd, 2n * U, FEE, R4.addr, au), ip);
      ok("B12 1107 M-1 RPC outage: 35 requests from one network all 503 'network busy' (no 429), and the same network is served as soon as the RPC is back", codes.every(c => c === "503") && after.status === 200 && !!after.hash, codes.slice(0, 5).join() + " ... " + JSON.stringify(after)); }
    // 1107 L-2: ambiguous send error + our transaction not visible on the first poll: polled again ~1 s later, found, the ORIGINAL hash returned, exactly one transaction
    { const c0 = await bal(C), n0 = await nonceOf(R4.addr); fault.dupErr = "upstream request timeout"; fault.hide = 2; const t0 = Date.now();
      const w = await post(RELAY4, "/relay", await wbody(W.pl1.stealth, C, 2n * U, null), nip()); const dt = Date.now() - t0; fault.dupErr = null; fault.hide = 0;
      let rc = null; if (w.hash) rc = await pub.waitForTransactionReceipt({ hash: w.hash, timeout: 15000 }).catch(() => null); await sleep(800);
      ok("B12 1107 L-2 timeout + transaction invisible on poll 1: found on a later poll (>= ~1 s), success, one transaction, money moved once", w.status === 200 && dt >= 900 && dt < 7000 && rc && rc.status === "success" && (await nonceOf(R4.addr)) - n0 === 1 && (await bal(C)) - c0 === 2n * U, dt + " ms " + JSON.stringify(w)); }
    // ... still invisible after all 3 polls: bounded (lock not held beyond the deadline), 503; the retry of the SAME authorization never signs a second transaction
    { const c0 = await bal(C), n0 = await nonceOf(R4.addr); await rpc("evm_setAutomine", [false]);
      const body = await wbody(W.pl2.stealth, C, 2n * U, null); fault.dupErr = "upstream request timeout"; fault.hide = 1000; const t0 = Date.now();
      const w1 = await post(RELAY4, "/relay", body, nip()); const dt = Date.now() - t0; fault.dupErr = null; fault.hide = 0;
      ok("B12 1107 L-2 all 3 polls miss: 503 within the recovery deadline (lock hold bounded: 2 gaps of ~1 s, < 7 s)", w1.status === 503 && dt >= 1800 && dt < 7000, dt + " ms " + JSON.stringify(w1));
      const w2 = await post(RELAY4, "/relay", body, nip());
      await rpc("evm_setAutomine", [true]); await mine(2);
      let rc = null; if (w2.hash) rc = await pub.waitForTransactionReceipt({ hash: w2.hash, timeout: 15000 }).catch(() => null); await sleep(800);
      ok("B12 1107 L-2 retry of the same authorization finds the first transaction (same tx, no second send): one transaction on chain, money moved once", w2.status === 200 && rc && rc.status === "success" && (await nonceOf(R4.addr)) - n0 === 1 && (await bal(C)) - c0 === 2n * U, JSON.stringify(w2) + " nonce+" + ((await nonceOf(R4.addr)) - n0) + " | " + R4.log().split("\n").slice(-4).join(" / ").slice(-400)); }
  }

  // ===================================================================================== B13) audit 1102 units
  sect("B13) 1102 M-1 / L-1 units: shared ceiling, honest-refusal weight, nginx map");
  { let t = 0; const fb = makeFailBudget({ perKey: 30, perMin: 10, now: () => t });
    for (let i = 0; i < 20; i++) fb.fail("k" + i, 1, true);                              // 20 distinct networks with RPC-costly failures in one minute (hardMin = 2 x perMin)
    ok("1102/1107 M-1 shared ceiling: a network with NO earlier failure is refused once RPC-costly failures hit the ceiling", fb.check("fresh") !== null && /busy/.test(fb.check("fresh")) && fb.check("k0") !== null);
    fb.ok("honest");
    ok("1107 M-1 ...but a key with a recent success keeps reserved capacity (also a key that failed before)", fb.check("honest") === null && (fb.ok("k0"), fb.check("k0")) === null);
    const fbj = makeFailBudget({ perKey: 30, perMin: 10, now: () => t });
    for (let i = 0; i < 40; i++) for (let j = 0; j < 30; j++) fbj.fail("junk" + i, 1, false);   // 1200 offline-rejected junk requests from 40 networks
    ok("1107 M-1 offline-rejected junk never trips the global ceiling: a fresh key is served; the junk keys hit their own per-key budget", fbj.check("fresh") === null && fbj.check("junk0") !== null && /too many failed/.test(fbj.check("junk0")));
    const fb2 = makeFailBudget({ perKey: 30, perMin: 10, now: () => t });
    for (let i = 0; i < 12; i++) fb2.fail("k" + i, 1, true);
    ok("1102 M-1 below the ceiling a clean network still passes while a failed one is refused", fb2.check("fresh") === null && fb2.check("k0") !== null);
    t += 61_000; ok("1102 M-1 the window resets after a minute", fb.check("fresh") === null);
    const fb3 = makeFailBudget({ perKey: 30, now: () => t });
    const honest = new Refusal("a withdrawal from this address is already in progress", { honest: true });
    for (let i = 0; i < 100; i++) fb3.fail("shared", failWeight(honest));
    ok("1102 L-1 100 honest-state refusals (in progress) do not lock a shared network (weight 0.2 -> 20 < 30)", fb3.check("shared") === null);
    for (let i = 0; i < 30; i++) fb3.fail("shared", failWeight(new Error("signature does not match the address")));
    ok("1102 L-1 ...but forged-input refusals still do", fb3.check("shared") !== null && failWeight(new Error("signature does not match the address")) === 1 && failWeight(honest) < 1);
    // 1107 L-1: weight by error CLASS, never by text: a plain Error / SyntaxError whose text contains an "honest" phrase weighs 1
    ok("1107 L-1 failWeight ignores message text: plain Error / SyntaxError / strings with 'fee below', 'holds less', 'gas budget' weigh 1; only Refusal{honest} weighs 0.2",
      ["fee below", "holds less", "gas budget"].every(m => failWeight(new Error(m)) === 1 && failWeight(m) === 1) && failWeight(new Refusal("holds less", { costly: true })) === 1
      && failWeight((() => { try { BigInt("fee below"); } catch (e) { return e; } })()) === 1 && failWeight(new Refusal("x", { honest: true, costly: true })) === 0.2);
    const src = fs.readFileSync(path.join(HERE, "relayer.mjs"), "utf8");
    ok("1107 L-1 relayer.mjs: no message-based classification left (no HONEST_REFUSAL / failWeight(msg))", !/HONEST_REFUSAL|failWeight\(msg\)/.test(src) && /failWeight\(e\)/.test(src)); }
  { // the nginx map in deploy/stealth-rh.conf, evaluated in JS (same regex dialect for these constructs): every spelling of one /64 must give one key, and agree with the relayer's ipKey()
    const conf = fs.readFileSync(path.join(HERE, "deploy/stealth-rh.conf"), "utf8");
    const rules = [...conf.matchAll(/^#\s+~(\S+)\s+(\S+);\s*$/gm)].map(m => [new RegExp(m[1]), m[2]]);
    const key = a => { for (const [re, v] of rules) { const m = a.match(re); if (m) return v.replace(/\$(\w+)/g, (_, n) => m.groups?.[n] ?? "$" + n); } return a; };
    const same = [["2001:db8:abcd:1::5", "2001:db8:abcd:1:0:0:0:9"], ["2001:db8:abcd::5", "2001:db8:abcd:0:1::7", "2001:db8:abcd::9999"], ["2001:db8::5", "2001:db8:0:0:3::1"], ["2001::5", "2001:0:0:0:8:8:8:8"], ["::5", "0:0:0:0:1:2:3:4"],
      ["1::2:3:4:5:6:7", "1:0:2:3:4:5:6:7"], ["1:2::4:5:6:7:8", "1:2:0:4:5:6:7:8"], ["::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8"], ["1:2:3::5:6:7:8", "1:2:3:0:5:6:7:8"]];
    ok("1102 M-1 nginx map has its rules", rules.length >= 6, String(rules.length));
    ok("1102 M-1 nginx map: all spellings of one /64 share a key, also with '::' in the first four groups", same.every(g => new Set(g.map(key)).size === 1), same.map(g => g.map(key).join("=")).join(" ; "));
    ok("1102 M-1 nginx map: different /64s differ; IPv4 and IPv4-mapped IPv6 are the IPv4 address; same bucketing as ipKey()", key("2001:db8:abcd::5") !== key("2001:db8:abce::5") && key("::ffff:1.2.3.4") === "1.2.3.4" && key("1.2.3.4") === "1.2.3.4"
      && same.every(g => new Set(g.map(ipKey)).size === 1));
    ok("1107 I-1 single zero group compressed by '::' (1::2:3:4:5:6:7): distinct /64s stay distinct (1:0:2:3 vs 1:0:9:3 vs 1:0:0:0)", key("1::2:3:4:5:6:7") === "1:0:2:3" && key("1::9:3:4:5:6:7") === "1:0:9:3" && key("1::") === "1:0:0:0" && key("2001:db8::7:8:9:a:b") === "2001:db8:0:7");
    const loc = conf.split(/^location /m);
    const sl = loc.find(b => /^= \/stealth-api\/rh\/relay\/sanctions-list/.test(b)), other = loc.find(b => /^~ \^\/stealth-api\/rh\/relay\/\(stats/.test(b));
    ok("1107 I-2 /relay/sanctions-list has its own location without hide_header / no-store, so the relayer's 5-minute cache header reaches the browser; the other GETs still hide it",
      sl && !/proxy_hide_header|no-store/.test(sl.replace(/#.*$/gm, "")) && other && !/sanctions-list/.test(other.split("\n")[0]) && /proxy_hide_header Cache-Control/.test(other)); }

  // 1107 I-3: the watchdog tracks the log's inode: a rotated file that has regrown PAST the old offset is read from its start
  { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "stw-")), lg = path.join(dir, "r.log");
    const py = `import sys,json,os,importlib.util
spec=importlib.util.spec_from_file_location('w',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
lg=sys.argv[2]; c={'name':'base','idx':'http://127.0.0.1:1','rel':'http://127.0.0.1:1','log':lg,'min_eth':0.0}; st={'alerts':{},'log_pos':{}}
A=lambda i:'2026-10-29T10:00:00.000Z ALERT relayer balance low: %d ETH\\n'%i
def run(): return sorted(k for k in m.check_chain(c,st) if ':log-' in k)
open(lg,'w').write('x'*10+'\\n'); r0=run()
open(lg,'a').write(A(1)); r1=run()
os.rename(lg,lg+'.1'); open(lg,'w').write(A(2)+A(3)+A(4)+A(5)+'y\\n'); r2=run()
print(json.dumps([r0,r1,r2]))`;
    const o = spawnSync("python3", ["-B", "-c", py, path.join(HERE, "stealth_watch.py"), lg], { encoding: "utf8" });
    let r = null; try { r = JSON.parse(o.stdout); } catch {}
    ok("1107 I-3 watchdog: first run reads nothing, a new ALERT is seen, and after a rotation the regrown file (larger than the old offset) is still read from its start", r && r[0].length === 0 && r[1].length === 1 && r[2].length === 1, (o.stdout + o.stderr).slice(0, 300));
    fs.rmSync(dir, { recursive: true, force: true }); }

  // ===================================================================================== C) UI pay amount
  sect("C) UI pay amount: 'you pay 10' = 10 leaves the wallet");
  { const fee = FEE, f = (src, text, dec = 6) => payAmounts({ src, text, decimals: dec, fee });
    ok("C1 'you pay 10' -> send 10.00, receiver gets 9.95", f("amount", "10")?.send === 10n * U && f("amount", "10")?.get === 9_950_000n);
    ok("C1 'receiver gets 10' -> send 10.05 (only when typed in the other field)", f("amount-get", "10")?.send === 10_050_000n && f("amount-get", "10")?.get === 10n * U);
    ok("C1 exact decimals (no float drift): 0.1, 1.005, 4.35, 123456.789012", [["0.1", 100000n], ["1.005", 1005000n], ["4.35", 4350000n], ["123456.789012", 123456789012n]].every(([t, v]) => f("amount", t)?.send === v));
    ok("C1 junk / zero / negative -> null; below fee -> get <= 0", f("amount", "") === null && f("amount", "0") === null && f("amount", "-5") === null && f("amount", "abc") === null && f("amount", "0.04").get < 0n);
    // on-chain: the exact amounts from the UI math through the relayer
    const P = await newPayer(50n * U), dd = newDest(), p0 = await bal(P.address), r0 = await bal(R1.addr), a = f("amount", "10");
    const au = await payAuth(P, dd, a.send, fee, R1.addr), r = await post(RELAY, "/relay/pay", payBody(P, dd, a.send, fee, R1.addr, au), nip());
    if (r.hash) await pub.waitForTransactionReceipt({ hash: r.hash });
    eq("C2 payer balance fell by exactly 10.000000", usd(p0 - await bal(P.address)), "10.000000");
    eq("C2 receiver got 9.950000, relayer 0.050000", usd(await bal(dd.stealth)) + "/" + usd((await bal(R1.addr)) - r0), "9.950000/0.050000");
    const msgSrc = fs.readFileSync(path.join(HERE, "../web/app.js"), "utf8");
    ok("C3 app.js passes the exact raw send amount to payGasless (no float round trip, no +fee on top)", /payStealth\(\{ token, amount, raw: token === "TOKEN" \? a\.send : null/.test(msgSrc) && /const raw = rawIn \?\? BigInt/.test(msgSrc) && !/raw \+ fee/.test(msgSrc.slice(msgSrc.indexOf("async function payGasless"), msgSrc.indexOf("// ---- amount: two linked"))));
  }
  // ===================================================================================== D) front proxy rate limit (nginx 503, non-JSON)
  sect("D) nginx 503 (non-JSON) -> Busy, retrying");
  { const mk = seq => { let i = 0; const calls = []; const f = async (u, o) => { calls.push(u); const x = seq[Math.min(i++, seq.length - 1)]; return { ok: x.s < 300, status: x.s, json: async () => { if (x.body === undefined) throw new SyntaxError("Unexpected token < in JSON"); return x.body; } }; }; f.calls = calls; return f; };
    const waits = [], msgs = [], opt = { sleep: async ms => { waits.push(ms); }, onBusy: m => msgs.push(m) };
    const f1 = mk([{ s: 503 }, { s: 503 }, { s: 200, body: { hash: "0xabc" } }]);
    const r1 = await postRelay(f1, "http://x/relay", { a: 1 }, opt);
    ok("D1 two 503 HTML bodies then 200: retried automatically, result returned", r1.r.ok && r1.d.hash === "0xabc" && f1.calls.length === 3);
    ok("D1 friendly 'Busy, retrying' message shown, exponential backoff 2s,4s", msgs.length === 2 && /Busy, retrying/.test(msgs[0]) && waits.join() === "2000,4000");
    waits.length = 0; const f2 = mk([{ s: 503 }]);
    const e2 = await postRelay(f2, "u", {}, opt).then(() => null, e => e);
    ok("D2 persistent 503: gives up after 5 retries with a clear message (no JSON parse error)", e2 && /busy/i.test(e2.message) && !/JSON|Unexpected/.test(e2.message) && f2.calls.length === 6 && waits.join() === "2000,4000,8000,16000,30000");
    const f3 = mk([{ s: 400, body: { error: "fee out of range" } }]); const r3 = await postRelay(f3, "u", {}, opt);
    ok("D3 a real relayer error (JSON 400) is returned at once, never retried", r3.d.error === "fee out of range" && f3.calls.length === 1);
    const f4 = mk([{ s: 429 }, { s: 200, body: { hash: "0x1" } }]); ok("D4 429 is retried too", (await postRelay(f4, "u", {}, opt)).d.hash === "0x1");
    const src = ["app.js", "private-withdraw.js", "zec-hop.js"].map(f => fs.readFileSync(path.join(HERE, "../web", f), "utf8")).join("\n");
    ok("D5 every web call site of /relay and /relay/pay goes through postRelay", (src.match(/postRelay\(/g) || []).length === 4 && !/fetch\w*\(\s*(ctx\.)?API \+ "\/relay|fetchFn\(ctx\.api \+ "\/relay/.test(src)); }
  finish(summary());
} catch (e) { console.log("ERROR", e && e.stack || e); rows.push({ g: "!", name: "suite crashed: " + String(e && e.message || e).slice(0, 80), pass: false }); finish(summary() || 2); }

function summary() {
  const bad = rows.filter(r => !r.pass);
  console.log("\n==== RESULT TABLE ====");
  for (const g of ["A", "B", "C", "D", "!"]) { const rs = rows.filter(r => r.g === g); if (rs.length) console.log(g + ": " + rs.filter(r => r.pass).length + "/" + rs.length + " pass" + rs.filter(r => !r.pass).map(r => "\n   FAIL " + r.name + (r.extra ? "  [" + r.extra + "]" : "")).join("")); }
  console.log(bad.length ? "SUITE FAIL (" + bad.length + " failing of " + rows.length + ")" : "SUITE PASS (" + rows.length + " checks)");
  return bad.length ? 1 : 0;
}
