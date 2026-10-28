/* Локальный тест релеера на форке Robinhood Chain (anvil). Запуск: node test_local.mjs   (нужны foundry/anvil и сеть до RPC)
   Родитель поднимает anvil и гоняет сценарии дочерними процессами (каждый -- свежий import relayer.mjs со своим окружением).
   Ничего не деплоит и не шлёт в живую цепь: деньги токена берутся импёрсонацией чужого адреса на форке. */
import { spawn, spawnSync } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http";
import { fileURLToPath } from "url";
const HERE = path.dirname(fileURLToPath(import.meta.url)); const ME = fileURLToPath(import.meta.url);
const PORT = 8645, RPC = "http://127.0.0.1:" + PORT;
const TOKEN = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", HOLDER = "0x0000000000000000000000000000000000000001";
const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });

if (process.argv[2] === "child") await child(process.argv[3]); else await parent();

async function parent() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-t-"));
  const anvil = spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(PORT), "--silent"], { stdio: "inherit" });
  for (let i = 0; i < 60; i++) { try { await rpc("eth_chainId"); break; } catch { await new Promise(r => setTimeout(r, 500)); } }
  console.log("anvil fork chainId", parseInt(await rpc("eth_chainId"), 16), "block", parseInt(await rpc("eth_blockNumber"), 16));
  const run = (sc, env = {}, state = "s_" + sc) => { env = { STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000", ...env };
    const r = spawnSync("node", [ME, "child", sc], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTH_RELAY_STATE: path.join(tmp, state + ".json"), STEALTH_RELAY_LOG: path.join(tmp, sc + ".log"), RELAYER_KEY: "", ...env }, encoding: "utf8", timeout: 120000 });
    process.stdout.write(r.stdout.split("\n").filter(l => l.startsWith("T:")).join("\n") + "\n"); if (r.status) { console.log("CHILD FAILED", r.stderr.slice(-800), r.stdout.slice(-400)); }
    return r;
  };
  try {
    if (process.env.ONLY) { run(process.env.ONLY, { STEALTH_RELAY_STUCK_S: "3" }); return; }
    console.log("== 1. параллельные запросы с одного from -> принят ровно один");
    run("concurrent", { STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000" }, "shared");
    console.log("== 2. рестарт (новый процесс, тот же файл) -> лимит суток сохранён");
    run("restart", {}, "shared");
    console.log("== 3. резерв бюджета: 4 параллельных заявки с разных from при бюджете ~1.2 транзакции");
    const e = run("budget", {}); const est = BigInt(/EST (\d+)/.exec(e.stdout)[1]);
    run("budget2", { STEALTH_RELAY_GAS_BUDGET_WEI: String(est * 12n / 10n) });
    console.log("== 4. комиссия feeAuth включена (FEE_MIN=0.1)");
    run("fee", { STEALTH_RELAY_FEE_MIN: "100000" });
    console.log("== 5. порог баланса релеера -> отказ + ALERT");
    run("lowbal", { STEALTH_RELAY_MIN_BALANCE_WEI: "999999999999999999999" });
    console.log("== 6. застрявшая транзакция -> замена тем же nonce");
    run("stuck", { STEALTH_RELAY_STUCK_S: "3" });
  } finally { if (process.env.KEEP) console.log("anvil left running pid", anvil.pid); else anvil.kill(); }
}

async function child(sc) {
  // свой индексатор-заглушка: known только для зарегистрированных адресов
  const known = new Set();
  const stub = http.createServer((q, s) => { const a = (new URL(q.url, "http://x").searchParams.get("addr") || "").toLowerCase(); s.end(JSON.stringify({ known: known.has(a) })); });
  await new Promise(r => stub.listen(0, "127.0.0.1", r));
  const { generatePrivateKey, privateKeyToAccount } = await import("viem/accounts");
  const { parseEther, toHex, getAddress } = await import("viem");
  process.env.STEALTH_INDEXER = "http://127.0.0.1:" + stub.address().port;
  const rk = generatePrivateKey(); process.env.RELAYER_KEY = rk;
  if (sc === "restart") process.env.RELAYER_KEY = fs.readFileSync(path.join(os.tmpdir(), "stealth-t-relayer.key"), "utf8");
  else if (sc === "concurrent") fs.writeFileSync(path.join(os.tmpdir(), "stealth-t-relayer.key"), rk, { mode: 0o600 });
  const R = await import("./relayer.mjs");
  const out = (...a) => console.log("T:", ...a);
  await rpc("anvil_setBalance", [R.account.address, toHex(parseEther("1"))]);
  await rpc("anvil_setBalance", [HOLDER, toHex(parseEther("1"))]); await rpc("anvil_impersonateAccount", [HOLDER]);
  const { encodeFunctionData, parseAbi, createPublicClient, http: vh } = await import("viem");
  const erc = parseAbi(["function transfer(address,uint256) returns (bool)", "function balanceOf(address) view returns (uint256)"]);
  const bal = (a) => R.pub.readContract({ address: TOKEN, abi: erc, functionName: "balanceOf", args: [a] });
  async function newStealth(usdg = 400_000n) {                     // свежий ключ, на нём USDG, зарегистрирован как known
    const pk = generatePrivateKey(), acc = privateKeyToAccount(pk);
    const eth = await rpc("eth_getBalance", [HOLDER, "latest"]); const tb = await bal(HOLDER); if (process.env.DBG) console.log("T: holder eth", eth, "usdg", String(tb));
    const h = await rpc("eth_sendTransaction", [{ from: HOLDER, to: TOKEN, data: encodeFunctionData({ abi: erc, functionName: "transfer", args: [acc.address, usdg] }) }]);
    for (let i = 0; i < 20 && !(await rpc("eth_getTransactionReceipt", [h])); i++) await new Promise(r => setTimeout(r, 200));
    known.add(acc.address.toLowerCase()); return acc;
  }
  const types = { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
  async function sign(acc, to, value, nonce) {
    const validBefore = BigInt(Math.floor(Date.now() / 1000) + 3600); nonce = nonce || toHex(crypto.getRandomValues(new Uint8Array(32)));
    const sig = await acc.signTypedData({ domain: { name: "Global Dollar", version: "1", chainId: 4663, verifyingContract: TOKEN }, types, primaryType: "TransferWithAuthorization", message: { from: acc.address, to, value, validAfter: 0n, validBefore, nonce } });
    return { from: acc.address, to, value: value.toString(), validAfter: "0", validBefore: validBefore.toString(), nonce, v: parseInt(sig.slice(130, 132), 16), r: "0x" + sig.slice(2, 66), s: "0x" + sig.slice(66, 130) };
  }
  const dest = () => privateKeyToAccount(generatePrivateKey()).address;
  const tryRelay = (b, ip = "1.1.1.1") => R.relay(b, ip).then(v => ({ ok: true, ...v }), e => ({ ok: false, err: String(e.shortMessage || e.message).slice(0, 90) }));
  const show = (rs) => rs.forEach((r, i) => out(i, r.ok ? "ACCEPTED " + r.hash.slice(0, 14) + (r.feeHash ? " fee " + r.feeHash.slice(0, 14) : "") : "refused: " + r.err));
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  if (sc === "concurrent") {
    const a = await newStealth(); const to = dest();
    const rs = await Promise.all([0, 1, 2, 3, 4].map(async () => tryRelay(await sign(a, to, 300000n), "2.2.2." + Math.random())));
    show(rs); const okN = rs.filter(r => r.ok).length; out("accepted =", okN, okN === 1 ? "PASS" : "FAIL");
    await sleep(800); out("recipient balance", String(await bal(to)), "state gas wei", String(R.st.gas), "perFrom", JSON.stringify(R.st.perFrom));
    fs.writeFileSync(path.join(os.tmpdir(), "stealth-t-from.json"), JSON.stringify({ pk: null, from: a.address }));
    const f = await sign(a, to, 300000n); fs.writeFileSync(path.join(os.tmpdir(), "stealth-t-req.json"), JSON.stringify(f));
    out("state file:", fs.readFileSync(process.env.STEALTH_RELAY_STATE, "utf8").slice(0, 200));
  } else if (sc === "restart") {
    out("loaded from file: gas", String(R.st.gas), "perFrom", JSON.stringify(R.st.perFrom));
    const req = JSON.parse(fs.readFileSync(path.join(os.tmpdir(), "stealth-t-req.json"), "utf8")); known.add(req.from.toLowerCase());
    const r = await tryRelay(req); show([r]); out("same-from after restart refused =", !r.ok && /already withdrew/.test(r.err) ? "PASS" : "FAIL");
  } else if (sc === "budget") {
    const accs = []; for (let i = 0; i < 4; i++) accs.push(await newStealth());
    const probe = await sign(accs[0], dest(), 300000n);
    const gas = await R.pub.estimateContractGas({ address: TOKEN, abi: parseAbi(["function transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"]), functionName: "transferWithAuthorization", args: [probe.from, probe.to, BigInt(probe.value), 0n, BigInt(probe.validBefore), probe.nonce, probe.v, probe.r, probe.s], account: R.account });
    const fees = await R.pub.estimateFeesPerGas(); const est = gas * 125n / 100n * fees.maxFeePerGas;
    out("gas", String(gas), "maxFee", String(fees.maxFeePerGas), "est one tx wei", String(est));
    out("EST", String(est));
  } else if (sc === "budget2") {
    const accs = []; for (let i = 0; i < 4; i++) accs.push(await newStealth());
    const rs = await Promise.all(accs.map(async (a, i) => tryRelay(await sign(a, dest(), 300000n), "3.3.3." + i)));
    show(rs); const okN = rs.filter(r => r.ok).length; out("accepted =", okN, okN === 1 ? "PASS (reserve blocked the burst)" : "FAIL");
    await sleep(1000); out("gas counted after receipt reconcile (wei):", String(R.st.gas), "budget:", process.env.STEALTH_RELAY_GAS_BUDGET_WEI);
  } else if (sc === "fee") {
    const a = await newStealth(700_000n); const to = dest();
    const noFee = await tryRelay(await sign(a, to, 500000n)); show([noFee]); out("without feeAuth refused =", !noFee.ok ? "PASS" : "FAIL");
    const low = await sign(a, R.account.address, 50000n);
    const r1 = await tryRelay({ ...(await sign(a, to, 500000n)), feeAuth: low }); show([r1]); out("fee below minimum refused =", !r1.ok ? "PASS" : "FAIL");
    const feeA = await sign(a, R.account.address, 150000n); const b0 = await bal(R.account.address);
    const r2 = await tryRelay({ ...(await sign(a, to, 500000n)), feeAuth: feeA }); show([r2]); await sleep(1000);
    out("recipient", String(await bal(to)), "relayer token gain", String((await bal(R.account.address)) - b0), "(expect 500000 / 150000)");
  } else if (sc === "lowbal") {
    const a = await newStealth(); const r = await tryRelay(await sign(a, dest(), 300000n)); show([r]);
    out("refused with clear error =", !r.ok && /out of gas funds/.test(r.err) ? "PASS" : "FAIL");
    out("log:", fs.readFileSync(process.env.STEALTH_RELAY_LOG, "utf8").split("\n").filter(l => l.includes("ALERT")).join(" | ").slice(0, 200));
  } else if (sc === "stuck") {
    const a = await newStealth(); const to = dest();
    await rpc("evm_setAutomine", [false]);
    const r = await tryRelay(await sign(a, to, 300000n)); show([r]); out("recipient before mining", String(await bal(to)));
    await sleep(5000); out("pending txs in pool:", JSON.stringify(Object.keys((await rpc("txpool_content")).pending || {}).length));
    await rpc("evm_mine"); await sleep(1500); await rpc("evm_mine"); await sleep(1500);
    const bn = await rpc("eth_getBlockByNumber", ["latest", false]); out("latest block txs", JSON.stringify(bn.transactions), "pool", JSON.stringify(await rpc("txpool_content")).slice(0, 300));
    const lg = fs.readFileSync(process.env.STEALTH_RELAY_LOG, "utf8"); const h2 = /replacement main (0x[0-9a-f]{64})/.exec(lg)[1];
    const rc2 = await rpc("eth_getTransactionReceipt", [h2]); out("receipt replacement", rc2 ? "status " + rc2.status + " block " + parseInt(rc2.blockNumber, 16) : "null", "orig", JSON.stringify(await rpc("eth_getTransactionReceipt", [r.hash])));
    out("recipient after mining", String(await bal(to)), "(expect 300000: exactly once)");
    out("log:", fs.readFileSync(process.env.STEALTH_RELAY_LOG, "utf8").split("\n").filter(l => /stuck|replacement|replaced|mined/.test(l)).map(l => l.slice(25, 110)).join(" | "));
    await rpc("evm_setAutomine", [true]);
  }
  stub.close(); setTimeout(() => process.exit(0), 300);
}
