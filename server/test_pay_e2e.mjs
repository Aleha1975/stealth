/* E2E на форке Robinhood Chain (anvil): платёж одной подписью через /relay/pay. Запуск: node test_pay_e2e.mjs
   Деплоит StealthPay на форк (ключ anvil #0), плательщику даёт USDG (импёрсонация держателя), подпись делает ТЕМ ЖЕ кодом, что веб
   (web/pay-auth.js), релеер -- отдельный процесс (relayer.mjs) с HTTP, как в бою. В живую цепь ничего не шлётся. */
import { spawn, spawnSync } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import { fileURLToPath } from "url";
import { createPublicClient, createWalletClient, http, parseAbi, parseEventLogs, hashTypedData, toHex, getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { paymentNonce, receiveDigest, receiveTypedData, splitSig } from "../web/pay-auth.js";
import { deriveForPayment, metaAddress, parseMeta, checkAnnouncement, secpUtils, hex, unhex, signDigest } from "../web/stealth-crypto.js";
import { CHAINS } from "../web/chains.js";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const APORT = 8745, RPORT = 3984, RPC = "http://127.0.0.1:" + APORT, RELAY = "http://127.0.0.1:" + RPORT;
const TOKEN = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", HOLDER = "0x0000000000000000000000000000000000000001";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const FUND = 5_000_000n, FEE = 50000n, AMOUNT = 2_000_000n;                       // $0.05 fee, $2.00 payment
const sleep = ms => new Promise(r => setTimeout(r, ms));
let fails = 0; const ok = (name, pass, extra = "") => { console.log((pass ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); if (!pass) fails++; };
const rpc = (m, p = []) => fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }).then(r => r.json()).then(j => { if (j.error) throw new Error(m + ": " + JSON.stringify(j.error)); return j.result; });
const procs = [];
const done = code => { procs.forEach(p => p.kill()); process.exit(code); };
process.on("SIGINT", () => done(1));
try {
  procs.push(spawn("anvil", ["--fork-url", "https://rpc.mainnet.chain.robinhood.com", "--port", String(APORT), "--silent"], { stdio: "inherit" }));
  for (let i = 0; i < 60; i++) { try { await rpc("eth_chainId"); break; } catch { await sleep(500); } }
  console.log("anvil fork chainId", parseInt(await rpc("eth_chainId"), 16), "block", parseInt(await rpc("eth_blockNumber"), 16));
  const chain = { id: 4663, name: "rh-fork", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
  const pub = createPublicClient({ chain, transport: http(RPC) });
  const deployer = createWalletClient({ account: privateKeyToAccount(ANVIL0), chain, transport: http(RPC) });
  const art = JSON.parse(fs.readFileSync(path.join(HERE, "../out/StealthPay.sol/StealthPay.json"), "utf8"));
  const dh = await deployer.deployContract({ abi: art.abi, bytecode: art.bytecode.object, args: ["0x55649E01B5Df198D18D95b5cc5051630cfD45564", TOKEN] });
  const SP = getAddress((await pub.waitForTransactionReceipt({ hash: dh })).contractAddress); console.log("StealthPay deployed on fork:", SP);
  const erc = parseAbi(["function transfer(address,uint256) returns (bool)", "function balanceOf(address) view returns (uint256)"]);
  const bal = a => pub.readContract({ address: TOKEN, abi: erc, functionName: "balanceOf", args: [a] });

  // relayer as a real process, throwaway key funded from anvil
  const rk = generatePrivateKey(), relayerAddr = privateKeyToAccount(rk).address;
  await rpc("anvil_setBalance", [relayerAddr, toHex(10n ** 18n)]);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stealth-pay-"));
  const rp = spawn("node", [path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTHPAY: SP, RELAYER_KEY: rk, STEALTH_RELAY_PORT: String(RPORT),
    STEALTH_RELAY_STATE: path.join(tmp, "st.json"), STEALTH_RELAY_LOG: path.join(tmp, "r.log"), STEALTH_RELAY_PAY_FEE: String(FEE), STEALTH_RELAY_PAY_FEE_MIN: String(FEE), STEALTH_RELAY_GAS_BUDGET_WEI: "1000000000000000000" }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(rp); await new Promise(r => rp.stdout.on("data", d => { if (String(d).includes("stealth relayer")) r(); }));
  const stats = await (await fetch(RELAY + "/stealth-api/relay/stats")).json();
  ok("stats: relayer, stealthpay, pay_fee", stats.relayer === relayerAddr && stats.stealthpay === SP && stats.pay_fee === String(FEE), JSON.stringify({ pay_fee: stats.pay_fee, pay_enabled: stats.pay_enabled }));

  // payer with USDG
  const payerPk = generatePrivateKey(), payer = privateKeyToAccount(payerPk);
  await rpc("anvil_setBalance", [HOLDER, toHex(10n ** 18n)]); await rpc("anvil_impersonateAccount", [HOLDER]);
  const th = await rpc("eth_sendTransaction", [{ from: HOLDER, to: TOKEN, data: "0xa9059cbb" + payer.address.slice(2).toLowerCase().padStart(64, "0") + FUND.toString(16).padStart(64, "0") }]);
  await pub.waitForTransactionReceipt({ hash: th });
  ok("payer funded, has no ETH", (await bal(payer.address)) === FUND && (await pub.getBalance({ address: payer.address })) === 0n);

  // receiver meta-address and a fresh stealth payment, derived exactly as the web does
  const sk = secpUtils.utils.randomPrivateKey(), vk = secpUtils.utils.randomPrivateKey();
  const keys = { spendPriv: sk, viewPriv: vk, spendPub: secpUtils.getPublicKey(sk, true), viewPub: secpUtils.getPublicKey(vk, true) };
  const d = deriveForPayment(parseMeta(metaAddress(keys, "rh")));
  const T = CHAINS.rh.token;
  const argsFor = (o = {}) => ({ chainId: 4663, stealthPay: SP, token: TOKEN, stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: FEE, feeRecipient: relayerAddr, ...o });
  const nonce = paymentNonce(argsFor());
  const onchainNonce = await pub.readContract({ address: SP, abi: parseAbi(["function paymentNonce(address,address,bytes,bytes1,uint256,address) view returns (bytes32)"]), functionName: "paymentNonce", args: [TOKEN, d.stealth, d.ephPub, d.viewTag, FEE, relayerAddr] });
  ok("JS paymentNonce == contract paymentNonce", nonce === onchainNonce, nonce);

  const validBefore = Math.floor(Date.now() / 1000) + 3600;
  const tdArgs = { token: T, chainId: 4663, from: payer.address, stealthPay: SP, amount: AMOUNT, validAfter: 0, validBefore, nonce };
  const jsDigest = hex(receiveDigest(tdArgs));
  const td = JSON.parse(receiveTypedData(tdArgs));
  const viemDigest = hashTypedData({ domain: { ...td.domain, chainId: 4663 }, types: { ReceiveWithAuthorization: td.types.ReceiveWithAuthorization }, primaryType: "ReceiveWithAuthorization", message: { ...td.message, value: AMOUNT, validAfter: 0n, validBefore: BigInt(validBefore) } });
  ok("JS EIP-712 digest == viem hashTypedData", jsDigest === viemDigest);
  const walletSig = splitSig(await payer.signTypedData({ domain: { ...td.domain, chainId: 4663 }, types: { ReceiveWithAuthorization: td.types.ReceiveWithAuthorization }, primaryType: "ReceiveWithAuthorization", message: { ...td.message, value: AMOUNT, validAfter: 0n, validBefore: BigInt(validBefore) } }));   // what a wallet returns for the same typed data
  const jsSig = signDigest(unhex(jsDigest), unhex(payerPk));
  ok("JS-signed == wallet-style signed", JSON.stringify(walletSig) === JSON.stringify(jsSig));
  const body = (o = {}, a = {}) => ({ token: TOKEN, amount: AMOUNT.toString(), stealth: d.stealth, eph: d.ephPub, viewTag: d.viewTag, fee: FEE.toString(), feeRecipient: relayerAddr,
    auth: { from: payer.address, validAfter: "0", validBefore: String(validBefore), v: walletSig.v, r: walletSig.r, s: walletSig.s, ...a }, ...o });
  const post = (b, ip = "9.9.9.9") => fetch(RELAY + "/stealth-api/relay/pay", { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip }, body: JSON.stringify(b) }).then(async r => ({ status: r.status, ...(await r.json()) }));
  const relayerNonce = () => pub.getTransactionCount({ address: relayerAddr });
  const n0 = await relayerNonce(), rb0 = await bal(relayerAddr), eb0 = await pub.getBalance({ address: relayerAddr });

  // refusals BEFORE sending: nothing may be spent
  const tampered = await post(body({ stealth: "0x" + "ab".repeat(20) }));
  ok("tampered stealth refused", tampered.status === 400 && /signature does not match|mismatch/.test(tampered.error), tampered.error);
  const tFee = await post(body({ fee: "1" })); ok("fee below relayer minimum refused", tFee.status === 400, tFee.error);
  const tRec = await post(body({ feeRecipient: payer.address })); ok("fee recipient != relayer refused", tRec.status === 400, tRec.error);
  const tTok = await post(body({ token: "0x" + "cd".repeat(20) })); ok("wrong token refused", tTok.status === 400, tTok.error);
  const tAmt = await post(body({ amount: (AMOUNT + 1n).toString() })); ok("tampered amount refused", tAmt.status === 400 && /signature/.test(tAmt.error), tAmt.error);
  const tEoa = await post(body({}, { r: "0x" + "11".repeat(32) })); ok("garbage signature refused", tEoa.status === 400, tEoa.error);
  ok("no gas spent, no tx sent by refusals", (await relayerNonce()) === n0 && (await pub.getBalance({ address: relayerAddr })) === eb0 && (await bal(payer.address)) === FUND);

  // the honest submit
  const r1 = await post(body());
  ok("honest submit accepted", r1.status === 200 && /^0x[0-9a-f]{64}$/.test(r1.hash || ""), r1.hash || r1.error);
  const rc = await pub.waitForTransactionReceipt({ hash: r1.hash });
  ok("tx mined success, sent by relayer", rc.status === "success" && rc.from.toLowerCase() === relayerAddr.toLowerCase() && rc.to.toLowerCase() === SP.toLowerCase());
  ok("stealth got amount - fee", (await bal(d.stealth)) === AMOUNT - FEE, String(await bal(d.stealth)));
  ok("relayer got fee", (await bal(relayerAddr)) - rb0 === FEE);
  ok("payer debited amount, still 0 ETH", (await bal(payer.address)) === FUND - AMOUNT && (await pub.getBalance({ address: payer.address })) === 0n);
  ok("StealthPay holds nothing", (await bal(SP)) === 0n);
  const logs = parseEventLogs({ abi: parseAbi(["event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)"]), logs: rc.logs });
  const ev = logs[0]?.args;
  ok("Announcement emitted for the stealth address", logs.length === 1 && ev.stealthAddress === d.stealth && ev.ephemeralPubKey.toLowerCase() === d.ephPub.toLowerCase() && ev.schemeId === 1n && ev.caller === SP);
  const net = (AMOUNT - FEE).toString(16).padStart(64, "0");
  ok("metadata = viewTag + transfer selector + token + net amount", ev.metadata.toLowerCase() === (d.viewTag + "a9059cbb" + TOKEN.slice(2).toLowerCase() + net).toLowerCase());
  const hit = checkAnnouncement(keys, ev.ephemeralPubKey, ev.metadata.slice(0, 4));
  ok("receiver finds it with the viewing key", !!hit && hit.stealth.toLowerCase() === d.stealth.toLowerCase());

  // replay
  const r2 = await post(body(), "9.9.9.10"); ok("second submit of same payload refused", r2.status === 400, r2.error);
  ok("replay moved nothing", (await bal(d.stealth)) === AMOUNT - FEE && (await relayerNonce()) === n0 + 1);
  // ---- indexer: payer of a gasless payment must be the SIGNER, not the relayer (tx.from); payToken -> the caller
  const d2 = deriveForPayment(parseMeta(metaAddress(keys, "rh")));
  await rpc("anvil_setBalance", [payer.address, toHex(10n ** 18n)]);
  const payerW = createWalletClient({ account: payer, chain, transport: http(RPC) });
  await pub.waitForTransactionReceipt({ hash: await payerW.writeContract({ address: TOKEN, abi: parseAbi(["function approve(address,uint256) returns (bool)"]), functionName: "approve", args: [SP, 1_000_000n] }) });
  const rc2 = await pub.waitForTransactionReceipt({ hash: await payerW.writeContract({ address: SP, abi: art.abi, functionName: "payToken", args: [TOKEN, 1_000_000n, d2.stealth, d2.ephPub, d2.viewTag] }) });
  ok("payToken mined", rc2.status === "success");
  await rpc("anvil_mine", ["0x8"]);
  const IPORT = 3985, IDB = path.join(tmp, "i.db");
  const iEnv = { ...process.env, STEALTH_CHAIN: "rh", STEALTH_RPC: RPC, STEALTH_DB: IDB, STEALTH_PORT: String(IPORT), STEALTHPAY: SP.toLowerCase(), STEALTH_CONFIRMATIONS: "2", STEALTH_START_BLOCK: String(Number(rc.blockNumber) - 2) };
  const ip = spawn("python3", ["-B", path.join(HERE, "stealth_indexer.py")], { env: iEnv, stdio: "ignore" }); procs.push(ip);
  const J = async u => (await fetch("http://127.0.0.1:" + IPORT + u)).json();
  let rows = []; for (let i = 0; i < 60; i++) { try { rows = (await J("/stealth-api/announcements?since=0&limit=50")).rows; } catch {} if (rows.length >= 2) break; await sleep(500); }
  const rowOf = st => rows.find(x => x.stealth.toLowerCase() === st.toLowerCase());
  ok("indexer: gasless payment payer == signer (not relayer)", rowOf(d.stealth)?.payer === payer.address.toLowerCase() && rowOf(d.stealth)?.payer !== relayerAddr.toLowerCase(), String(rowOf(d.stealth)?.payer));
  ok("indexer: payToken payer == caller", rowOf(d2.stealth)?.payer === payer.address.toLowerCase(), String(rowOf(d2.stealth)?.payer));
  // --refill-payers: corrupt the stored payer to the relayer (old behaviour), recompute, check
  ip.kill(); await sleep(800);
  const py = (code) => spawnSync("python3", ["-I", "-c", code], { encoding: "utf8" });
  py("import sqlite3;c=sqlite3.connect(%j);c.execute(\"UPDATE ann SET payer=?\",(%j,));c.commit()".replace("%j", JSON.stringify(IDB)).replace("%j", JSON.stringify(relayerAddr.toLowerCase())));
  const rf = spawnSync("python3", ["-B", path.join(HERE, "stealth_indexer.py"), "--refill-payers"], { env: iEnv, encoding: "utf8" });
  const got = py("import sqlite3;print(','.join(r[0] for r in sqlite3.connect(%j).execute('SELECT payer FROM ann ORDER BY id')))".replace("%j", JSON.stringify(IDB))).stdout.trim();
  ok("--refill-payers recomputes existing rows", rf.status === 0 && got === payer.address.toLowerCase() + "," + payer.address.toLowerCase(), rf.stdout.trim() + " | " + got);
  console.log(fails ? "RESULT FAIL " + fails : "RESULT PASS");
  done(fails ? 1 : 0);
} catch (e) { console.log("ERROR", e && e.stack || e); done(2); }
