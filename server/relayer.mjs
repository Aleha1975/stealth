/* Stealth relayer: отправляет за клиента token.transferWithAuthorization (EIP-3009; USDC на Base, USDG на Robinhood Chain) со
   стелс-адреса, чтобы одноразовому адресу не нужен был ETH на газ. Подпись делает клиент у себя ключом стелс-адреса; релеер
   платит газ своим ОТДЕЛЬНЫМ ключом (RELAYER_KEY из /opt/stealth/relayer.env) и шлёт транзакцию. Цепь: STEALTH_CHAIN=base|rh
   (chains.json; одна служба = одна цепь, порт/состояние/лог через окружение). Ограничения против расхода нашего газа чужими:
   адрес должен быть объявлен через наш StealthPay (индексатор /known), один вывод с адреса в сутки (с замком на время
   обработки -- два параллельных запроса с одного адреса не пройдут оба), бюджет газа в сутки (резервируется ДО отправки,
   сверяется по квитанции), лимит на IP; счётчики пишутся в файл (рестарт не обнуляет). Застрявшая транзакция заменяется
   один раз тем же nonce с повышенной комиссией. Баланс релеера ниже порога -> отказ и строка ALERT в логе.
   Необязательная комиссия: feeAuth (вторая авторизация с того же адреса на адрес релеера на сумму >= STEALTH_RELAY_FEE_MIN,
   0 = выключено); отправляется первой. Ответ -- хеш сразу после отправки, квитанцию клиент ждёт сам.
   POST /stealth-api/relay/pay {token,amount,stealth,eph,viewTag,fee,feeRecipient,auth:{from,validAfter,validBefore,v,r,s}} -> {hash} (платёж одной подписью плательщика, StealthPay.payWithAuthorization;
   нужен STEALTHPAY=<адрес>, STEALTH_RELAY_PAY_FEE_MIN/PAY_FEE/PAY_PER_PAYER)
   API 127.0.0.1:3874: POST /stealth-api/relay {from,to,value,validAfter,validBefore,nonce,v,r,s[,feeAuth:{value,validAfter,validBefore,nonce,v,r,s}]}
   -> {hash[,feeHash]}; GET /stealth-api/relay/stats */
import http from "http"; import fs from "fs"; import path from "path"; import { fileURLToPath, pathToFileURL } from "url";
import { createPublicClient, createWalletClient, http as vhttp, fallback, parseAbi, formatEther, getAddress, defineChain, encodeAbiParameters, keccak256, toHex, recoverTypedDataAddress, isAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
const HERE = path.dirname(fileURLToPath(import.meta.url));
for (const f of ["/opt/mprhedged/exec/.env", "/opt/stealth/relayer.env"]) {
  if (!fs.existsSync(f)) continue;
  for (const line of fs.readFileSync(f, "utf8").split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)=["']?([^"'#\n]+)/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
  }
}
const E = process.env;
const CHAIN = (E.STEALTH_CHAIN || "base").trim().toLowerCase();
const CHAINS = JSON.parse(fs.readFileSync(path.join(HERE, "chains.json"), "utf8"));
const CC = CHAINS[CHAIN]; if (!CC) { console.error("unknown STEALTH_CHAIN", CHAIN); process.exit(1); }
const TOKEN = getAddress(CC.token);
const RPCS = (E.STEALTH_RPC ? E.STEALTH_RPC.split(",") : [...CC.rpc_env.map(k => E[k]), ...CC.rpcs]).map(s => (s || "").trim()).filter(Boolean);
const chain = defineChain({ id: CC.id, name: CC.name, nativeCurrency: { name: "Ether", symbol: CC.native, decimals: 18 }, rpcUrls: { default: { http: RPCS } } });
const abi = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "function balanceOf(address) view returns (uint256)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
]);
const payAbi = parseAbi([
  "struct Authorization { address from; uint256 validAfter; uint256 validBefore; uint8 v; bytes32 r; bytes32 s; }",
  "function payWithAuthorization(address token, uint256 amount, address stealthAddress, bytes ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient, Authorization auth)",
  "function paymentNonce(address token, address stealthAddress, bytes ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient) view returns (bytes32)",
]);
const STEALTHPAY = /^0x[0-9a-fA-F]{40}$/.test((E.STEALTHPAY || "").trim()) ? getAddress(E.STEALTHPAY.trim()) : null;   // StealthPay этой цепи; нет -> /relay/pay выключен
const PAY_FEE_MIN = BigInt(E.STEALTH_RELAY_PAY_FEE_MIN || "0");                                  // минимальная комиссия за газ в платеже
const PAY_FEE = BigInt(E.STEALTH_RELAY_PAY_FEE || PAY_FEE_MIN.toString());                       // комиссия, которую предлагает веб (в /relay/stats)
const MAX_PER_PAYER_PER_DAY = Number(E.STEALTH_RELAY_PAY_PER_PAYER || 20);
const MAX_PER_IP_PER_DAY = Number(E.STEALTH_RELAY_MAX_PER_IP || 30);
const GAS_BUDGET_WEI_PER_DAY = BigInt(E.STEALTH_RELAY_GAS_BUDGET_WEI || "200000000000000");   // 0.0002 ETH/day
const MIN_VALUE = BigInt(E.STEALTH_RELAY_MIN_USDC || "100000");                                  // $0.10 (токен 6 знаков на обеих цепях)
const FEE_MIN = BigInt(E.STEALTH_RELAY_FEE_MIN || "0");                                          // 0 = комиссия выключена
const MIN_BALANCE_WEI = BigInt(E.STEALTH_RELAY_MIN_BALANCE_WEI || "100000000000000");           // ниже -- отказ + ALERT
const STUCK_S = Number(E.STEALTH_RELAY_STUCK_S || 60);                                           // нет квитанции за N с -> замена
const BUMP_PCT = BigInt(E.STEALTH_RELAY_BUMP_PCT || "30");
const GAS_PAD_PCT = 125n;                                                                         // запас к оценке газа для резерва
const INDEXER = E.STEALTH_INDEXER || "http://127.0.0.1:3873";
const STATE_FILE = E.STEALTH_RELAY_STATE || "/opt/stealth/relayer_state." + CHAIN + ".json";
const LOG = E.STEALTH_RELAY_LOG || "/opt/stealth/relayer." + CHAIN + ".log";
const KEY = (E.RELAYER_KEY || "").trim();
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY)) { console.error("RELAYER_KEY missing: generate one into /opt/stealth/relayer.env"); process.exit(1); }
export const account = privateKeyToAccount(KEY);
const transport = RPCS.length > 1 ? fallback(RPCS.map(u => vhttp(u, { timeout: 30000 }))) : vhttp(RPCS[0], { timeout: 30000 });
export const pub = createPublicClient({ chain, transport }); const wal = createWalletClient({ account, chain, transport });
const log = (...a) => { const s = new Date().toISOString() + " " + a.join(" "); console.log(s); try { fs.appendFileSync(LOG, s + "\n"); } catch {} };
const day = () => Math.floor(Date.now() / 86400000);

// ---- счётчики суток: gas = потрачено + зарезервировано под ещё не сверённые транзакции; пишутся в файл атомарно
export let st = { day: day(), gas: 0n, perIp: {}, perFrom: {}, perPayer: {} };
const save = () => {
  try { const tmp = STATE_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify({ day: st.day, gas: st.gas.toString(), perIp: st.perIp, perFrom: st.perFrom, perPayer: st.perPayer })); fs.renameSync(tmp, STATE_FILE); }
  catch (e) { log("ALERT state save failed", String(e).slice(0, 80)); }
};
export const load = () => {
  try { const j = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); if (j.day === day()) st = { day: j.day, gas: BigInt(j.gas), perIp: j.perIp || {}, perFrom: j.perFrom || {}, perPayer: j.perPayer || {} }; } catch {}
};
load();
const roll = () => { if (st.day !== day()) { st = { day: day(), gas: 0n, perIp: {}, perFrom: {}, perPayer: {} }; save(); } };
const inflight = new Set();                 // from-адреса, обрабатываемые прямо сейчас
let nonceLock = Promise.resolve();
let lastAlert = 0;
const alertOnce = (...a) => { if (Date.now() - lastAlert > 60000) { lastAlert = Date.now(); log("ALERT", ...a); } };
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

function parseAuth(o, what) {
  if (!o || !HEX32.test(o.nonce) || !HEX32.test(o.r) || !HEX32.test(o.s)) throw new Error("bad signature fields" + what);
  const v = Number(o.v); if (![27, 28].includes(v)) throw new Error("bad v" + what);
  return { value: BigInt(o.value), validAfter: BigInt(o.validAfter || 0), validBefore: BigInt(o.validBefore), nonce: o.nonce, v, r: o.r, s: o.s };
}

// отправка со сверкой по квитанции; возвращает hash сразу. spent: резерв заменяется фактом по квитанции
const TRANSFER_CALL = args => ({ address: TOKEN, abi, functionName: "transferWithAuthorization", args });
async function sendAndTrack(call, gasLimit, reserve, from, tag, onRevert) {
  let hash;
  await (nonceLock = nonceLock.then(async () => { hash = await wal.writeContract(call); }, () => {}));
  // nonceLock не должен залипать после ошибки одной отправки: ошибка уходит вызывающему через throw ниже
  if (!hash) throw new Error("send failed");
  const watch = async () => {
    let rc;
    try { rc = await pub.waitForTransactionReceipt({ hash, timeout: STUCK_S * 1000 }); }
    catch {
      try {                                                    // застряла: та же nonce, комиссия выше -- один раз
        const tx = await pub.getTransaction({ hash });
        const up = (x) => x + x * BUMP_PCT / 100n + 1n;
        const fees = tx.maxFeePerGas ? { maxFeePerGas: up(tx.maxFeePerGas), maxPriorityFeePerGas: up(tx.maxPriorityFeePerGas || 0n) } : { gasPrice: up(tx.gasPrice) };
        log("stuck", tag, hash, "nonce", tx.nonce, "-> replacing with +" + BUMP_PCT + "%");
        const h2 = await wal.writeContract({ ...call, nonce: tx.nonce, gas: tx.gas, ...fees });
        log("replacement", tag, h2);
      } catch (e) { log("replace failed", tag, hash, String(e).slice(0, 100)); }
      try { rc = await pub.waitForTransactionReceipt({ hash, timeout: 180_000, onReplaced: r => log("replaced", hash, "->", r.transaction.hash, r.reason) }); }
      catch (e) { log("ALERT receipt wait failed", tag, hash, String(e).slice(0, 80)); return; }   // резерв остаётся (консервативно)
    }
    const spent = rc.gasUsed * (rc.effectiveGasPrice || 0n); st.gas += spent - reserve; if (st.gas < 0n) st.gas = 0n;
    if (rc.status !== "success") { if (onRevert) onRevert(); else if (tag === "main") delete st.perFrom[from]; log("reverted", tag, hash); } else log("mined", tag, hash, "gas", formatEther(spent), "ETH");
    save();
  };
  watch().catch(e => log("watch error", String(e).slice(0, 80)));
  return hash;
}

export async function relay(b, ip) {
  const from = getAddress(b.from), to = getAddress(b.to);
  const main = parseAuth(b, ""); const value = main.value;
  if (value < MIN_VALUE) throw new Error("below the minimum of $0.10");
  let fee = null;
  if (b.feeAuth) {
    if (FEE_MIN === 0n) throw new Error("fees are not enabled");
    fee = parseAuth(b.feeAuth, " (fee)");
    if (fee.value < FEE_MIN) throw new Error("fee below the minimum");
  } else if (FEE_MIN > 0n) throw new Error("fee authorization required");
  roll();
  // ---- синхронный блок: проверки суток и замок адреса без await между проверкой и записью
  if ((st.perIp[ip] || 0) >= MAX_PER_IP_PER_DAY) throw new Error("too many requests from this network today");
  if (st.perFrom[from]) throw new Error("this address already withdrew today; try tomorrow");
  if (inflight.has(from)) throw new Error("a withdrawal from this address is already in progress");
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
  inflight.add(from); st.perIp[ip] = (st.perIp[ip] || 0) + 1;
  let reserve = 0n, used = 0n, sent = false;
  try {
    const known = await fetch(INDEXER + "/stealth-api/known?addr=" + from, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => ({ known: false }));
    if (!known.known) throw new Error("not a stealth address paid through Stealth");
    const bal = await pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] });
    if (bal < value + (fee ? fee.value : 0n)) throw new Error("the address holds less than the requested amount");
    const now = BigInt(Math.floor(Date.now() / 1000));
    const list = [["main", main, to]]; if (fee) list.unshift(["fee", fee, account.address]);
    for (const [, a] of list) {
      if (await pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, a.nonce] })) throw new Error("authorization already used");
      if (a.validBefore <= now + 30n) throw new Error("authorization expires too soon");
    }
    const bw = await pub.getBalance({ address: account.address });
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Error("relayer is out of gas funds, try again later"); }
    const calls = list.map(([tag, a, dst]) => [tag, [from, dst, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s]]);
    let gas = 0n; const lims = [];
    for (const [, args] of calls) {
      await pub.simulateContract({ address: TOKEN, abi, functionName: "transferWithAuthorization", args, account });
      const g = await pub.estimateContractGas({ address: TOKEN, abi, functionName: "transferWithAuthorization", args, account });
      gas += g; lims.push(g * GAS_PAD_PCT / 100n);                  // лимит газа явно: оценка узла бывает впритык (OOG на ecrecover)
    }
    const fees = await pub.estimateFeesPerGas();
    const est = gas * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    // резерв под бюджет суток СИНХРОННО (после последнего await): параллельные заявки видят уже зарезервированное
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
    st.gas += est; reserve = est; save();
    const hashes = {};
    const n = BigInt(calls.length); let left = reserve;
    for (let i = 0; i < calls.length; i++) {                 // комиссия первой; резерв делится поровну между транзакциями
      const [tag, args] = calls[i]; const part = i === calls.length - 1 ? left : reserve / n; left -= part;
      try { hashes[tag] = await sendAndTrack(TRANSFER_CALL(args), lims[i], part, from, tag); }
      catch (e) { if (sent) log("ALERT fee sent but main failed", from, String(e).slice(0, 80)); throw e; }
      sent = true; used += part;
      if (tag === "main") { st.perFrom[from] = true; save(); }
    }
    log("relay", from, "->", to, (Number(value) / 1e6).toFixed(6), CC.token_symbol, hashes.main, fee ? "fee " + (Number(fee.value) / 1e6).toFixed(6) + " " + hashes.fee : "", "ip", ip);
    return fee ? { hash: hashes.main, feeHash: hashes.fee } : { hash: hashes.main };
  } catch (e) {
    st.gas -= reserve - used; if (st.gas < 0n) st.gas = 0n;     // неотправленная часть резерва возвращается
    if (!sent && st.perIp[ip] > 0) st.perIp[ip]--;              // до отправки ничего не потрачено: вернуть и счётчик IP
    save();
    throw e;
  } finally { inflight.delete(from); }
}

// ---- платёж одной подписью: payWithAuthorization на StealthPay (газ платит релеер, комиссия fee идёт релееру из суммы платежа)
const HEX1 = /^0x[0-9a-fA-F]{2}$/, EPH = /^0x0[23][0-9a-fA-F]{64}$/;
const RECEIVE_TYPES = { ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
export const localPaymentNonce = (token, stealth, eph, tag, fee, feeTo) => keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "bytes1" }, { type: "uint256" }, { type: "address" }],
  [keccak256(toHex("StealthPay.payWithAuthorization")), BigInt(CC.id), STEALTHPAY, token, stealth, keccak256(eph), tag, fee, feeTo]));
export async function relayPay(b, ip) {
  if (!STEALTHPAY) throw new Error("payments are not enabled on this chain");
  if (!b || !b.auth || !isAddress(b.token || "") || !isAddress(b.stealth || "") || !isAddress(b.auth.from || "") || !isAddress(b.feeRecipient || "")) throw new Error("bad request");
  if (!EPH.test(b.eph || "") || !HEX1.test(b.viewTag || "")) throw new Error("bad ephemeral key or view tag");
  if (!HEX32.test(b.auth.r) || !HEX32.test(b.auth.s) || ![27, 28].includes(Number(b.auth.v))) throw new Error("bad signature fields");
  const token = getAddress(b.token), stealth = getAddress(b.stealth), feeTo = getAddress(b.feeRecipient), from = getAddress(b.auth.from);
  if (token !== TOKEN) throw new Error("unsupported token");
  const amount = BigInt(b.amount), fee = BigInt(b.fee), eph = b.eph.toLowerCase(), tag = b.viewTag.toLowerCase();
  const auth = { from, validAfter: BigInt(b.auth.validAfter || 0), validBefore: BigInt(b.auth.validBefore), v: Number(b.auth.v), r: b.auth.r, s: b.auth.s };
  if (amount < MIN_VALUE) throw new Error("below the minimum of $0.10");
  if (fee < PAY_FEE_MIN || fee >= amount) throw new Error("fee out of range");
  if (fee > 0n ? feeTo !== account.address : feeTo !== "0x0000000000000000000000000000000000000000") throw new Error("fee recipient must be the relayer");
  if (stealth === STEALTHPAY || stealth === TOKEN || stealth === account.address || stealth === from) throw new Error("bad destination");
  roll();
  if ((st.perIp[ip] || 0) >= MAX_PER_IP_PER_DAY) throw new Error("too many requests from this network today");
  if ((st.perPayer[from] || 0) >= MAX_PER_PAYER_PER_DAY) throw new Error("too many payments from this wallet today");
  const lockKey = "pay:" + from;
  if (inflight.has(lockKey)) throw new Error("a payment from this wallet is already in progress");
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
  inflight.add(lockKey); st.perIp[ip] = (st.perIp[ip] || 0) + 1; st.perPayer[from] = (st.perPayer[from] || 0) + 1;
  let reserve = 0n, sent = false;
  try {
    const nonce = localPaymentNonce(token, stealth, eph, tag, fee, feeTo);
    const onchain = await pub.readContract({ address: STEALTHPAY, abi: payAbi, functionName: "paymentNonce", args: [token, stealth, eph, tag, fee, feeTo] });
    if (onchain.toLowerCase() !== nonce.toLowerCase()) throw new Error("payment nonce mismatch");
    const signer = await recoverTypedDataAddress({
      domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization",
      message: { from, to: STEALTHPAY, value: amount, validAfter: auth.validAfter, validBefore: auth.validBefore, nonce },
      signature: { r: auth.r, s: auth.s, v: BigInt(auth.v) } }).catch(() => null);
    if (!signer || signer !== from) throw new Error("signature does not match the payer");
    if ((await pub.getCode({ address: stealth }))) throw new Error("destination is a contract");
    const bal = await pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] });
    if (bal < amount) throw new Error("the wallet holds less than the amount");
    if (await pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, nonce] })) throw new Error("authorization already used");
    const now = BigInt(Math.floor(Date.now() / 1000));
    if (auth.validBefore <= now + 30n) throw new Error("authorization expires too soon");
    if (auth.validAfter > now) throw new Error("authorization not valid yet");
    const bw = await pub.getBalance({ address: account.address });
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Error("relayer is out of gas funds, try again later"); }
    const call = { address: STEALTHPAY, abi: payAbi, functionName: "payWithAuthorization", args: [token, amount, stealth, eph, tag, fee, feeTo, auth] };
    await pub.simulateContract({ ...call, account });
    const g = await pub.estimateContractGas({ ...call, account });
    const fees = await pub.estimateFeesPerGas();
    const est = g * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
    st.gas += est; reserve = est; save();
    const hash = await sendAndTrack(call, g * GAS_PAD_PCT / 100n, reserve, from, "pay", () => { if (st.perPayer[from] > 0) st.perPayer[from]--; });
    sent = true;
    log("relay-pay", from, "->", stealth, (Number(amount) / 1e6).toFixed(6), CC.token_symbol, "fee", (Number(fee) / 1e6).toFixed(6), hash, "ip", ip);
    return { hash };
  } catch (e) {
    if (!sent) { st.gas -= reserve; if (st.gas < 0n) st.gas = 0n; if (st.perIp[ip] > 0) st.perIp[ip]--; if (st.perPayer[from] > 0) st.perPayer[from]--; save(); }
    throw e;
  } finally { inflight.delete(lockKey); }
}

export const stats = () => { roll(); return { chain: CHAIN, relayer: account.address, gas_spent_today_eth: formatEther(st.gas), gas_budget_eth: formatEther(GAS_BUDGET_WEI_PER_DAY), fee_min: FEE_MIN.toString(), pay_enabled: !!STEALTHPAY, stealthpay: STEALTHPAY, pay_fee: PAY_FEE.toString(), pay_fee_min: PAY_FEE_MIN.toString() }; };

function serve() {
  http.createServer((req, res) => {
    const send = (code, obj) => { const s = JSON.stringify(obj); res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) }); res.end(s); };
    if (req.method === "GET" && req.url.endsWith("/relay/stats")) return send(200, stats());
    const isPay = req.url.endsWith("/relay/pay");
    if (req.method !== "POST" || !(isPay || req.url.endsWith("/relay"))) return send(404, { error: "not found" });
    let body = ""; req.on("data", c => { body += c; if (body.length > 8192) req.destroy(); });
    req.on("end", async () => {
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
      try { send(200, await (isPay ? relayPay : relay)(JSON.parse(body), ip)); }
      catch (e) { const msg = String(e && (e.shortMessage || e.message) || e).slice(0, 160); log("refused", ip, msg); send(400, { error: msg }); }
    });
  }).listen(Number(E.STEALTH_RELAY_PORT || 3874), "127.0.0.1", async () => {
    log("stealth relayer", CHAIN, "on", E.STEALTH_RELAY_PORT || 3874, "as", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) serve();
