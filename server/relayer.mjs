/* Stealth relayer: отправляет за клиента token.transferWithAuthorization (EIP-3009; USDC на Base, USDG на Robinhood Chain) со
   стелс-адреса, чтобы одноразовому адресу не нужен был ETH на газ. Подпись делает клиент у себя ключом стелс-адреса; релеер
   платит газ своим ОТДЕЛЬНЫМ ключом (RELAYER_KEY из /opt/stealth/relayer.env) и шлёт транзакцию. Цепь: STEALTH_CHAIN=base|rh
   (chains.json; одна служба = одна цепь, порт/состояние/лог через окружение). Ограничения против расхода нашего газа чужими:
   адрес должен быть объявлен через наш StealthPay (индексатор /known), до STEALTH_RELAY_PER_FROM (3) выводов с адреса в сутки (с замком на время
   обработки -- два параллельных запроса с одного адреса не пройдут оба), бюджет газа в сутки (резервируется ДО отправки,
   сверяется по квитанции), лимит на IP; счётчики пишутся в файл (рестарт не обнуляет). Застрявшая транзакция заменяется
   один раз тем же nonce с повышенной комиссией. Баланс релеера ниже порога -> отказ и строка ALERT в логе.
   Необязательная комиссия: feeAuth (вторая авторизация с того же адреса на адрес релеера на сумму >= STEALTH_RELAY_FEE_MIN,
   0 = выключено); отправляется первой. Ответ -- хеш сразу после отправки, квитанцию клиент ждёт сам.
   POST /stealth-api/relay/pay {token,amount,stealth,eph,viewTag,fee,feeRecipient,auth:{from,validAfter,validBefore,v,r,s}} -> {hash} (платёж одной подписью плательщика, StealthPay.payWithAuthorization;
   нужен STEALTHPAY=<адрес>, STEALTH_RELAY_PAY_FEE_MIN/PAY_FEE/PAY_PER_PAYER)
   Audit 1099 notes. (1) End-recipient screening is an HONOUR SYSTEM: endRecipient is screened only when the client sends it (the web app screens the recipient itself via
   GET /relay/screen); the relayer cannot see the real beneficiary of a 1Click deposit address. Accepted risk, documented, not a compliance control.
   (2) Logging: the first argument of log() is a fixed template, user text only as later arguments (neutralised); stealth_watch.py matches only the fixed templates.
   (3) Failing requests are metered here, independent of nginx: per-/64 and global failure budgets, concurrency cap, coalesced state writes, rate-limited refusal log lines.
   API 127.0.0.1:3874: POST /stealth-api/relay {from,to,value,validAfter,validBefore,nonce,v,r,s[,feeAuth:{value,validAfter,validBefore,nonce,v,r,s}]}
   -> {hash[,feeHash]}; GET /stealth-api/relay/stats */
import { makeScreen } from "./sanctions/screen.mjs";
import { cleanLog, neutral, safeIp, capMap, makeFailBudget, makeLineLimiter, ipKey, parseEnvLine } from "./relay-util.mjs";
import http from "http"; import fs from "fs"; import path from "path"; import { fileURLToPath, pathToFileURL } from "url";
import { createPublicClient, createWalletClient, http as vhttp, fallback, parseAbi, formatEther, getAddress, defineChain, encodeAbiParameters, encodeFunctionData, keccak256, toHex, recoverTypedDataAddress, isAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
const HERE = path.dirname(fileURLToPath(import.meta.url));
// audit 1087 L-2: the foreign project's file (/opt/mprhedged) may only lend RPC URLs, never the hot key or limits; our own file may set anything. Quoted values keep # and quotes.
const FOREIGN_OK = /^(BASE_RPC2?|BASE_LOGS_RPC|RH_RPC2?|RH_LOGS_RPC)$/;
for (const [f, own] of [["/opt/stealth/relayer.env", true], ["/opt/mprhedged/exec/.env", false]]) {   // audit 1099 I-3: ours first (first writer wins), the foreign file only fills what is still missing
  if (process.env.STEALTH_ENV_ONLY === "1" || !fs.existsSync(f)) continue;   // ENV_ONLY=1 (rh.env): never fall back to the Base key file
  for (const line of fs.readFileSync(f, "utf8").split("\n")) {
    const kv = parseEnvLine(line); if (kv && (own || FOREIGN_OK.test(kv[0])) && !process.env[kv[0]]) process.env[kv[0]] = kv[1];
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
const MAX_PER_FROM = Math.max(1, Number(E.STEALTH_RELAY_PER_FROM || 3));
const GONE_GAP_MS = Number(E.STEALTH_RELAY_GONE_GAP_MS || 4000);                                // audit 1099 L-3: second "not found" probe this much later
const FAIL_PER_IP = Number(E.STEALTH_RELAY_FAIL_PER_IP || 30);                                    // audit 1099 M-2: failed requests per network (/64) per hour
const FAIL_PER_MIN = Number(E.STEALTH_RELAY_FAIL_PER_MIN || 120);                                 // ... and globally per minute (then networks that already failed are refused before any RPC)
const MAX_CONCURRENT = Number(E.STEALTH_RELAY_MAX_CONCURRENT || 64);                              // requests in progress at once
const DEDUPE_MS = Number(E.STEALTH_RELAY_DEDUPE_MS || 24 * 3600 * 1000);                          // audit 1099 L-1: a finished authorization keeps answering with its hash this long
const INDEXER = E.STEALTH_INDEXER || "http://127.0.0.1:3873";
const STATE_FILE = E.STEALTH_RELAY_STATE || "/opt/stealth/relayer_state." + CHAIN + ".json";
const LOG = E.STEALTH_RELAY_LOG || "/opt/stealth/relayer." + CHAIN + ".log";
const KEY = (E.RELAYER_KEY || "").trim();
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY)) { console.error("RELAYER_KEY missing: generate one into /opt/stealth/relayer.env"); process.exit(1); }
export const account = privateKeyToAccount(KEY);
const transport = RPCS.length > 1 ? fallback(RPCS.map(u => vhttp(u, { timeout: 30000 }))) : vhttp(RPCS[0], { timeout: 30000 });
export const pub = createPublicClient({ chain, transport }); const wal = createWalletClient({ account, chain, transport });
// audit 1099 M-1: the FIRST argument is a fixed template (the watchdog keys on it: "ALERT <template>" / "reverted"); every further argument is data and goes through neutral()
// (no line breaks, and the words ALERT / reverted are broken up), so no request can forge or mute a watchdog line. Write user text only as later arguments.
const log = (head, ...rest) => { const s = new Date().toISOString() + " " + cleanLog(head) + (rest.length ? " " + neutral(rest.join(" ")) : "");
   console.log(s); try { fs.appendFileSync(LOG, s + "\n"); } catch {} };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const day = () => Math.floor(Date.now() / 86400000);
export const screen = makeScreen(undefined, log);                    // OFAC SDN EVM addresses (sanctions/evm.json), reloaded on file change

// ---- счётчики суток: gas = потрачено + зарезервировано под ещё не сверённые транзакции; пишутся в файл атомарно
export let st = { day: day(), gas: 0n, perIp: {}, perFrom: {}, perPayer: {} };
const save = () => {
  try { const tmp = STATE_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify({ day: st.day, gas: st.gas.toString(), perIp: st.perIp, perFrom: st.perFrom, perPayer: st.perPayer })); fs.renameSync(tmp, STATE_FILE); }
  catch (e) { log("ALERT state save failed", String(e).slice(0, 80)); }
};
// audit 1099 M-2: failing requests must not write the whole state synchronously; they mark it dirty and a timer flushes it (also on exit)
let saveTimer = null;
const saveSoon = () => { if (!saveTimer) { saveTimer = setTimeout(() => { saveTimer = null; save(); }, 1500); saveTimer.unref(); } };
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { if (saveTimer) save(); process.exit(0); });
process.on("exit", () => { if (saveTimer) save(); });
const dec = (o, k) => { if (o[k] > 1) o[k]--; else delete o[k]; };            // audit 1099 M-2: a counter back at zero is removed, so the maps cannot grow with failed requests
const migFrom = (o) => { const r = {}; for (const [k, v] of Object.entries(o || {})) { const n = v === true ? 1 : Number(v); if (Number.isFinite(n) && n > 0) r[k] = Math.floor(n); } return r; };   // старый формат: true -> 1
export const load = () => {
  try { const j = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); if (j.day === day()) st = { day: j.day, gas: BigInt(j.gas), perIp: j.perIp || {}, perFrom: migFrom(j.perFrom), perPayer: j.perPayer || {} }; } catch {}
};
load();
const roll = () => { if (st.day !== day()) { st = { day: day(), gas: 0n, perIp: {}, perFrom: {}, perPayer: {} }; save(); } };
const inflight = new Set();                 // from-адреса, обрабатываемые прямо сейчас
// audit 1087 L-4a: поправки к суточному счётчику применяются только к тому дню, в котором сделан резерв (после полуночи новый день не «прощает» чужие траты)
const adj = (d0, delta) => { if (st.day === d0) { st.gas += delta; if (st.gas < 0n) st.gas = 0n; } };
// audit 1087 M-1: подписи, отправленные, но ещё не смайненные: from:nonce -> ответ клиенту. Повтор той же подписи получает тот же хеш (не вторую транзакцию, которая откатится и сожжёт газ).
// audit 1099 L-1: the entry is NOT deleted at the receipt: for DEDUPE_MS (24 h) a late retry still gets the original hash. Removed early only if the node lost the transaction (user may re-send).
const pendingAuth = new Map();
const dedupeGet = k => { const e = pendingAuth.get(k); if (!e) return null; if (Date.now() - e.t > DEDUPE_MS) { pendingAuth.delete(k); return null; } return e.res; };
const dedupeSet = (k, res) => { pendingAuth.delete(k); pendingAuth.set(k, { res, t: Date.now() }); capMap(pendingAuth, 20000); };
// audit "stuck tx": исходный хеш -> хеш замены; клиент спрашивает GET /relay/status?hash= и идёт по цепочке
const issued = new Map();                   // audit 1099 M-2: hashes we sent (and their replacements): /relay/status answers only for these, so it cannot be used as a free RPC proxy
const replacedBy = new Map(); const remember = (h, h2) => { replacedBy.set(h.toLowerCase(), h2); capMap(replacedBy, 2000); issued.set(h2.toLowerCase(), 1); capMap(issued, 5000); };   // audit 1099 I-2: drop the oldest, not everything
let nonceLock = Promise.resolve();
let lastAlert = 0;
const alertOnce = (...a) => { if (Date.now() - lastAlert > 60000) { lastAlert = Date.now(); log("ALERT", ...a); } };
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

function parseAuth(o, what) {
  if (!o || !HEX32.test(o.nonce) || !HEX32.test(o.r) || !HEX32.test(o.s)) throw new Error("bad signature fields" + what);
  const v = Number(o.v); if (![27, 28].includes(v)) throw new Error("bad v" + what);
  return { value: BigInt(o.value), validAfter: BigInt(o.validAfter || 0), validBefore: BigInt(o.validBefore), nonce: o.nonce, v, r: o.r, s: o.s };
}

// ---- отправка: nonce ведём локально (один getTransactionCount на старте/после ошибки), комиссии кэшируем на 2 с, подписываем сами --
// под замком остаётся ОДИН RPC (eth_sendRawTransaction) вместо ~4 у writeContract (nonce, fees, chainId, gas): при 100 параллельных заявках
// очередь на замке в ~4 раза короче. Любая ошибка отправки сбрасывает локальный nonce -> следующая отправка берёт pending-счётчик с узла.
export const tmStats = { n: 0, wait: 0, maxWait: 0, send: 0 };
let localNonce = null, feeCache = { t: 0, v: null, p: null };
async function cachedFees() {
  if (feeCache.v && Date.now() - feeCache.t < 2000) return feeCache.v;
  if (feeCache.p) return feeCache.p;
  feeCache.p = pub.estimateFeesPerGas().then(v => { feeCache = { t: Date.now(), v, p: null }; return v; }, e => { feeCache.p = null; throw e; });
  return feeCache.p;
}
const nonceOfHash = new Map();               // hash -> nonce нашей отправки: если транзакцию выбросил узел, закрываем дыру в nonce
const seenTx = h => pub.getTransactionReceipt({ hash: h }).then(() => true, () => pub.getTransaction({ hash: h }).then(() => true, () => false));
// audit 1099 L-2: the hash of the signed transaction is known BEFORE it is sent. "already known" = our own transaction is in the pool -> success with that hash.
// "nonce too low" may be our own transaction already mined (the answer of a first attempt was lost): look for it, and for the authorization already used on chain,
// before signing a second transaction with a new nonce. A second send of the same authorization is never made.
async function submit(call, gasLimit, used, retried = false, prevHash = null) {
  let h = null, nonce = null;
  try {
    const fees = await cachedFees();
    if (localNonce === null) localNonce = await pub.getTransactionCount({ address: account.address, blockTag: "pending" });
    const tx = { chainId: CC.id, nonce: localNonce, gas: gasLimit, to: call.address, value: 0n, data: encodeFunctionData({ abi: call.abi, functionName: call.functionName, args: call.args }),
      ...(fees.maxFeePerGas ? { type: "eip1559", maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas || 0n } : { type: "legacy", gasPrice: fees.gasPrice }) };
    const ser = await account.signTransaction(tx); nonce = tx.nonce; h = keccak256(ser);
    const hash = await pub.sendRawTransaction({ serializedTransaction: ser });
    capMap(nonceOfHash, 500);
    nonceOfHash.set(hash, tx.nonce); localNonce++; return hash;
  } catch (e) {
    localNonce = null; feeCache.t = 0;
    const msg = String(e && (e.details || e.shortMessage || e.message) || e);
    if (h && /already known/i.test(msg)) { capMap(nonceOfHash, 500); nonceOfHash.set(h, nonce); return h; }
    // локальный nonce устарел (ключ релеера использовал кто-то ещё, рестарт узла): один повтор с nonce, взятым заново с узла, вместо отказа клиенту
    if (!retried && /nonce too low|nonce.*(lower|too low)/i.test(msg)) {
      for (const c of [h, prevHash]) if (c && await seenTx(c)) return c;
      if (used && await used().catch(() => false)) throw new Error("authorization already used");
      return submit(call, gasLimit, used, true, h);
    }
    throw e;
  }
}
// отправка со сверкой по квитанции; возвращает hash сразу. spent: резерв заменяется фактом по квитанции
const TRANSFER_CALL = args => ({ address: TOKEN, abi, functionName: "transferWithAuthorization", args });
const usedOf = (from, nonce) => () => pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, nonce] });
// audit 1099 L-3: "not found" only from viem's own not-found errors; any other error (rate limit, timeout, lagging backend) is "unknown". true = gone, false = exists, null = unknown
const isNF = (e, name) => { for (let i = 0; e && i < 5; i++, e = e.cause) if (e.name === name) return true; return false; };
async function probeTx(hash) {
  try { await pub.getTransactionReceipt({ hash }); return false; } catch (e) { if (!isNF(e, "TransactionReceiptNotFoundError")) return null; }
  try { await pub.getTransaction({ hash }); return false; } catch (e) { if (!isNF(e, "TransactionNotFoundError")) return null; }
  return true;
}
async function sendAndTrack(call, gasLimit, reserve, from, tag, onRevert, onGone = () => {}, used) {
  const d0 = st.day;
  let hash;
  const tq = Date.now(); let tw = 0;
  await (nonceLock = nonceLock.then(async () => { tw = Date.now() - tq; hash = await submit(call, gasLimit, used); }, () => {}));
  tmStats.n++; tmStats.wait += tw; tmStats.maxWait = Math.max(tmStats.maxWait, tw); tmStats.send += Date.now() - tq - tw;   // lock wait vs send time (see /relay/stats)
  // nonceLock не должен залипать после ошибки одной отправки: ошибка уходит вызывающему через throw ниже
  if (!hash) throw new Error("send failed");
  issued.set(hash.toLowerCase(), 1); capMap(issued, 5000);
  const watch = async () => {
    let rc;
    try { rc = await pub.waitForTransactionReceipt({ hash, timeout: STUCK_S * 1000 }); }
    catch {
      // audit 1099 L-3: dropped only if two independent probes a few seconds apart both say "not found" with no RPC error in between
      let gone = false; if ((await probeTx(hash)) === true) { await sleep(GONE_GAP_MS); gone = (await probeTx(hash)) === true; }
      if (gone) {                                              // узел выбросил транзакцию (не в пуле, не в блоке): закрыть дыру в nonce, иначе все следующие повиснут за ней
        const n = nonceOfHash.get(hash);
        log("dropped", tag, hash, "nonce", n);
        await (nonceLock = nonceLock.then(async () => {        // the gap fill takes the same lock as every send
          localNonce = null;
          try {
            if (n !== undefined && (await pub.getTransactionCount({ address: account.address, blockTag: "latest" })) <= n && (await pub.getTransactionCount({ address: account.address, blockTag: "pending" })) <= n) {
              const f = await cachedFees();
              const up = (x) => x + x * BUMP_PCT / 100n + 1n;
              const h = await wal.sendTransaction({ to: account.address, value: 0n, nonce: n, gas: 21000n, ...(f.maxFeePerGas ? { maxFeePerGas: up(f.maxFeePerGas), maxPriorityFeePerGas: up(f.maxPriorityFeePerGas || 0n) } : { gasPrice: up(f.gasPrice) }) });
              adj(d0, 21000n * (f.maxFeePerGas ? up(f.maxFeePerGas) : up(f.gasPrice)));   // the fill costs gas too
              log("nonce gap filled", n, h);
            }
          } catch (e) { log("ALERT nonce gap fill failed", n, String(e).slice(0, 80)); }
        }, () => {}));
        if (onRevert) onRevert(); else if (tag === "main") dec(st.perFrom, from);   // клиент может повторить: подпись не использована
        adj(d0, -reserve); onGone(); save(); return;                     // audit 1087 L-4c: транзакции нет ни в пуле, ни в блоке -- газа не потрачено, резерв возвращается
      }
      try {                                                    // застряла: та же nonce, комиссия выше -- один раз
        const tx = await pub.getTransaction({ hash });
        const up = (x) => x + x * BUMP_PCT / 100n + 1n;
        const fees = tx.maxFeePerGas ? { maxFeePerGas: up(tx.maxFeePerGas), maxPriorityFeePerGas: up(tx.maxPriorityFeePerGas || 0n) } : { gasPrice: up(tx.gasPrice) };
        log("stuck", tag, hash, "nonce", tx.nonce, "-> replacing with +" + BUMP_PCT + "%");
        const h2 = await wal.writeContract({ ...call, nonce: tx.nonce, gas: tx.gas, ...fees });
        log("replacement", tag, h2); remember(hash, h2);
        const extra = reserve * BUMP_PCT / 100n; adj(d0, extra); reserve += extra;   // audit 1087 L-4b: замена дороже на BUMP_PCT -- доплата в резерв, иначе бюджет занижен
      } catch (e) { log("replace failed", tag, hash, String(e).slice(0, 100)); }
      try { rc = await pub.waitForTransactionReceipt({ hash, timeout: 180_000, onReplaced: r => { log("replaced", hash, "->", r.transaction.hash, r.reason); remember(hash, r.transaction.hash); } }); }
      catch (e) { log("ALERT receipt wait failed", tag, hash, String(e).slice(0, 80)); return; }   // резерв остаётся (консервативно)
    }
    const spent = rc.gasUsed * (rc.effectiveGasPrice || 0n); adj(d0, spent - reserve);
    // audit 1087 M-1: откат НЕ возвращает лимит на адрес/плательщика (раньше возвращал -- можно было гонять откаты бесконечно за наш газ); возвращается только пропажа транзакции (выше)
    if (rc.status !== "success") log("reverted", tag, hash); else log("mined", tag, hash, "gas", formatEther(spent), "ETH");
    save();
  };
  watch().catch(e => log("watch error", String(e).slice(0, 80)));
  return hash;
}

export async function relay(b, ip) {
  ip = safeIp(ipKey(ip));                                              // audit 1087 M-1: IPv6 -> its /64; audit 1099 M-1: only an address-like token reaches the log
  if (!b || typeof b !== "object" || !isAddress(b.from || "") || !isAddress(b.to || "")) throw new Error("bad request");   // cheap shape checks first (audit 1099 M-2)
  if (b.endRecipient && !isAddress(b.endRecipient)) throw new Error("bad request");
  const from = getAddress(b.from), to = getAddress(b.to);
  // audit 1087 M-3: `to` is a 1Click deposit address for a private withdraw. A client that names the real end recipient (endRecipient) gets it screened too;
  // the web app screens it itself via /relay/screen before signing (sending it here would tell this server who receives the money).
  screen.check({ from, to, feeRecipient: account.address, ...(b.endRecipient ? { endRecipient: getAddress(b.endRecipient) } : {}) }, ip);      // before any RPC / counters / gas
  const main = parseAuth(b, ""); const value = main.value;
  if (value < MIN_VALUE) throw new Error("below the minimum of $0.10");
  let fee = null;
  if (b.feeAuth) {
    if (FEE_MIN === 0n) throw new Error("fees are not enabled");
    fee = parseAuth(b.feeAuth, " (fee)");
    if (fee.value < FEE_MIN) throw new Error("fee below the minimum");
  } else if (FEE_MIN > 0n) throw new Error("fee authorization required");
  // audit 1099 L-1: a repeat of an authorization we already sent gets the original hash(es), also after it was mined (kept DEDUPE_MS); no RPC, no counters
  const dupKey = (from + ":" + main.nonce).toLowerCase(), dup = dedupeGet(dupKey);
  if (dup) return dup;
  // audit 1099 M-2/I-6: everything that can be decided without the network is decided now: validity window and the EIP-712 signature (so a stranger cannot take the address lock, and junk costs no RPC)
  const nowS = BigInt(Math.floor(Date.now() / 1000));
  for (const a of fee ? [main, fee] : [main]) { if (a.validBefore <= nowS + 30n) throw new Error("authorization expires too soon"); if (a.validAfter > nowS) throw new Error("authorization not valid yet"); }
  for (const [a, dst] of fee ? [[main, to], [fee, account.address]] : [[main, to]]) {
    const signer = await recoverTypedDataAddress({ domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: TRANSFER_TYPES, primaryType: "TransferWithAuthorization",
      message: { from, to: dst, value: a.value, validAfter: a.validAfter, validBefore: a.validBefore, nonce: a.nonce }, signature: { r: a.r, s: a.s, v: BigInt(a.v) } }).catch(() => null);
    if (signer !== from) throw new Error("signature does not match the address");
  }
  roll();
  const d0 = st.day;
  // ---- синхронный блок: проверки суток и замок адреса без await между проверкой и записью
  if ((st.perIp[ip] || 0) >= MAX_PER_IP_PER_DAY) throw new Error("too many requests from this network today");
  if ((st.perFrom[from] || 0) >= MAX_PER_FROM) throw new Error("this address reached its withdrawal limit today; try tomorrow");
  if (inflight.has(from)) throw new Error("a withdrawal from this address is already in progress");
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
  inflight.add(from); st.perIp[ip] = (st.perIp[ip] || 0) + 1;
  let reserve = 0n, used = 0n, sent = false;
  try {
    const known = await fetch(INDEXER + "/stealth-api/known?addr=" + from, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => ({ known: false }));
    if (!known.known) throw new Error("not a stealth address paid through Stealth");
    const bal = await pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] });
    if (bal < value + (fee ? fee.value : 0n)) throw new Error("the address holds less than the requested amount");
    const list = [["main", main, to]]; if (fee) list.unshift(["fee", fee, account.address]);
    for (const [, a] of list) if (await pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, a.nonce] })) throw new Error("authorization already used");
    const bw = await pub.getBalance({ address: account.address });
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Error("relayer is out of gas funds, try again later"); }
    const calls = list.map(([tag, a, dst]) => [tag, [from, dst, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s]]);
    let gas = 0n; const lims = [];
    for (const [, args] of calls) {
      const g = await pub.estimateContractGas({ address: TOKEN, abi, functionName: "transferWithAuthorization", args, account });
      gas += g; lims.push(g * GAS_PAD_PCT / 100n);                  // лимит газа явно: оценка узла бывает впритык (OOG на ecrecover)
    }
    const fees = await cachedFees();
    const est = gas * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    // резерв под бюджет суток СИНХРОННО (после последнего await): параллельные заявки видят уже зарезервированное
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
    st.gas += est; reserve = est; save();
    const hashes = {};
    const n = BigInt(calls.length); let left = reserve;
    for (let i = 0; i < calls.length; i++) {                 // комиссия первой; резерв делится поровну между транзакциями
      const [tag, args] = calls[i]; const part = i === calls.length - 1 ? left : reserve / n; left -= part;
      const last = i === calls.length - 1;       // освободить запись о подписи, когда смайнена (или потеряна) последняя транзакция
      try { hashes[tag] = await sendAndTrack(TRANSFER_CALL(args), lims[i], part, from, tag, undefined, last ? () => pendingAuth.delete(dupKey) : undefined, usedOf(from, args[5])); }
      catch (e) { if (sent) log("ALERT fee sent but main failed", from, String(e).slice(0, 80)); throw e; }
      sent = true; used += part;
      if (tag === "main") { st.perFrom[from] = (st.perFrom[from] || 0) + 1; save(); }
    }
    log("relay", from, "->", to, (Number(value) / 1e6).toFixed(6), CC.token_symbol, hashes.main, fee ? "fee " + (Number(fee.value) / 1e6).toFixed(6) + " " + hashes.fee : "", "ip", ip);
    const res = fee ? { hash: hashes.main, feeHash: hashes.fee } : { hash: hashes.main };
    dedupeSet(dupKey, res); return res;
  } catch (e) {
    adj(d0, -(reserve - used));                                 // неотправленная часть резерва возвращается (в том же дне)
    if (!sent) dec(st.perIp, ip);                               // до отправки ничего не потрачено: вернуть и счётчик IP
    if (sent) save(); else saveSoon();                          // audit 1099 M-2: a failed request never writes the state synchronously
    throw e;
  } finally { inflight.delete(from); }
}

// ---- платёж одной подписью: payWithAuthorization на StealthPay (газ платит релеер, комиссия fee идёт релееру из суммы платежа)
const HEX1 = /^0x[0-9a-fA-F]{2}$/, EPH = /^0x0[23][0-9a-fA-F]{64}$/;
const TRANSFER_TYPES = { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
const RECEIVE_TYPES = { ReceiveWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] };
export const localPaymentNonce = (token, stealth, eph, tag, fee, feeTo) => keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "bytes1" }, { type: "uint256" }, { type: "address" }],
  [keccak256(toHex("StealthPay.payWithAuthorization")), BigInt(CC.id), STEALTHPAY, token, stealth, keccak256(eph), tag, fee, feeTo]));
export async function relayPay(b, ip) {
  if (!STEALTHPAY) throw new Error("payments are not enabled on this chain");
  if (!b || !b.auth || !isAddress(b.token || "") || !isAddress(b.stealth || "") || !isAddress(b.auth.from || "") || !isAddress(b.feeRecipient || "")) throw new Error("bad request");
  if (!EPH.test(b.eph || "") || !HEX1.test(b.viewTag || "")) throw new Error("bad ephemeral key or view tag");
  if (!HEX32.test(b.auth.r) || !HEX32.test(b.auth.s) || ![27, 28].includes(Number(b.auth.v))) throw new Error("bad signature fields");
  ip = safeIp(ipKey(ip));                                              // audit 1087 M-1: IPv6 -> its /64
  const token = getAddress(b.token), stealth = getAddress(b.stealth), feeTo = getAddress(b.feeRecipient), from = getAddress(b.auth.from);
  screen.check({ payer: from, stealth, feeRecipient: feeTo }, ip);   // before any RPC / counters / gas
  if (token !== TOKEN) throw new Error("unsupported token");
  const amount = BigInt(b.amount), fee = BigInt(b.fee), eph = b.eph.toLowerCase(), tag = b.viewTag.toLowerCase();
  const auth = { from, validAfter: BigInt(b.auth.validAfter || 0), validBefore: BigInt(b.auth.validBefore), v: Number(b.auth.v), r: b.auth.r, s: b.auth.s };
  if (amount < MIN_VALUE) throw new Error("below the minimum of $0.10");
  if (fee < PAY_FEE_MIN || fee >= amount) throw new Error("fee out of range");
  if (fee > 0n ? feeTo !== account.address : feeTo !== "0x0000000000000000000000000000000000000000") throw new Error("fee recipient must be the relayer");
  if (stealth === STEALTHPAY || stealth === TOKEN || stealth === account.address || stealth === from) throw new Error("bad destination");
  roll();
  const nonce = localPaymentNonce(token, stealth, eph, tag, fee, feeTo), dupKey = ("pay:" + from + ":" + nonce).toLowerCase(), dup = dedupeGet(dupKey);
  if (dup) return dup;                                                  // audit 1087 M-1 / 1099 L-1: the same payment already sent: the same hash, also after it was mined
  // audit 1099 M-2/I-6: validity window and signature are decided offline, before the lock and before any RPC
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (auth.validBefore <= now + 30n) throw new Error("authorization expires too soon");
  if (auth.validAfter > now) throw new Error("authorization not valid yet");
  const signer = await recoverTypedDataAddress({
    domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization",
    message: { from, to: STEALTHPAY, value: amount, validAfter: auth.validAfter, validBefore: auth.validBefore, nonce },
    signature: { r: auth.r, s: auth.s, v: BigInt(auth.v) } }).catch(() => null);
  if (!signer || signer !== from) throw new Error("signature does not match the payer");
  const d0 = st.day;
  if ((st.perIp[ip] || 0) >= MAX_PER_IP_PER_DAY) throw new Error("too many requests from this network today");
  if ((st.perPayer[from] || 0) >= MAX_PER_PAYER_PER_DAY) throw new Error("too many payments from this wallet today");
  const lockKey = "pay:" + from;
  if (inflight.has(lockKey)) throw new Error("a payment from this wallet is already in progress");
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
  inflight.add(lockKey); st.perIp[ip] = (st.perIp[ip] || 0) + 1; st.perPayer[from] = (st.perPayer[from] || 0) + 1;
  let reserve = 0n, sent = false;
  try {
    // независимые чтения -- одним залпом (раньше ~6 последовательных RPC на заявку); проверки применяются в прежнем порядке
    const [onchain, code, bal, used, bw] = await Promise.all([
      pub.readContract({ address: STEALTHPAY, abi: payAbi, functionName: "paymentNonce", args: [token, stealth, eph, tag, fee, feeTo] }),
      pub.getCode({ address: stealth }),
      pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] }),
      pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, nonce] }),
      pub.getBalance({ address: account.address })]);
    if (onchain.toLowerCase() !== nonce.toLowerCase()) throw new Error("payment nonce mismatch");
    if (code) throw new Error("destination is a contract");
    if (bal < amount) throw new Error("the wallet holds less than the amount");
    if (used) throw new Error("authorization already used");
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Error("relayer is out of gas funds, try again later"); }
    const call = { address: STEALTHPAY, abi: payAbi, functionName: "payWithAuthorization", args: [token, amount, stealth, eph, tag, fee, feeTo, auth] };
    const [g, fees] = await Promise.all([pub.estimateContractGas({ ...call, account }), cachedFees()]);   // estimateGas reverts iff the tx would revert
    const est = g * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
    st.gas += est; reserve = est; save();
    const hash = await sendAndTrack(call, g * GAS_PAD_PCT / 100n, reserve, from, "pay", () => dec(st.perPayer, from), () => pendingAuth.delete(dupKey), usedOf(from, nonce));   // onRevert = только пропавшая транзакция, не откат (audit 1087 M-1)
    sent = true; dedupeSet(dupKey, { hash });
    log("relay-pay", from, "->", stealth, (Number(amount) / 1e6).toFixed(6), CC.token_symbol, "fee", (Number(fee) / 1e6).toFixed(6), hash, "ip", ip);
    return { hash };
  } catch (e) {
    if (!sent) { adj(d0, -reserve); dec(st.perIp, ip); dec(st.perPayer, from); saveSoon(); }   // audit 1099 M-2: no synchronous write for a failed request
    throw e;
  } finally { inflight.delete(lockKey); }
}

/** GET /relay/status?hash=0x.. -> {hash: latest hash (follows a replacement), status: "pending"|"success"|"reverted"} */
const statusCache = new Map();
export async function statusOf(h) {
  if (!HEX32.test(h || "")) throw new Error("bad hash");
  const h0 = h.toLowerCase();
  if (!issued.has(h0) && !replacedBy.has(h0)) throw new Error("unknown hash");     // audit 1099 M-2: only hashes this relayer sent
  let cur = h0; for (let i = 0; i < 5 && replacedBy.has(cur); i++) cur = replacedBy.get(cur).toLowerCase();
  const c = statusCache.get(cur); if (c && Date.now() - c.t < 2000) return c.v;     // ... and at most one RPC per hash per 2 s
  const rc = await pub.getTransactionReceipt({ hash: cur }).catch(() => null);
  const v = { hash: cur, status: rc ? (rc.status === "success" ? "success" : "reverted") : "pending" };
  statusCache.set(cur, { t: Date.now(), v }); capMap(statusCache, 2000);
  return v;
}
export const stats = () => { roll(); return { chain: CHAIN, relayer: account.address, gas_spent_today_eth: formatEther(st.gas), gas_budget_eth: formatEther(GAS_BUDGET_WEI_PER_DAY), fee_min: FEE_MIN.toString(), pay_enabled: !!STEALTHPAY, stealthpay: STEALTHPAY, pay_fee: PAY_FEE.toString(), pay_fee_min: PAY_FEE_MIN.toString(), sends: tmStats.n, avg_lock_wait_ms: tmStats.n ? Math.round(tmStats.wait / tmStats.n) : 0, max_lock_wait_ms: tmStats.maxWait, avg_send_ms: tmStats.n ? Math.round(tmStats.send / tmStats.n) : 0 }; };

const fails = makeFailBudget({ perKey: FAIL_PER_IP, perMin: FAIL_PER_MIN }), refusedLines = makeLineLimiter(Number(E.STEALTH_RELAY_REFUSED_LOG_PER_MIN || 20)); let active = 0;
function serve() {
  http.createServer((req, res) => {
    const send = (code, obj) => { const s = JSON.stringify(obj); res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) }); res.end(s); };
    // audit 1087 L-5: route by the parsed pathname (never by a substring of the raw URL with its query string); POSTs take no query at all
    let u; try { u = new URL(req.url, "http://x"); } catch { return send(400, { error: "bad url" }); }
    const route = u.pathname.replace(/\/+$/, "").match(/^(?:\/stealth-api)?\/relay(\/(?:stats|screen|status|pay|sanctions-list))?$/);   // audit 1099 I-5: anchored at the front
    if (req.method === "GET" && route && route[1] === "/stats") return send(200, stats());
    if (req.method === "GET" && route && route[1] === "/screen") {                           // GET /stealth-api/relay/screen?addr=0x.. -> {addr,listed}
      const a = u.searchParams.get("addr") || ""; if (!isAddress(a)) return send(400, { error: "bad address" });
      return send(200, { addr: a.toLowerCase(), listed: screen.isListed(a) });
    }
    if (req.method === "GET" && route && route[1] === "/sanctions-list") {                   // the whole screened list, so the browser can screen recipients locally (never sent to us)
      const l = screen.list(), s = JSON.stringify({ updated: l.updated, count: l.count, addresses: l.addresses });
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "public, max-age=300", "Content-Length": Buffer.byteLength(s) }); return res.end(s);
    }
    if (req.method === "GET" && route && route[1] === "/status") return statusOf(u.searchParams.get("hash")).then(r => send(200, r), e => send(400, { error: String(e.message).slice(0, 80) }));
    const isPay = !!route && route[1] === "/pay";
    if (req.method !== "POST" || !route || (route[1] && !isPay) || u.search) return send(404, { error: "not found" });
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(), ipk = safeIp(ipKey(ip));
    // audit 1099 M-2: failure budgets and the concurrency cap are checked before the body is even read, independent of nginx
    const why = fails.check(ipk); if (why) return send(429, { error: why });
    if (active >= MAX_CONCURRENT) return send(503, { error: "busy, try again shortly" });
    active++; let released = false; const release = () => { if (!released) { released = true; active--; } };
    res.on("close", release);
    let body = ""; req.on("data", c => { body += c; if (body.length > 8192) req.destroy(); });
    req.on("end", async () => {
      try { send(200, await (isPay ? relayPay : relay)(JSON.parse(body), ip)); }
      catch (e) {
        const msg = String(e && (e.shortMessage || e.message) || e).slice(0, 160); fails.fail(ipk);
        const t = refusedLines.take();   // audit 1099 M-2: at most 20 refusal lines a minute, the rest is summarised
        if (t.summary) log("refused lines suppressed", t.summary);
        if (t.log) log("refused", ipk, JSON.stringify(msg));   // audit 1099 M-1: msg is data (later argument): neutralised; JSON.stringify: audit 1087 L-1, one line per refusal
        send(400, { error: msg });
      }
    });
  }).listen(Number(E.STEALTH_RELAY_PORT || 3874), "127.0.0.1", async () => {
    log("stealth relayer", CHAIN, "on", E.STEALTH_RELAY_PORT || 3874, "as", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) serve();
