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
   (3) Abuse limits are metered here, independent of nginx, and are PER KEY only (IPv4 or IPv6 /64; audit 1108): hourly failure counter, token bucket on RPC-costly requests; globally only
   the concurrency cap and the daily gas budget. No shared failure ceiling exists (it was the source of three rounds of lockout findings). Also coalesced state writes, rate-limited refusal log lines.
   API 127.0.0.1:3874: POST /stealth-api/relay {from,to,value,validAfter,validBefore,nonce,v,r,s[,feeAuth:{value,validAfter,validBefore,nonce,v,r,s}]}
   -> {hash[,feeHash]}; GET /stealth-api/relay/stats */
import { makeScreen } from "./sanctions/screen.mjs";
import { cleanLog, neutral, safeIp, capMap, makeFailBudget, makeTokenBucket, makeLineLimiter, makeCounters, parseAllow, ipKey, parseEnvLine, isLowS, failWeight, classifyError, Refusal, Upstream } from "./relay-util.mjs";
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
const RPC_BURST = Number(E.STEALTH_RELAY_RPC_BURST || 20), RPC_REFILL_MS = Number(E.STEALTH_RELAY_RPC_REFILL_MS || 10_000);   // audit 1108: per-network token bucket on RPC-costly requests (no global failure state)
// STEALTH_RELAY_ALLOW_KEYS: comma-separated IPs or /64 keys (empty by default). Those networks skip the per-key buckets, the per-IP / per-payer daily counters and the failure counter;
// every validation, the sanctions check, MAX_CONCURRENT and the daily gas budget still apply. One fixed log line per allowed request.
const ALLOW = parseAllow(E.STEALTH_RELAY_ALLOW_KEYS);                 // audit 1113 I-1: same canonicaliser as the request keys (a "/64" suffix and compressed IPv6 included)
const LOCK_MS = Number(E.STEALTH_RELAY_LOCK_MS || 40_000);                                        // audit 1108 L-2: one deadline for everything done while the nonce lock is held
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

const unsure = new Map();                    // ukey (from:nonce) -> { h, nonce, t, counted }: a transaction sent (or possibly sent) and not yet seen mined; persisted (audit 1108 L-1), TTL DEDUPE_MS
// ---- счётчики суток: gas = потрачено + зарезервировано под ещё не сверённые транзакции; пишутся в файл атомарно
const PERSIST_MAX = 10000;                   // audit 1113 M-3: bound of every persisted map
const lc = s => String(s).toLowerCase();     // audit 1113 L-1: one case for every guard key
const ukOf = (from, nonce) => lc(from + ":" + nonce);
export let st = { day: day(), gas: 0n, perFrom: {}, perPayer: {} };   // persisted: only what safety needs (gas, funded sends per address / payer, unsure)
const ipDay = makeCounters(20000);           // audit 1113 M-1/M-3: per-network SENT transactions today; memory only, LRU, never written to disk
const bump = (o, k) => { const n = (o[k] || 0) + 1; delete o[k]; o[k] = n; const ks = Object.keys(o); for (let i = 0; i < ks.length - PERSIST_MAX; i++) delete o[ks[i]]; };
// audit 1113 M-3: the state file is written asynchronously, at most once a second (saveSoon); only the record of an UNSURE send, made just before the send, is written at once (saveNow:
// restart safety, and bounded by the daily gas budget).
const snapshot = () => JSON.stringify({ day: st.day, gas: st.gas.toString(), perFrom: st.perFrom, perPayer: st.perPayer, unsure: [...unsure] });
let writing = null, again = false, lastWrite = 0, saveTimer = null, dirty = false;
const saveNow = () => {
  if (writing) { again = true; return writing; }
  writing = (async () => {
    try { do { again = false; dirty = false; const tmp = STATE_FILE + ".tmp"; await fs.promises.writeFile(tmp, snapshot()); await fs.promises.rename(tmp, STATE_FILE); } while (again); }
    catch (e) { log("ALERT state save failed", String(e).slice(0, 80)); }
    finally { writing = null; lastWrite = Date.now(); }
  })();
  return writing;
};
const saveSoon = () => { dirty = true; if (!saveTimer) { saveTimer = setTimeout(() => { saveTimer = null; saveNow(); }, Math.max(0, 1000 - (Date.now() - lastWrite))); saveTimer.unref(); } };
const saveSync = () => { if (!dirty && !saveTimer) return; try { const tmp = STATE_FILE + ".tmp"; fs.writeFileSync(tmp, snapshot()); fs.renameSync(tmp, STATE_FILE); dirty = false; } catch {} };
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { saveSync(); process.exit(0); });
process.on("exit", saveSync);
const dec = (o, k) => { if (o[k] > 1) o[k]--; else delete o[k]; };            // audit 1099 M-2: a counter back at zero is removed, so the maps cannot grow
const migFrom = (o) => { const r = {}; for (const [k, v] of Object.entries(o || {}).slice(-PERSIST_MAX)) { const n = v === true ? 1 : Number(v); if (Number.isFinite(n) && n > 0) r[k] = Math.floor(n); } return r; };   // старый формат: true -> 1
export const load = () => {
  try { const j = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    for (const [k, v] of Array.isArray(j.unsure) ? j.unsure : []) if (v && /^0x[0-9a-fA-F]{64}$/.test(v.h) && Date.now() - v.t < DEDUPE_MS) unsure.set(lc(k), { h: v.h, nonce: v.nonce, t: v.t, counted: !!v.counted });   // audit 1108 L-1: survives a restart (also across midnight); 1113 L-1: keys lower-cased
    capMap(unsure, 2000);
    if (j.day === day()) st = { day: j.day, gas: BigInt(j.gas), perFrom: migFrom(j.perFrom), perPayer: migFrom(j.perPayer) }; } catch {}
};
load();
const roll = () => { if (st.day !== day()) { st = { day: day(), gas: 0n, perFrom: {}, perPayer: {} }; ipDay.clear(); saveSoon(); } };
const inflight = new Set();                 // from-адреса, обрабатываемые прямо сейчас
// audit 1087 L-4a: поправки к суточному счётчику применяются только к тому дню, в котором сделан резерв (после полуночи новый день не «прощает» чужие траты)
const adj = (d0, delta) => { if (st.day === d0) { st.gas += delta; if (st.gas < 0n) st.gas = 0n; } };
// audit 1087 M-1: подписи, отправленные, но ещё не смайненные: from:nonce -> ответ клиенту. Повтор той же подписи получает тот же хеш (не вторую транзакцию, которая откатится и сожжёт газ).
// audit 1099 L-1: the entry is NOT deleted at the receipt: for DEDUPE_MS (24 h) a late retry still gets the original hash. Removed early only if the node lost the transaction (user may re-send).
const pendingAuth = new Map();
const dedupeGet = k => { k = lc(k); const e = pendingAuth.get(k); if (!e) return null; if (Date.now() - e.t > DEDUPE_MS) { pendingAuth.delete(k); return null; } return e.res; };
const dedupeSet = (k, res) => { k = lc(k); pendingAuth.delete(k); pendingAuth.set(k, { res, t: Date.now() }); capMap(pendingAuth, 20000); };
// audit "stuck tx": исходный хеш -> хеш замены; клиент спрашивает GET /relay/status?hash= и идёт по цепочке
const issued = new Map();                   // audit 1099 M-2: hashes we sent (and their replacements): /relay/status answers only for these, so it cannot be used as a free RPC proxy
const replacedBy = new Map(); const remember = (h, h2) => { replacedBy.set(h.toLowerCase(), h2); capMap(replacedBy, 2000); issued.set(h2.toLowerCase(), 1); capMap(issued, 5000); };   // audit 1099 I-2: drop the oldest, not everything
const rpcBucket = makeTokenBucket({ cap: RPC_BURST, refillMs: RPC_REFILL_MS });
let nonceLock = Promise.resolve();
let lastAlert = 0, lastLockAlert = 0;
const alertOnce = (...a) => { if (Date.now() - lastAlert > 60000) { lastAlert = Date.now(); log("ALERT", ...a); } };
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

function parseAuth(o, what) {
  if (!o || !HEX32.test(o.nonce) || !HEX32.test(o.r) || !HEX32.test(o.s)) throw new Error("bad signature fields" + what);
  const v = Number(o.v); if (![27, 28].includes(v)) throw new Error("bad v" + what);
  if (!isLowS(o.s)) throw new Error("bad signature (high s)" + what);          // audit 1102 L-3: offline, before any RPC
  return { value: BigInt(o.value), validAfter: BigInt(o.validAfter || 0), validBefore: BigInt(o.validBefore), nonce: lc(o.nonce), v, r: o.r, s: o.s };   // audit 1113 L-1: nonce in one case
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
// audit 1107 L-2: an AMBIGUOUS send error (timeout, dropped connection, 5xx) may hide a transaction the node did accept. Poll for our own hash POLLS times POLL_GAP_MS apart, but never
// longer than RECOVER_MS in total (the nonce lock is held meanwhile). If it is still unknown, remember the hash per authorization: the user's retry first looks for THAT transaction
// and is refused (not re-sent) while it may still be known, so a second transaction for the same authorization is never signed.
const POLLS = 3, POLL_GAP_MS = Number(E.STEALTH_RELAY_POLL_GAP_MS || 1000), RECOVER_MS = Number(E.STEALTH_RELAY_RECOVER_MS || 8000), UNSURE_MS = 60_000;
const AMBIGUOUS = /timeout|timed out|etimedout|econn|epipe|socket|fetch failed|network|connection|aborted|\b5\d\d\b|bad gateway|unavailable|http request failed|rate limit/i;
const within = (p, ms) => Promise.race([p.catch(() => false), new Promise(r => setTimeout(() => r(false), Math.max(1, ms)))]);
async function findTx(h, polls, deadline) {
  for (let i = 0; i < polls; i++) {
    if (await within(seenTx(h), deadline - Date.now())) return true;
    if (i < polls - 1) { if (Date.now() + POLL_GAP_MS >= deadline) break; await sleep(POLL_GAP_MS); }
  }
  return false;
}
// audit 1108 L-1/L-2: the hash of a signed transaction is written to `unsure` (and the state file) BEFORE it is sent, and removed only when it is mined or proven gone. A retry, also after a
// restart, looks for THAT transaction first, so a second one is never signed for the same authorization. ctl.dead = the nonce-lock deadline passed: such a holder must not send any more.
async function submit(call, gasLimit, used, retried = false, prevHash = null, ukey = null, ctl = { dead: false }, info = {}) {
  let h = null, nonce = null;
  const u = ukey && unsure.get(ukey);
  if (u) {
    const found = await findTx(u.h, 1, Date.now() + RECOVER_MS);
    if (ctl.dead) throw new Upstream("relayer busy, try again shortly");
    if (found) { capMap(nonceOfHash, 500); nonceOfHash.set(u.h, u.nonce); info.counted = !!u.counted; log("earlier unconfirmed send found", u.h); return u.h; }
    unsure.delete(ukey);
    if (used && await used().catch(() => false)) throw new Refusal("authorization already used", { honest: true });
    if (Date.now() - u.t < UNSURE_MS) { unsure.set(ukey, u); throw new Refusal("a previous attempt for this authorization is still being confirmed, try again in a minute", { honest: true }); }
  }
  try {
    const fees = await cachedFees();
    if (localNonce === null) { const n0 = await pub.getTransactionCount({ address: account.address, blockTag: "pending" }); if (ctl.dead) throw new Upstream("relayer busy, try again shortly"); localNonce = n0; }
    if (localNonce === null) throw new Upstream("relayer busy, try again shortly");     // audit 1113 L-2: never sign with a nonce another holder just reset
    const tx = { chainId: CC.id, nonce: localNonce, gas: gasLimit, to: call.address, value: 0n, data: encodeFunctionData({ abi: call.abi, functionName: call.functionName, args: call.args }),
      ...(fees.maxFeePerGas ? { type: "eip1559", maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas || 0n } : { type: "legacy", gasPrice: fees.gasPrice }) };
    const ser = await account.signTransaction(tx);
    if (ctl.dead) throw new Upstream("relayer busy, try again shortly");                // audit 1108 L-2: no send after the deadline
    nonce = tx.nonce; h = keccak256(ser);
    if (ukey) { unsure.set(ukey, { h, nonce, t: Date.now() }); capMap(unsure, 2000); await saveNow(); if (ctl.dead) { unsure.delete(ukey); saveSoon(); throw new Upstream("relayer busy, try again shortly"); } }   // persisted BEFORE the send (restart safety); nothing sent yet if the deadline passed meanwhile
    const hash = await pub.sendRawTransaction({ serializedTransaction: ser });
    if (ctl.dead) return hash;                                                          // audit 1113 L-2: released meanwhile: the new holder owns localNonce (not touched here); the entry stays in `unsure`, the user's retry finds this hash and reconciles it
    capMap(nonceOfHash, 500);
    nonceOfHash.set(hash, tx.nonce); localNonce++; return hash;
  } catch (e) {
    if (!ctl.dead) { localNonce = null; feeCache.t = 0; }                                // a timed-out holder never mutates the nonce state of the next one
    const msg = String(e && (e.details || e.shortMessage || e.message) || e);
    if (h && /already known/i.test(msg)) { capMap(nonceOfHash, 500); nonceOfHash.set(h, nonce); return h; }
    // audit 1102 L-2: any other send error may be a lost ANSWER (timeout, dropped connection, 5xx) of a transaction the node did accept: look for our own hash before giving up,
    // otherwise the user's retry of the same authorization would sign a second transaction that reverts on our gas
    if (h && !/nonce too low|nonce.*(lower|too low)/i.test(msg)) {
      const amb = AMBIGUOUS.test(msg) || /^(HttpRequestError|TimeoutError|WebSocketRequestError)$/.test(String(e && e.name));
      if (await findTx(h, amb ? POLLS : 1, Date.now() + RECOVER_MS)) { capMap(nonceOfHash, 500); nonceOfHash.set(h, nonce); log("send answer lost, transaction found", h); return h; }
      if (!amb && ukey) { unsure.delete(ukey); saveSoon(); }                              // the node refused it outright: nothing is out there
      if (amb) throw new Upstream("the send could not be confirmed, try again in a minute");   // audit 1108 M-3: lost answer of OUR transaction (entry stays in `unsure`): infrastructure trouble, not the caller's
    }
    // локальный nonce устарел (ключ релеера использовал кто-то ещё, рестарт узла): один повтор с nonce, взятым заново с узла, вместо отказа клиенту
    if (!retried && /nonce too low|nonce.*(lower|too low)/i.test(msg)) {
      for (const c of [h, prevHash]) if (c && await seenTx(c)) { if (ukey && c !== h) unsure.set(ukey, { h: c, nonce: nonce ?? 0, t: Date.now() }); return c; }
      if (ukey) { unsure.delete(ukey); saveSoon(); }
      if (used && await used().catch(() => false)) throw new Refusal("authorization already used", { honest: true });
      if (ctl.dead) throw new Upstream("relayer busy, try again shortly");
      return submit(call, gasLimit, used, true, h, ukey, ctl, info);
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
// audit 1113 L-2: EVERY holder of the nonce lock (send and gap fill) runs under ONE deadline (LOCK_MS); on expiry ctl.dead is set, the local nonce is reset once, and the holder
// can no longer send or change nonce state (submit() checks ctl.dead). A send that still resolves after that is reconciled through `unsure`.
async function withNonceLock(tag, fn) {
  const ctl = { dead: false, tw: 0 }, tq = Date.now();
  await (nonceLock = nonceLock.then(() => {}, () => {}).then(() => new Promise((res, rej) => {   // the previous holder's failure must not skip THIS one
    ctl.tw = Date.now() - tq;
    const timer = setTimeout(() => { ctl.dead = true; localNonce = null; feeCache.t = 0; if (Date.now() - lastLockAlert > 60000) { lastLockAlert = Date.now(); log("ALERT nonce lock deadline exceeded", tag, "after", LOCK_MS, "ms"); } rej(new Upstream("relayer busy, try again shortly")); }, LOCK_MS);
    fn(ctl).then(() => { clearTimeout(timer); res(); }, e => { clearTimeout(timer); rej(e); });
  })));
  return ctl;
}
async function sendAndTrack(call, gasLimit, reserve, from, tag, onRevert, onGone = () => {}, used, ukey = null, info = {}) {
  const d0 = st.day;
  let hash;
  const tq = Date.now();
  const ctl = await withNonceLock(tag, c => submit(call, gasLimit, used, false, null, ukey, c, info).then(h => { hash = h; }));
  const tw = ctl.tw;
  tmStats.n++; tmStats.wait += tw; tmStats.maxWait = Math.max(tmStats.maxWait, tw); tmStats.send += Date.now() - tq - tw;   // lock wait vs send time (see /relay/stats)
  // nonceLock не должен залипать после ошибки одной отправки: ошибка уходит вызывающему через throw ниже
  if (!hash) throw new Error("send failed");
  issued.set(hash.toLowerCase(), 1); capMap(issued, 5000);
  const clearUnsure = () => { const x = ukey && unsure.get(ukey); if (x && x.h === hash) unsure.delete(ukey); };   // mined or proven gone: no longer "unconfirmed"
  const watch = async () => {
    let rc;
    try { rc = await pub.waitForTransactionReceipt({ hash, timeout: STUCK_S * 1000 }); }
    catch {
      // audit 1099 L-3: dropped only if two independent probes a few seconds apart both say "not found" with no RPC error in between
      let gone = false; if ((await probeTx(hash)) === true) { await sleep(GONE_GAP_MS); gone = (await probeTx(hash)) === true; }
      if (gone) {                                              // узел выбросил транзакцию (не в пуле, не в блоке): закрыть дыру в nonce, иначе все следующие повиснут за ней
        const n = nonceOfHash.get(hash);
        log("dropped", tag, hash, "nonce", n);
        await withNonceLock("gap fill", async ctl => {        // the gap fill takes the same lock, under the same deadline
          localNonce = null;
          try {
            if (n !== undefined && (await pub.getTransactionCount({ address: account.address, blockTag: "latest" })) <= n && (await pub.getTransactionCount({ address: account.address, blockTag: "pending" })) <= n) {
              const f = await cachedFees();
              const up = (x) => x + x * BUMP_PCT / 100n + 1n;
              if (ctl.dead) return;
              const h = await wal.sendTransaction({ to: account.address, value: 0n, nonce: n, gas: 21000n, ...(f.maxFeePerGas ? { maxFeePerGas: up(f.maxFeePerGas), maxPriorityFeePerGas: up(f.maxPriorityFeePerGas || 0n) } : { gasPrice: up(f.gasPrice) }) });
              adj(d0, 21000n * (f.maxFeePerGas ? up(f.maxFeePerGas) : up(f.gasPrice)));   // the fill costs gas too
              log("nonce gap filled", n, h);
            }
          } catch (e) { log("ALERT nonce gap fill failed", n, String(e).slice(0, 80)); }
        }).catch(() => {});
        if (onRevert) onRevert(); else if (tag === "main") dec(st.perFrom, from);   // клиент может повторить: подпись не использована
        adj(d0, -reserve); onGone(); clearUnsure(); saveSoon(); return;                     // audit 1087 L-4c: транзакции нет ни в пуле, ни в блоке -- газа не потрачено, резерв возвращается
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
    clearUnsure();
    const spent = rc.gasUsed * (rc.effectiveGasPrice || 0n); adj(d0, spent - reserve);
    // audit 1087 M-1: откат НЕ возвращает лимит на адрес/плательщика (раньше возвращал -- можно было гонять откаты бесконечно за наш газ); возвращается только пропажа транзакции (выше)
    if (rc.status !== "success") log("reverted", tag, hash); else log("mined", tag, hash, "gas", formatEther(spent), "ETH");
    saveSoon();
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
  // audit 1099 M-2/I-6: everything that can be decided without the network is decided now: the EIP-712 signature (so a stranger cannot take the address lock, and junk costs no RPC)
  for (const [a, dst] of fee ? [[main, to], [fee, account.address]] : [[main, to]]) {
    const signer = await recoverTypedDataAddress({ domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: TRANSFER_TYPES, primaryType: "TransferWithAuthorization",
      message: { from, to: dst, value: a.value, validAfter: a.validAfter, validBefore: a.validBefore, nonce: a.nonce }, signature: { r: a.r, s: a.s, v: BigInt(a.v) } }).catch(() => null);
    if (signer !== from) throw new Error("signature does not match the address");
  }
  // audit 1099 L-1 / 1108 M-2: a repeat of an authorization we already sent (and whose signature checks out) gets the original hash(es), also after it was mined (kept DEDUPE_MS).
  // No RPC, no counters, no budget of any kind is touched by a hit.
  const dupKey = (from + ":" + main.nonce).toLowerCase(), dup = dedupeGet(dupKey);
  if (dup) return dup;
  const nowS = BigInt(Math.floor(Date.now() / 1000));
  for (const a of fee ? [main, fee] : [main]) { if (a.validBefore <= nowS + 30n) throw new Refusal("authorization expires too soon", { honest: true }); if (a.validAfter > nowS) throw new Refusal("authorization not valid yet", { honest: true }); }
  roll();
  const d0 = st.day;
  // ---- синхронный блок: проверки суток и замок адреса без await между проверкой и записью
  const allowed = ALLOW.has(ip);
  if (!allowed && ipDay.get(ip) >= MAX_PER_IP_PER_DAY) throw new Refusal("too many requests from this network today", { honest: true });   // audit 1113 M-1: counts SENT transactions only
  if ((st.perFrom[from] || 0) >= MAX_PER_FROM) throw new Refusal("this address reached its withdrawal limit today; try tomorrow", { honest: true });
  if (inflight.has(from)) throw new Refusal("a withdrawal from this address is already in progress", { honest: true });
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Refusal("relayer gas budget for today is spent", { honest: true });
  if (!allowed && !rpcBucket.take(ip)) throw new Refusal("too many requests from this network, try again shortly", { honest: true });   // audit 1108: per-key admission of RPC-costly work
  inflight.add(from);
  let reserve = 0n, used = 0n, sent = false;
  try {
    const known = await fetch(INDEXER + "/stealth-api/known?addr=" + from, { signal: AbortSignal.timeout(5000) }).then(r => { if (!r.ok) throw new Error("indexer " + r.status); return r.json(); }).catch(e => { throw new Upstream("indexer unavailable: " + String(e && e.message || e).slice(0, 60)); });   // audit 1107 M-1: an indexer outage is not the caller's failure
    if (!known.known) throw new Refusal("not a stealth address paid through Stealth");
    const bal = await pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] });
    if (bal < value + (fee ? fee.value : 0n)) throw new Refusal("the address holds less than the requested amount", { honest: true });
    const list = [["main", main, to]]; if (fee) list.unshift(["fee", fee, account.address]);
    for (const [, a] of list) if (await pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, a.nonce] })) throw new Refusal("authorization already used", { honest: true });
    const bw = await pub.getBalance({ address: account.address });
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Refusal("relayer is out of gas funds, try again later", { honest: true }); }
    const calls = list.map(([tag, a, dst]) => [tag, [from, dst, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s]]);
    let gas = 0n; const lims = [];
    for (const [, args] of calls) {
      const g = await pub.estimateContractGas({ address: TOKEN, abi, functionName: "transferWithAuthorization", args, account });
      gas += g; lims.push(g * GAS_PAD_PCT / 100n);                  // лимит газа явно: оценка узла бывает впритык (OOG на ecrecover)
    }
    const fees = await cachedFees();
    const est = gas * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    // резерв под бюджет суток СИНХРОННО (после последнего await): параллельные заявки видят уже зарезервированное
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Refusal("relayer gas budget for today is spent", { honest: true });
    st.gas += est; reserve = est; saveSoon();
    const hashes = {};
    const n = BigInt(calls.length); let left = reserve;
    for (let i = 0; i < calls.length; i++) {                 // комиссия первой; резерв делится поровну между транзакциями
      const [tag, args] = calls[i]; const part = i === calls.length - 1 ? left : reserve / n; left -= part;
      const last = i === calls.length - 1;       // освободить запись о подписи, когда смайнена (или потеряна) последняя транзакция
      const uk = ukOf(from, args[5]), info = {};
      try { hashes[tag] = await sendAndTrack(TRANSFER_CALL(args), lims[i], part, from, tag, undefined, last ? () => pendingAuth.delete(dupKey) : undefined, usedOf(from, args[5]), uk, info); }
      catch (e) { if (sent) log("ALERT fee sent but main failed", from, String(e).slice(0, 80)); throw e; }
      sent = true; used += part;
      if (tag === "main") { if (!info.counted) { bump(st.perFrom, from); if (!allowed) ipDay.inc(ip); } const x = unsure.get(uk); if (x) x.counted = true; saveSoon(); }   // audit 1108 I-1: a send recovered from an earlier attempt that was already counted counts once
    }
    log("relay", from, "->", to, (Number(value) / 1e6).toFixed(6), CC.token_symbol, hashes.main, fee ? "fee " + (Number(fee.value) / 1e6).toFixed(6) + " " + hashes.fee : "", "ip", ip);
    const res = fee ? { hash: hashes.main, feeHash: hashes.fee } : { hash: hashes.main };
    dedupeSet(dupKey, res); return res;
  } catch (e) {
    const err = classifyError(e);                               // audit 1108 M-3: by cause; only demonstrable transport trouble is Upstream
    adj(d0, -(reserve - used));                                 // неотправленная часть резерва возвращается (в том же дне)
    if (err instanceof Upstream && !sent && !allowed) rpcBucket.refund(ip);   // audit 1108: ONLY infrastructure trouble is refunded to the key's token bucket
    if (reserve > 0n || sent) saveSoon();                       // a refusal that changed nothing durable writes nothing
    throw err;
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
  if (!isLowS(b.auth.s)) throw new Error("bad signature (high s)");           // audit 1102 L-3
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
  const nonce = localPaymentNonce(token, stealth, eph, tag, fee, feeTo), dupKey = ("pay:" + from + ":" + nonce).toLowerCase();
  // audit 1099 M-2/I-6: the signature is decided offline, before the lock and before any RPC
  const signer = await recoverTypedDataAddress({
    domain: { name: CC.domain.name, version: CC.domain.version, chainId: CC.id, verifyingContract: TOKEN }, types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization",
    message: { from, to: STEALTHPAY, value: amount, validAfter: auth.validAfter, validBefore: auth.validBefore, nonce },
    signature: { r: auth.r, s: auth.s, v: BigInt(auth.v) } }).catch(() => null);
  if (!signer || signer !== from) throw new Error("signature does not match the payer");
  const dup = dedupeGet(dupKey);
  if (dup) return dup;                                                  // audit 1087 M-1 / 1099 L-1 / 1108 M-2: the same (signed) payment already sent: the same hash, also after it was mined; touches no budget
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (auth.validBefore <= now + 30n) throw new Refusal("authorization expires too soon", { honest: true });
  if (auth.validAfter > now) throw new Refusal("authorization not valid yet", { honest: true });
  const d0 = st.day;
  const allowed = ALLOW.has(ip);
  if (!allowed && ipDay.get(ip) >= MAX_PER_IP_PER_DAY) throw new Refusal("too many requests from this network today", { honest: true });
  if (!allowed && (st.perPayer[from] || 0) >= MAX_PER_PAYER_PER_DAY) throw new Refusal("too many payments from this wallet today", { honest: true });
  const lockKey = "pay:" + from;
  if (inflight.has(lockKey)) throw new Refusal("a payment from this wallet is already in progress", { honest: true });
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Refusal("relayer gas budget for today is spent", { honest: true });
  if (!allowed && !rpcBucket.take(ip)) throw new Refusal("too many requests from this network, try again shortly", { honest: true });   // audit 1108
  inflight.add(lockKey);
  let reserve = 0n, sent = false;
  try {
    // независимые чтения -- одним залпом (раньше ~6 последовательных RPC на заявку); проверки применяются в прежнем порядке
    // audit 1102 M-1: ONE cheap read first -- a self-signed junk request from an empty wallet costs one RPC instead of five
    const bal = await pub.readContract({ address: TOKEN, abi, functionName: "balanceOf", args: [from] });
    if (bal < amount) throw new Refusal("the wallet holds less than the amount", { honest: true });
    const [onchain, code, used, bw] = await Promise.all([
      pub.readContract({ address: STEALTHPAY, abi: payAbi, functionName: "paymentNonce", args: [token, stealth, eph, tag, fee, feeTo] }),
      pub.getCode({ address: stealth }),
      pub.readContract({ address: TOKEN, abi, functionName: "authorizationState", args: [from, nonce] }),
      pub.getBalance({ address: account.address })]);
    if (onchain.toLowerCase() !== nonce.toLowerCase()) throw new Refusal("payment nonce mismatch");
    if (code) throw new Refusal("destination is a contract");
    if (used) throw new Refusal("authorization already used", { honest: true });
    if (bw < MIN_BALANCE_WEI) { alertOnce("relayer balance low:", formatEther(bw), "ETH < threshold", formatEther(MIN_BALANCE_WEI)); throw new Refusal("relayer is out of gas funds, try again later", { honest: true }); }
    const call = { address: STEALTHPAY, abi: payAbi, functionName: "payWithAuthorization", args: [token, amount, stealth, eph, tag, fee, feeTo, auth] };
    const [g, fees] = await Promise.all([pub.estimateContractGas({ ...call, account }), cachedFees()]);   // estimateGas reverts iff the tx would revert
    const est = g * GAS_PAD_PCT / 100n * (fees.maxFeePerGas || fees.gasPrice || 0n);
    if (st.gas + est > GAS_BUDGET_WEI_PER_DAY) throw new Refusal("relayer gas budget for today is spent", { honest: true });
    st.gas += est; reserve = est; saveSoon();
    const hash = await sendAndTrack(call, g * GAS_PAD_PCT / 100n, reserve, from, "pay", () => dec(st.perPayer, from), () => pendingAuth.delete(dupKey), usedOf(from, nonce), ukOf(from, nonce));   // onRevert = только пропавшая транзакция, не откат (audit 1087 M-1)
    sent = true; if (!allowed) { bump(st.perPayer, from); ipDay.inc(ip); } saveSoon(); dedupeSet(dupKey, { hash });   // audit 1113 M-1: the daily counters are charged only for a transaction the relayer actually sent
    log("relay-pay", from, "->", stealth, (Number(amount) / 1e6).toFixed(6), CC.token_symbol, "fee", (Number(fee) / 1e6).toFixed(6), hash, "ip", ip);
    return { hash };
  } catch (e) {
    const err = classifyError(e);                                                            // audit 1108 M-3
    if (!sent) { adj(d0, -reserve); if (err instanceof Upstream && !allowed) rpcBucket.refund(ip); if (reserve > 0n) saveSoon(); }   // 1108: only Upstream is refunded
    throw err;
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

const fails = makeFailBudget({ perKey: FAIL_PER_IP }), refusedLines = makeLineLimiter(Number(E.STEALTH_RELAY_REFUSED_LOG_PER_MIN || 20)); let active = 0;
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
    const allowedNet = ALLOW.has(ipk);
    if (allowedNet) log("allow-listed request", ipk, isPay ? "pay" : "relay");
    const why = allowedNet ? null : fails.check(ipk); if (why) return send(429, { error: why });
    if (active >= MAX_CONCURRENT) return send(503, { error: "busy, try again shortly" });
    // audit 1113 M-2: the slot is held until the WORK ends (finally below), not until the client disconnects; a request that dies before its body is complete frees it on close
    active++; let released = false, started = false; const release = () => { if (!released) { released = true; active--; } };
    req.on("close", () => { if (!started) release(); });
    let body = ""; req.on("data", c => { body += c; if (body.length > 8192) req.destroy(); });
    req.on("end", async () => {
      started = true;
      try { const r = await (isPay ? relayPay : relay)(JSON.parse(body), ip); send(200, r); }
      catch (e) {
        const msg = String(e && (e.shortMessage || e.message) || e).slice(0, 160);
        if (e instanceof Upstream) {                           // audit 1107 M-1: RPC / indexer trouble: 503, no failure budget consumed (an outage must not lock honest users out)
          const t = refusedLines.take(); if (t.log) log("upstream trouble", ipk, JSON.stringify(msg));
          return send(503, { error: "network busy, try again shortly" });
        }
        if (!allowedNet) fails.fail(ipk, failWeight(e));                      // audit 1107 L-1: weight by error CLASS, never by message text
        const t = refusedLines.take();   // audit 1099 M-2: at most 20 refusal lines a minute, the rest is summarised
        if (t.summary) log("refused lines suppressed", t.summary);
        if (t.log) { log("refused", ipk, JSON.stringify(msg)); if (e.unknown) log("unclassified error", ipk, JSON.stringify(e.detail)); }   // audit 1113 I-5: ONE log token per refusal   // audit 1099 M-1: msg is data (later argument): neutralised; JSON.stringify: audit 1087 L-1, one line per refusal
        send(400, { error: msg });
      } finally { release(); }
    });
  }).listen(Number(E.STEALTH_RELAY_PORT || 3874), "127.0.0.1", async () => {
    log("stealth relayer", CHAIN, "on", E.STEALTH_RELAY_PORT || 3874, "as", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) serve();
