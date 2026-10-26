/* Stealth relayer: отправляет за клиента USDC.transferWithAuthorization (EIP-3009) со стелс-адреса, чтобы одноразовому
   адресу не нужен был ETH на газ. Подпись делает клиент у себя ключом стелс-адреса; релеер платит газ своим ОТДЕЛЬНЫМ
   ключом (RELAYER_KEY из /opt/stealth/relayer.env) и шлёт транзакцию. Ограничения против расхода нашего газа чужими:
   адрес должен быть объявлен через наш StealthPay (индексатор /known), один вывод с адреса в сутки, бюджет газа в сутки,
   лимит на IP; учитываются только успешные транзакции. Ответ -- хеш сразу после отправки, квитанцию клиент ждёт сам.
   API 127.0.0.1:3874: POST /stealth-api/relay {from,to,value,validAfter,validBefore,nonce,v,r,s} -> {hash}; GET /stealth-api/relay/stats */
import http from "http"; import fs from "fs";
import { createPublicClient, createWalletClient, http as vhttp, parseAbi, formatEther, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
for (const f of ["/opt/mprhedged/exec/.env", "/opt/stealth/relayer.env"]) {
  if (!fs.existsSync(f)) continue;
  for (const line of fs.readFileSync(f, "utf8").split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)=["']?([^"'#\n]+)/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
  }
}
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const abi = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "function balanceOf(address) view returns (uint256)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
]);
const MAX_PER_IP_PER_DAY = Number(process.env.STEALTH_RELAY_MAX_PER_IP || 30);
const GAS_BUDGET_WEI_PER_DAY = BigInt(process.env.STEALTH_RELAY_GAS_BUDGET_WEI || "200000000000000");   // 0.0002 ETH/day
const MIN_VALUE = BigInt(process.env.STEALTH_RELAY_MIN_USDC || "100000");                                   // $0.10
const INDEXER = process.env.STEALTH_INDEXER || "http://127.0.0.1:3873";
const KEY = (process.env.RELAYER_KEY || "").trim();
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY)) { console.error("RELAYER_KEY missing: generate one into /opt/stealth/relayer.env"); process.exit(1); }
const account = privateKeyToAccount(KEY);
const transport = vhttp(process.env.BASE_RPC2 || process.env.BASE_RPC, { timeout: 30000 });
const pub = createPublicClient({ chain: base, transport }); const wal = createWalletClient({ account, chain: base, transport });
const LOG = "/opt/stealth/relayer.log";
const log = (...a) => { const s = new Date().toISOString() + " " + a.join(" "); console.log(s); fs.appendFileSync(LOG, s + "\n"); };
const day = () => Math.floor(Date.now() / 86400000);
let st = { day: day(), gas: 0n, perIp: {}, perFrom: {} };
const roll = () => { if (st.day !== day()) st = { day: day(), gas: 0n, perIp: {}, perFrom: {} }; };
let nonceLock = Promise.resolve();

async function relay(b, ip) {
  const from = getAddress(b.from), to = getAddress(b.to);
  const value = BigInt(b.value); const validAfter = BigInt(b.validAfter || 0), validBefore = BigInt(b.validBefore);
  if (!/^0x[0-9a-fA-F]{64}$/.test(b.nonce) || !/^0x[0-9a-fA-F]{64}$/.test(b.r) || !/^0x[0-9a-fA-F]{64}$/.test(b.s)) throw new Error("bad signature fields");
  const v = Number(b.v); if (![27, 28].includes(v)) throw new Error("bad v");
  if (value < MIN_VALUE) throw new Error("below the minimum of $0.10");
  roll();
  if ((st.perIp[ip] || 0) >= MAX_PER_IP_PER_DAY) throw new Error("too many requests from this network today");
  if (st.perFrom[from]) throw new Error("this address already withdrew today; try tomorrow");
  if (st.gas >= GAS_BUDGET_WEI_PER_DAY) throw new Error("relayer gas budget for today is spent");
  const known = await fetch(INDEXER + "/stealth-api/known?addr=" + from).then(r => r.json()).catch(() => ({ known: false }));
  if (!known.known) throw new Error("not a stealth address paid through Stealth");
  const bal = await pub.readContract({ address: USDC, abi, functionName: "balanceOf", args: [from] });
  if (bal < value) throw new Error("the address holds less than the requested amount");
  if (await pub.readContract({ address: USDC, abi, functionName: "authorizationState", args: [from, b.nonce] })) throw new Error("authorization already used");
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (validBefore <= now + 30n) throw new Error("authorization expires too soon");
  const args = [from, to, value, validAfter, validBefore, b.nonce, v, b.r, b.s];
  await pub.simulateContract({ address: USDC, abi, functionName: "transferWithAuthorization", args, account });
  let hash;
  await (nonceLock = nonceLock.then(async () => { hash = await wal.writeContract({ address: USDC, abi, functionName: "transferWithAuthorization", args }); }));
  st.perIp[ip] = (st.perIp[ip] || 0) + 1; st.perFrom[from] = true;
  log("relay", from, "->", to, (Number(value) / 1e6).toFixed(6), "USDC", hash, "ip", ip);
  pub.waitForTransactionReceipt({ hash, timeout: 180_000 }).then(rc => {
    const spent = rc.gasUsed * (rc.effectiveGasPrice || 0n); st.gas += spent;
    if (rc.status !== "success") { delete st.perFrom[from]; log("reverted", hash); } else log("mined", hash, "gas", formatEther(spent), "ETH");
  }).catch(e => log("receipt wait failed", hash, String(e).slice(0, 80)));
  return { hash };
}

http.createServer((req, res) => {
  const send = (code, obj) => { const s = JSON.stringify(obj); res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) }); res.end(s); };
  if (req.method === "GET" && req.url.endsWith("/relay/stats")) { roll(); return send(200, { relayer: account.address, gas_spent_today_eth: formatEther(st.gas), gas_budget_eth: formatEther(GAS_BUDGET_WEI_PER_DAY) }); }
  if (req.method !== "POST" || !req.url.endsWith("/relay")) return send(404, { error: "not found" });
  let body = ""; req.on("data", c => { body += c; if (body.length > 4096) req.destroy(); });
  req.on("end", async () => {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    try { send(200, await relay(JSON.parse(body), ip)); }
    catch (e) { const msg = String(e && (e.shortMessage || e.message) || e).slice(0, 160); log("refused", ip, msg); send(400, { error: msg }); }
  });
}).listen(Number(process.env.STEALTH_RELAY_PORT || 3874), "127.0.0.1", async () => {
  log("stealth relayer on 3874 as", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
});
