/* Stealth relayer: отправляет за клиента USDC.transferWithAuthorization (EIP-3009) со стелс-адреса, чтобы
   одноразовому адресу не нужен был ETH на газ (ETH с основного кошелька связал бы адреса). Подпись делает
   клиент у себя ключом стелс-адреса; релеер только платит газ и шлёт транзакцию. Ничьих ключей, кроме своего, не видит.
   Защита: лимит на число переводов в сутки и на один адрес-получатель; только USDC Base; предохранитель
   вывода H1/H2 (не на кошелёк, который зарегистрировал ключи, и не обратно плательщику) проверяется у клиента,
   здесь -- только формат и лимиты. API 127.0.0.1:3874: POST /stealth-api/relay {from,to,value,validAfter,validBefore,nonce,v,r,s}
   GET /stealth-api/relay/stats */
import http from "http"; import fs from "fs";
import { createPublicClient, createWalletClient, http as vhttp, parseAbi, formatEther, isAddress, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
for (const line of fs.readFileSync("/opt/mprhedged/exec/.env", "utf8").split("\n")) {
  const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)=["']?([^"'#\n]+)/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
}
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const abi = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "function balanceOf(address) view returns (uint256)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
]);
const MAX_PER_DAY = Number(process.env.STEALTH_RELAY_MAX_PER_DAY || 200);
const MAX_PER_TO_PER_DAY = Number(process.env.STEALTH_RELAY_MAX_PER_TO || 20);
const MIN_VALUE = BigInt(process.env.STEALTH_RELAY_MIN_USDC || "100000");       // $0.10
const account = privateKeyToAccount(process.env.MPRH_EXECUTOR_KEY.trim());
const transport = vhttp(process.env.BASE_RPC2 || process.env.BASE_RPC, { timeout: 30000 });
const pub = createPublicClient({ chain: base, transport }); const wal = createWalletClient({ account, chain: base, transport });
const LOG = "/opt/stealth/relayer.log";
const log = (...a) => { const s = new Date().toISOString() + " " + a.join(" "); console.log(s); fs.appendFileSync(LOG, s + "\n"); };
const day = () => Math.floor(Date.now() / 86400000);
let stats = { day: day(), n: 0, perTo: {} };
const bump = to => { if (stats.day !== day()) stats = { day: day(), n: 0, perTo: {} }; stats.n++; stats.perTo[to] = (stats.perTo[to] || 0) + 1; };
let busy = Promise.resolve();

async function relay(b) {
  const from = getAddress(b.from), to = getAddress(b.to);
  const value = BigInt(b.value); const validAfter = BigInt(b.validAfter || 0), validBefore = BigInt(b.validBefore);
  if (!/^0x[0-9a-fA-F]{64}$/.test(b.nonce) || !/^0x[0-9a-fA-F]{64}$/.test(b.r) || !/^0x[0-9a-fA-F]{64}$/.test(b.s)) throw new Error("bad signature fields");
  const v = Number(b.v); if (![27, 28].includes(v)) throw new Error("bad v");
  if (value < MIN_VALUE) throw new Error("below the minimum of $0.10");
  if (stats.day === day() && stats.n >= MAX_PER_DAY) throw new Error("relayer daily limit reached");
  if (stats.day === day() && (stats.perTo[to] || 0) >= MAX_PER_TO_PER_DAY) throw new Error("too many transfers to this address today");
  const bal = await pub.readContract({ address: USDC, abi, functionName: "balanceOf", args: [from] });
  if (bal < value) throw new Error("the stealth address holds " + Number(bal) / 1e6 + " USDC, not " + Number(value) / 1e6);
  if (await pub.readContract({ address: USDC, abi, functionName: "authorizationState", args: [from, b.nonce] })) throw new Error("authorization already used");
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (validBefore <= now + 30n) throw new Error("authorization expires too soon");
  // симуляция до отправки: ошибки подписи ловим бесплатно
  await pub.simulateContract({ address: USDC, abi, functionName: "transferWithAuthorization", args: [from, to, value, validAfter, validBefore, b.nonce, v, b.r, b.s], account });
  const hash = await wal.writeContract({ address: USDC, abi, functionName: "transferWithAuthorization", args: [from, to, value, validAfter, validBefore, b.nonce, v, b.r, b.s] });
  bump(to);
  log("relay", from, "->", to, (Number(value) / 1e6).toFixed(6), "USDC", hash);
  const rc = await pub.waitForTransactionReceipt({ hash, timeout: 120_000 });
  return { hash, status: rc.status, gas: rc.gasUsed.toString() };
}

http.createServer((req, res) => {
  const send = (code, obj) => { const s = JSON.stringify(obj); res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) }); res.end(s); };
  if (req.method === "GET" && req.url.endsWith("/relay/stats")) return send(200, { relayer: account.address, today: stats.day === day() ? stats.n : 0, max_per_day: MAX_PER_DAY });
  if (req.method !== "POST" || !req.url.endsWith("/relay")) return send(404, { error: "not found" });
  let body = ""; req.on("data", c => { body += c; if (body.length > 4096) req.destroy(); });
  req.on("end", () => {
    busy = busy.then(async () => {
      try { send(200, await relay(JSON.parse(body))); }
      catch (e) { const msg = String(e && (e.shortMessage || e.message) || e).slice(0, 200); log("refused", msg); send(400, { error: msg }); }
    });
  });
}).listen(Number(process.env.STEALTH_RELAY_PORT || 3874), "127.0.0.1", async () => {
  log("stealth relayer on 3874 as", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
});
