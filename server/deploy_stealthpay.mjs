/* Деплой StealthPay на Base ключом исполнителя. Конструктор: адрес общего Announcer ERC-5564 и единственный токен (USDC на Base). */
import fs from "fs";
import { createPublicClient, createWalletClient, http, formatEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
for (const line of fs.readFileSync("/opt/mprhedged/exec/.env", "utf8").split("\n")) {
  const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)=["']?([^"'#\n]+)/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
}
const art = JSON.parse(fs.readFileSync("/opt/stealth/StealthPay.artifact.json", "utf8"));
const account = privateKeyToAccount(process.env.MPRH_EXECUTOR_KEY.trim());
const transport = http(process.env.BASE_RPC2 || process.env.BASE_RPC, { timeout: 30000 });
const pub = createPublicClient({ chain: base, transport }); const wal = createWalletClient({ account, chain: base, transport });
console.log("executor", account.address, "balance", formatEther(await pub.getBalance({ address: account.address })), "ETH");
const hash = await wal.deployContract({ abi: art.abi, bytecode: art.bytecode, args: ["0x55649E01B5Df198D18D95b5cc5051630cfD45564", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" /* USDC on Base: the one token of this deployment */] });
console.log("deploy tx", hash);
const rc = await pub.waitForTransactionReceipt({ hash, timeout: 180_000 });
console.log("status", rc.status, "StealthPay", rc.contractAddress, "gas", rc.gasUsed.toString());
