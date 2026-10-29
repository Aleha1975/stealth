/* Деплой StealthPay v3 на Robinhood Chain (4663) ключом исполнителя. Конструктор: общий Announcer ERC-5564 и единственный токен USDG.
   Запуск: node deploy_stealthpay_rh.mjs check   — только адрес и баланс, без транзакций;
           node deploy_stealthpay_rh.mjs deploy  — деплой. Ключ берётся из /opt/mprhedged/exec/.env и не печатается. */
import fs from "fs";
import { createPublicClient, createWalletClient, http, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
for (const line of fs.readFileSync("/opt/mprhedged/exec/.env", "utf8").split("\n")) {
  const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)=["']?([^"'#\n]+)/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
}
const RPC = process.env.RH_RPC || "https://rpc.mainnet.chain.robinhood.com";
const rh = defineChain({ id: 4663, name: "Robinhood Chain", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } });
const ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564", USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
const art = JSON.parse(fs.readFileSync(process.env.ARTIFACT || "/opt/stealth/StealthPay.v3.artifact.json", "utf8"));
const account = privateKeyToAccount(process.env.MPRH_EXECUTOR_KEY.trim());
const transport = http(RPC, { timeout: 30000 });
const pub = createPublicClient({ chain: rh, transport }); const wal = createWalletClient({ account, chain: rh, transport });
if (await pub.getChainId() !== 4663) throw new Error("wrong chain");
for (const a of [ANNOUNCER, USDG]) if (!(await pub.getCode({ address: a }))) throw new Error("no code at " + a);
const bal = await pub.getBalance({ address: account.address });
const gas = await pub.estimateGas({ account, data: art.bytecode + "000000000000000000000000" + ANNOUNCER.slice(2).toLowerCase() + "000000000000000000000000" + USDG.slice(2).toLowerCase() });
const price = await pub.getGasPrice();
console.log("executor", account.address, "balance", formatEther(bal), "ETH; deploy gas", gas.toString(), "cost ~", formatEther(gas * price), "ETH");
if (process.argv[2] !== "deploy") process.exit(0);
if (bal < gas * price * 3n) throw new Error("not enough ETH on Robinhood Chain for the deploy");
const hash = await wal.deployContract({ abi: art.abi, bytecode: art.bytecode, args: [ANNOUNCER, USDG] });
console.log("deploy tx", hash);
const rc = await pub.waitForTransactionReceipt({ hash, timeout: 180_000 });
console.log("status", rc.status, "StealthPay", rc.contractAddress, "block", rc.blockNumber.toString(), "gas", rc.gasUsed.toString());
