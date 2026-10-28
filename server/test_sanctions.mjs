/* Sanctions test: no anvil/network needed. A counting stub RPC proves a listed address is refused BEFORE any RPC call (hence before any gas).
   Run: node test_sanctions.mjs */
import { spawn } from "child_process"; import fs from "fs"; import os from "os"; import path from "path"; import http from "http"; import { fileURLToPath } from "url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "st-sanc-"));
const BAD = "0x" + "ab".repeat(20), OK = "0x" + "cd".repeat(20), OK2 = "0x" + "ef".repeat(20), LATE = "0x" + "12".repeat(20);
const list = path.join(tmp, "evm.json"); const write = a => fs.writeFileSync(list, JSON.stringify({ published: "test", addresses: a }));
write([BAD.toUpperCase().replace("0X", "0x")]);                       // mixed case in the file must still match
let rpcCalls = 0; const stub = http.createServer((q, s) => { let b = ""; q.on("data", c => b += c); q.on("end", () => { rpcCalls++; const j = JSON.parse(b); s.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, result: "0x1" })); }); });
await new Promise(r => stub.listen(0, "127.0.0.1", r));
Object.assign(process.env, { STEALTH_CHAIN: "rh", STEALTH_ENV_ONLY: "1", STEALTH_RPC: "http://127.0.0.1:" + stub.address().port, STEALTH_SANCTIONS_FILE: list, STEALTH_RELAY_LOG: path.join(tmp, "r.log"),
  STEALTH_RELAY_STATE: path.join(tmp, "s.json"), STEALTHPAY: "0x" + "99".repeat(20), RELAYER_KEY: "0x" + "11".repeat(32), STEALTH_RELAY_PAY_FEE_MIN: "0" });
const R = await import("./relayer.mjs");
let fails = 0; const t = (name, ok) => { console.log(ok ? "PASS" : "FAIL", name); if (!ok) fails++; };
const sig = { nonce: "0x" + "00".repeat(32), r: "0x" + "00".repeat(32), s: "0x" + "00".repeat(32), v: 27, value: "300000", validBefore: "99999999999" };
const err = p => p.then(() => null, e => String(e.message));
rpcCalls = 0;
t("relay: listed from refused", (await err(R.relay({ ...sig, from: BAD, to: OK }, "1.1.1.1"))) === "address is on a sanctions list");
t("relay: listed to refused", (await err(R.relay({ ...sig, from: OK, to: BAD }, "1.1.1.1"))) === "address is on a sanctions list");
const pay = (o) => ({ token: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", amount: "300000", fee: "0", stealth: OK2, eph: "0x02" + "11".repeat(32), viewTag: "0x01", feeRecipient: "0x0000000000000000000000000000000000000000",
  auth: { from: OK, validAfter: "0", validBefore: "99999999999", v: 27, r: sig.r, s: sig.s }, ...o });
t("pay: listed payer refused", (await err(R.relayPay(pay({ auth: { ...pay().auth, from: BAD } }), "1.1.1.1"))) === "address is on a sanctions list");
t("pay: listed stealth refused", (await err(R.relayPay(pay({ stealth: BAD }), "1.1.1.1"))) === "address is on a sanctions list");
t("pay: listed feeRecipient refused", (await err(R.relayPay(pay({ feeRecipient: BAD }), "1.1.1.1"))) === "address is on a sanctions list");
t("zero RPC calls (no gas, no reads) for refusals", rpcCalls === 0);
t("refusal does not consume IP/payer quota", Object.keys(R.st.perIp).length === 0 && Object.keys(R.st.perPayer).length === 0);
t("refusals are logged", (fs.readFileSync(path.join(tmp, "r.log"), "utf8").match(/sanctions refused/g) || []).length === 5);
const e1 = await err(R.relay({ ...sig, from: OK, to: OK2 }, "1.1.1.1")); t("unlisted address is NOT refused for sanctions (fails later)", e1 !== "address is on a sanctions list");
t("unlisted passes screen", R.screen.isListed(OK) === false && R.screen.isListed(BAD) === true);
write([BAD, LATE]); await new Promise(r => setTimeout(r, 1100)); t("reload on file change picks up new address", R.screen.isListed(LATE) === true);
fs.writeFileSync(list, "{broken"); await new Promise(r => setTimeout(r, 1100)); t("broken reload keeps previous list", R.screen.isListed(LATE) === true);
write([BAD]); const port = 38000 + Math.floor(Math.random() * 1000);
const child = spawn("node", [path.join(HERE, "relayer.mjs")], { env: { ...process.env, STEALTH_RELAY_PORT: String(port) }, stdio: "ignore" });
await new Promise(r => setTimeout(r, 1500));
const g = u => fetch("http://127.0.0.1:" + port + u).then(async r => [r.status, await r.json()]);
const a = await g("/stealth-api/relay/screen?addr=" + BAD), b = await g("/stealth-api/relay/screen?addr=" + OK), c = await g("/stealth-api/relay/screen?addr=zzz");
t("GET /relay/screen listed=true", a[0] === 200 && a[1].listed === true); t("GET /relay/screen listed=false", b[1].listed === false); t("GET /relay/screen bad addr 400", c[0] === 400);
const post = await fetch("http://127.0.0.1:" + port + "/stealth-api/relay", { method: "POST", body: JSON.stringify({ ...sig, from: BAD, to: OK }) }).then(async r => [r.status, await r.json()]);
t("POST /relay over HTTP -> 400 sanctions error", post[0] === 400 && post[1].error === "address is on a sanctions list");
child.kill(); stub.close(); console.log(fails ? "FAILED " + fails : "ALL PASS"); process.exit(fails ? 1 : 0);
