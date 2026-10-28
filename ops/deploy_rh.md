# Deploy StealthPay v3 on Robinhood Chain (chain 4663)

Constructor `(announcer, token)`: announcer `0x55649E01B5Df198D18D95b5cc5051630cfD45564` (ERC-5564, code present), token USDG `0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`.
Script: `script/DeployStealthPay.s.sol` (asserts chainid via `EXPECT_CHAIN_ID`, code at both addresses, re-reads immutables after deploy).

## 0. Deployer env file (never inline, never in git)
`~/.stealth/deployer.rh.env`, `chmod 600`:
```
DEPLOYER_KEY=0x<64 hex>        # read by the script via vm.envUint, so it never appears in argv / shell history
RH_RPC=https://rpc.mainnet.chain.robinhood.com
ANNOUNCER=0x55649E01B5Df198D18D95b5cc5051630cfD45564
TOKEN=0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168
EXPECT_CHAIN_ID=4663
```
Fund the deployer address with >= 0.0005 ETH on RH (see estimate; a fresh key, not the relayer key).

## 1. Simulate (no broadcast, no key needed). Result measured 2026-10-28
```
cd ~/stealth && forge build && ANNOUNCER=0x55649E01B5Df198D18D95b5cc5051630cfD45564 TOKEN=0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168 EXPECT_CHAIN_ID=4663 \
  forge script script/DeployStealthPay.s.sol --fork-url https://rpc.mainnet.chain.robinhood.com --sender 0x1111111111111111111111111111111111111111
```
Output: `Estimated total gas used for script: 1429041`. eth_gasPrice on RH = 0.02101 gwei (21010000 wei) -> **~0.00003 ETH** at the live price.
forge's own estimate (it applies a ~2x price margin: 0.04197 gwei) printed `0.00005997 ETH`. Budget **0.0001 ETH**, worst case 0.0006 at 10x price spike.
(The address printed by the simulation belongs to the dummy `--sender`; the real address is fixed by deployer + nonce.)

## 2. Broadcast
```
set -a; . ~/.stealth/deployer.rh.env; set +a
cd ~/stealth && forge script script/DeployStealthPay.s.sol --rpc-url "$RH_RPC" --broadcast --slow
```
Copy `StealthPay deployed at 0x...` (also in `broadcast/DeployStealthPay.s.sol/4663/run-latest.json`, keys NOT stored there; `broadcast/` stays out of git).
Record the block number: `jq '.receipts[0].blockNumber' broadcast/DeployStealthPay.s.sol/4663/run-latest.json` (hex) -> `STEALTH_START_BLOCK` in rh.env.
Check on chain: `cast code $ADDR --rpc-url $RH_RPC | wc -c` (not 3), `cast call $ADDR 'TOKEN()(address)' --rpc-url $RH_RPC`, `cast call $ADDR 'ANNOUNCER()(address)' ...`.

## 3. Verify the source
Sourcify supports 4663 (checked: sourcify.dev/server/chains lists it as supported):
```
forge verify-contract $ADDR src/StealthPay.sol:StealthPay --chain 4663 --verifier sourcify --verifier-url https://sourcify.dev/server/ \
  --constructor-args $(cast abi-encode 'constructor(address,address)' $ANNOUNCER $TOKEN) --watch
```
Blockscout (explorer in server/chains.json = https://robinhoodchain.blockscout.com; Blockscout's Etherscan-compatible API lives at `/api/`):
```
forge verify-contract $ADDR src/StealthPay.sol:StealthPay --chain 4663 --verifier blockscout --verifier-url https://robinhoodchain.blockscout.com/api/ \
  --constructor-args $(cast abi-encode 'constructor(address,address)' $ANNOUNCER $TOKEN) --watch
```
Caveat: from this sandbox `robinhoodchain.blockscout.com/api` answers with a Cloudflare "Just a moment" challenge, so the URL could not be confirmed with curl. If forge gets the same challenge from your IP, verify through Sourcify only, or use the Blockscout web UI "Verify & publish" with standard-json input (`forge verify-contract --show-standard-json-input` prints it; solc 0.8.26, evm cancun, optimizer 200).

## 4. Server (after step 2). Nothing here touches the Base units
1. `server/deploy/rh.env.example` -> `/opt/stealth/rh.env`: set `STEALTHPAY=<addr>`, `STEALTH_START_BLOCK=<deploy block>`, a NEW `RELAYER_KEY` generated on the server, `STEALTH_RPC`. `chmod 600; chown stealth:stealth`.
2. Fund the RH relayer address with ~0.05 ETH on RH (at 0.021 gwei that is thousands of relays).
3. `web/chains.js`, `rh.stealthPay: "<addr>"` (replaces `null`); web owner commits and deploys web/.
4. Run `ops/install_rh.sh` (dry run), read it, then `sudo ops/install_rh.sh --apply`. It copies code and units, writes nginx zones and the `snippets/stealth-rh.conf`, runs `nginx -t`, starts the RH units only.
   If it prints the `[todo] include ...` line, add `include /etc/nginx/snippets/stealth-rh.conf;` inside the `server{}` of app.deepyield.ai, then re-run with `--apply`.
5. Smoke tests:
```
curl -s http://127.0.0.1:3883/stealth-api/head
curl -s http://127.0.0.1:3884/stealth-api/relay/stats        # pay_enabled:true, stealthpay:<addr>
curl -s 'http://127.0.0.1:3884/stealth-api/relay/screen?addr=0x0000000000000000000000000000000000000001'   # {"listed":false}
curl -s https://app.deepyield.ai/stealth-api/rh/head
curl -s https://app.deepyield.ai/stealth-api/rh/relay/stats
curl -s https://app.deepyield.ai/stealth-api/rh/pages/manifest.json   # appears after the indexer wrote its first page
curl -s -o /dev/null -w '%{http_code}\n' https://app.deepyield.ai/stealth-api/rh/nonsense   # 404
```
6. First live payment: $0.20 from own wallet via the web (`?chain=rh`), check `/relay/stats` `sends` and the relayer log in `/opt/stealth/data-rh/relayer.rh.log`.

## Sanctions list (all servers)
`/opt/stealth/sanctions/evm.json` is refreshed daily by `stealth-sanctions.timer` (update.py; OFAC SDN.XML). Relayers reload it on file change. The relayer FAILS CLOSED if the file is absent at start (set `STEALTH_SANCTIONS_OPTIONAL=1` only deliberately).
Pre-check API for the web: `GET /stealth-api/relay/screen?addr=0x..` -> `{"addr":"0x..","listed":true|false}` (RH: `/stealth-api/rh/relay/screen`, routed by stealth-rh.conf; Base: add the same `screen` suffix to the existing Base relay-stats location).
Relay refusals return HTTP 400 `{"error":"address is on a sanctions list"}`.
