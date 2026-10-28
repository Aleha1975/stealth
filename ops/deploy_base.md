# Deploy StealthPay v3 on Base (chain 8453)

Base already runs a StealthPay (`0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76` in web/chains.js, v2). v3 is a NEW address: Base clients, indexer (`STEALTHPAY` / start block) and relayer must switch together, and old announcements stay in the shared Announcer (indexer decides what it lists). Decide the cutover plan before broadcasting.
Constructor `(announcer, token)`: announcer `0x55649E01B5Df198D18D95b5cc5051630cfD45564`, token USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.

## 0. Deployer env file `~/.stealth/deployer.base.env` (chmod 600, never in git)
```
DEPLOYER_KEY=0x<64 hex>
BASE_RPC=https://base-rpc.publicnode.com        # for broadcast prefer your private RPC
ANNOUNCER=0x55649E01B5Df198D18D95b5cc5051630cfD45564
TOKEN=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
EXPECT_CHAIN_ID=8453
```
## 1. Simulate (measured 2026-10-28, no broadcast)
```
cd ~/stealth && ANNOUNCER=0x55649E01B5Df198D18D95b5cc5051630cfD45564 TOKEN=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 EXPECT_CHAIN_ID=8453 \
  forge script script/DeployStealthPay.s.sol --fork-url https://base-rpc.publicnode.com --sender 0x1111111111111111111111111111111111111111
```
`Estimated total gas used for script: 1429057`. eth_gasPrice 0.006 gwei (6000000 wei) -> **~0.0000086 ETH**; forge (2x margin, 0.01065 gwei): `0.0000152 ETH`. Fund the deployer with 0.0005 ETH for safety (Base gas can spike).
## 2. Broadcast
```
set -a; . ~/.stealth/deployer.base.env; set +a
forge script script/DeployStealthPay.s.sol --rpc-url "$BASE_RPC" --broadcast --slow
```
Check with `cast call $ADDR 'TOKEN()(address)'` and `'ANNOUNCER()(address)'`.
## 3. Verify
```
forge verify-contract $ADDR src/StealthPay.sol:StealthPay --chain 8453 --verifier sourcify --verifier-url https://sourcify.dev/server/ \
  --constructor-args $(cast abi-encode 'constructor(address,address)' $ANNOUNCER $TOKEN) --watch
# Basescan (needs ETHERSCAN_API_KEY in the env file, never inline):
forge verify-contract $ADDR src/StealthPay.sol:StealthPay --chain base --verifier etherscan --etherscan-api-key "$ETHERSCAN_API_KEY" \
  --constructor-args $(cast abi-encode 'constructor(address,address)' $ANNOUNCER $TOKEN) --watch
```
## 4. Server (Base units are LIVE: change one thing at a time)
1. `/opt/stealth/relayer.env`: `STEALTHPAY=<new addr>`; indexer env: new start block / watched contract per `stealth_indexer.py`.
2. `web/chains.js` `base.stealthPay` (web owner). Old clients with the old address keep working against v2 until the web is switched.
3. `systemctl restart stealth-relayer` (not done by install_rh.sh), then `curl -s http://127.0.0.1:3874/stealth-api/relay/stats` (pay_enabled, stealthpay), `curl -s .../stealth-api/head`, `curl -s https://app.deepyield.ai/stealth-api/pages/manifest.json`.
4. Sanctions: copy `server/sanctions/` to `/opt/stealth/sanctions/` BEFORE restarting the Base relayer on the new relayer.mjs (it fails closed without evm.json). `ops/install_rh.sh --apply` does this copy as part of the RH install; it does not restart Base.
