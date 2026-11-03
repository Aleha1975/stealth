# Loophole (Stealth) on Robinhood Chain: launch readiness

Date 2026-11-03 (times UTC = London). Repo HEAD 1b4b8ec, branch `shielded-v2`. Method: owner framework (sections 2, 3.1-3.7, 5, 11, 13, 14) applied to the live state. Server 46.224.154.72 and public endpoints read with read-only commands; secrets files checked for existence, mode and owner only (their contents were not read). Load test run on a scratch worktree with a local anvil fork of RH. Nothing on the servers was changed.

Live state at the time of the pass:

| what | value |
|---|---|
| contract | `0x6f488f90...08ac7`, Sourcify `exact_match` (verified 2026-10-29), 4.8 kB runtime |
| web | https://app.deepyield.ai/stealth-zec/ serves `?v=1b4b8ec` (HEAD); `vendor/*` and `SHA256SUMS` identical to HEAD; wasm sha256 = `8b218ea3...` = manifest |
| server code | `/opt/stealth-rh/relayer.mjs` and `stealth_indexer.py` byte-identical to HEAD |
| relayer | 0.006920 ETH, 0.70 USDG of fees, 4 sends today, avg_send_ms 713 (4 samples), budget 0.01 ETH/day |
| indexer | head = chain head, lag 0, 27 rows, 0 full history pages |
| host | 2 vCPU, 3.8 GB RAM (1.2 GB available), no swap, disk 47%, load 0.8, 206 days up, hosts about 55 other units |

Status key: DONE / PARTIAL / GAP. Priority: P0 blocks launch, P1 before real users or first week, P2 backlog.

---

## 1. SECURITY (framework 3.1-3.7, section 5)

### 1.1 Contract (3.1)

| item | evidence | status | prio | fix (effort) |
|---|---|---|---|---|
| Immutables, no admin, no upgrade | `cast call ANNOUNCER()` = 0x55649E01...5564; `TOKEN()` = USDG 0x5fc5...d168; `owner()` reverts; ODA 1076/1078 0C/0H/0M | DONE | - | - |
| Verified bytecode | `curl sourcify.dev/server/v2/contract/4663/0x6f48...` -> `exact_match`; residuals file says metadata hash matches | DONE | - | - |
| Each limiter proven by attack | PoCs from 1076/1078 turned into tests (40/40 per memory); L-1 delta check closed in 7bd0b8c | DONE | - | - |
| Where an outside contract pays | `payWithAuthorization` uses `receiveWithAuthorization` with `to` = contract and nonce = keccak(stealth, eph, viewTag, ...) so it cannot be redirected (C2 in 1078) | DONE | - | - |
| Token is a proxy: USDG at `0x5fc5...d168` is an upgradeable proxy (EIP-1967 impl `0x68184c44...6f8f`) with `paused()` | `cast storage <usdg> 0x3608...2bbc`; `paused()` = false | PARTIAL (residual) | P2 | Name it in the residuals file: the token issuer can pause, freeze or upgrade and every balance on the product follows. Not fixable by us; disclose in the terms (30 min) |
| Griefing through `used[stealth]` (1161 M-1) | audit/stealthpay-v3-residuals.md; relayer checks `used()` first, client re-derives | DONE (accepted) | P2 | - |
| Second external audit round on the final contract | rounds 1076, 1078 on the contract; later 1085-1181 are client/relayer/ops | DONE | - | - |

### 1.2 Relayer (3.2, 3.5)

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Key file mode/owner | `stat /opt/stealth-rh/rh.env` = 600 stealth:stealth; `/opt/stealth-base/base.env` 600 stealth:stealth; `/opt/stealth/relayer.env` 600 root | DONE | - | - |
| Who can read the key | root, and every process running as uid `stealth` (988). The Base v3 relayer, RH relayer, both indexers and the watchdog all run as the same uid (`systemctl show -p User`). No other human user in the group (`id stealth`) | PARTIAL | P1 | One uid per role (relayer vs indexer/watch) and per chain; the indexer (Python, parses chain data, 76 kB) has no reason to share a uid with the key holder. Framework 3.5 open item "different uid per product". 1 h: new users + `User=` + chown data |
| Key separate from Base | RH key generated on the server (new); Base v3 and legacy v2 relayer report the same address 0x956B...9a03 (`/stealth-api/relay/stats` and `/stealth-api/base/relay/stats`), i.e. the legacy root unit and the Base v3 unit share a key | PARTIAL | P2 | Retire legacy v2 (below), keep one key per chain |
| Budget caps | `STEALTH_RELAY_GAS_BUDGET_WEI` = 0.01 ETH/day (stats), reservation before send, `MIN_BALANCE` refusal at 0.001 ETH, `PAY_PER_PAYER` 20/day, `PER_FROM` 3 withdrawals/address/day (relayer.mjs:62,82) | DONE | - | - |
| Fee ceiling | `FEE_CEIL` = budget/4/250000 = 10 gwei (relayer.mjs:68), 503 above it, never signs | DONE | - | - |
| Locks | nonce lock with 40 s deadline (`LOCK_MS`, :93), `flights` map, `unsure` table fsync'd, MAX_CONCURRENT 64 (:94), audits 1108-1124 | DONE | - | - |
| Sanctions list freshness | `evm.json` 127 addresses, written 2026-11-03 06:30 by `stealth-sanctions@rh.timer` (daily); relayer reloads on change; watchdog template "sanctions list is older than" | DONE | - | - |
| Sanctions timer failure goes unseen | timer results are in the journal only (see 2: no Telegram) | PARTIAL | P1 | Wire alerts (section 2) |
| Allow-list | `STEALTH_RELAY_ALLOW_KEYS` supported, not set in committed config; live value not read (env contents not read by design) | PARTIAL | P2 | Confirm empty with `systemctl show -p Environment` style check done by the owner, or `grep -c ALLOW_KEYS rh.env` (count only) |
| Dead config | `STEALTH_RELAY_MAX_PER_IP` is in rh.env but removed from the code (audit 1116 M-2; no hit in `server/relayer.mjs`) | GAP | P2 | Delete the line so nobody thinks a per-IP cap of 60 exists (2 min) |
| Relayer log is world-readable and links stealth to destination | `/opt/stealth-rh/data/relayer.rh.log` is 644; lines read `relay <stealth> -> <destination> <amount>`; same lines in the journal | GAP | P1 | Any local account on the shared host (other products run as `proofline`, `neobank`, `hypersentinel`) can read who withdrew to whom. `UMask=0077` in both RH units + `chmod 600` the log; journal access is group-limited already (5 min) |
| Systemd sandbox | RH relayer/indexer: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictSUIDSGID`, `ReadWritePaths=/opt/stealth-rh/data`, `MemoryMax=512M`, `TasksMax=200` | DONE | - | - |
| Sandbox gaps | no `CapabilityBoundingSet=`, `RestrictAddressFamilies`, `SystemCallFilter`, `ProtectKernel*` beyond two, no `IPAddressDeny` (relayer needs only localhost + RPC hosts) | PARTIAL | P2 | Add the 4 lines, test on the fork host first (1 h). `systemd-analyze security stealth-relayer-rh` to score |
| Shared dependencies | `node_modules` is a symlink to `/opt/mprhedged/exec/node_modules` (root-owned, owned by another product, changed whenever that product updates npm packages) | GAP | P1 | The relayer signs transactions with viem from a directory another product controls and updates. Install `server/package-lock.json` into `/opt/stealth-rh/node_modules` with `npm ci` and pin (30 min) |
| Legacy Base v2 relayer | `stealth-relayer.service` and `stealth-indexer.service` on 3874/3873: `User=` empty (root), `ProtectSystem=no`, `NoNewPrivileges=no`, `MemoryMax=infinity`; reached from the internet through `location ^~ /stealth-api/relay` and `/stealth-api/` which have no `limit_req`; balance 0 | GAP | P1 | Product: Base v2 is refused by design ("no gas, rejects before signature"). Stop and disable both units, remove the two nginx locations (or return 410). 15 min, needs owner OK because the old Base URL stops answering |
| Base v3 relayer drift | `/opt/stealth-base/relayer.mjs` hash `3d780d49` differs from HEAD `38705b7e` (deployed 2026-11-02 17:14) | PARTIAL | P2 | Redeploy Base from HEAD or retire Base (Base contract v3 `0xC07f...916d` also live) |

### 1.3 Indexer / API (3.3)

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Binds to localhost only | `ss -ltnp`: 127.0.0.1:3883/3884/3893/3894; only 22/80/443 public | DONE | - | - |
| Input validation and limits | `/balances`: `MAX_ADDRS` + regex (stealth_indexer.py:922), `limit` clamp 1-2000 (:891), `BoundedServer` 64 threads then 503 (:799), relayer body 8k (nginx), `MAX_SINGLE` | DONE | - | - |
| nginx rate limits | `st_rh_read` 10 r/s burst 40, `st_rh_post` 10 r/m burst 5, `st_rh_conn` 10-20, `limit_except` per method, `proxy_next_upstream off` for POST (stealth-rh.conf) | DONE | - | - |
| Zones keyed on full IPv6 address | `limit_req_zone $binary_remote_addr` (conf.d/stealth-rh-zones.conf): one user with a /64 gets 2^64 buckets; relayer groups by /64 for failures, nginx does not | PARTIAL | P2 | `map $remote_addr $net` collapsing IPv6 to /64 for the zones (30 min) |
| Rate-limit exemption for sync scanning | cached pages + 1 s micro-cache on the tail | DONE | - | - |
| Private data path | `/balances` still exists on the indexer even though the web reads balances over RPC (audit 1098 M-2) | PARTIAL | P2 | Leave; 10 r/s limit and no logging of the address list. Check access log format does not store query strings of `/balances` (nginx `access.log` does: query string is logged) |
| nginx access log stores query strings | `/var/log/nginx/access.log` (rotated 14 days, 9.5 MB) uses the default request format, which includes the query string (not checked line by line for `/balances` and `/screen?addr=`; check with `grep -c balances`) | GAP | P1 | `log_format` without `$args` for `/stealth-api/` locations (`access_log off` or `$uri`) so IP to stealth address is not kept (15 min) |

### 1.4 Web (3.4)

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| CSP | meta tag in web/app.html:9: `default-src 'self'; script-src 'self' blob: 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self' + 1click, chainsafe lightwalletd, RH rpc, base rpcs; object-src 'none'; base-uri 'none'; form-action 'none'`; nginx adds `frame-ancestors 'none'` | DONE | - | - |
| CSP only partly in a header | the header on `/stealth-zec/` is only `frame-ancestors` (snippet stealth-zec.conf, audit 1158 F-9). The script rules live in the page meta tag, so a tampered or replaced HTML defeats them; `style-src 'unsafe-inline'` | PARTIAL | P2 | Move the same policy into the nginx header after a browser test with the wallet (1 h). The wallet needs `blob:` workers |
| Other headers | live: COOP same-origin, COEP require-corp, CORP same-origin, nosniff, no-referrer, `Cache-Control: no-cache`; HSTS and Permissions-Policy not seen on the response | PARTIAL | P2 | `curl -sI`: no `strict-transport-security` on this path. Add HSTS (it is also an app.deepyield.ai concern) and a restrictive Permissions-Policy (10 min) |
| No CDN | `grep https://` over web/*.js,*.html: only RPC, 1Click, lightwalletd, blockscout, docs links; noble is vendored | DONE | - | - |
| Vendor hashes | `web/vendor/SHA256SUMS` + `webzjs/SHA256SUMS`; deploy refuses unlisted files, symlinks, dirty tree (ops/deploy_prod.sh); live files equal HEAD | DONE | - | - |
| Wasm integrity | 60,341,920 bytes, live sha256 equals manifest; served `application/wasm`, immutable cache. The browser does not verify the hash at load (no SRI for wasm fetched by the glue) | PARTIAL | P2 | Add a hash check of the fetched wasm bytes in `zec-hop.js` before instantiate (2 h); until then integrity = deploy gate + server file mode |
| Deploy does not overwrite live data | rsync without `--delete`, `?v=<commit>` busting | DONE | - | - |
| Provenance of the live build | `app.js?v=1b4b8ec`; deploy script refuses a dirty `web/` | DONE | - | - |

### 1.5 Server hardening (3.5)

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| SSH | `sshd -T`: `permitrootlogin without-password`, `passwordauthentication no`, `maxauthtries 3`, 3 authorized keys; fail2ban sshd jail active (36 banned now, 8306 total) | DONE | - | - |
| Firewall | `ufw status`: deny incoming; 22, 80, 443 allow (v4 and v6) | DONE | - | - |
| Exposed ports | `ss -ltnp`: public = 22, 80, 443 only | DONE | - | - |
| File modes | `/opt/stealth-rh`, `/opt/stealth-base`: code root-owned 644, `data/` stealth 755, env 600 stealth; `relayer_state.rh.json` 600; `announcements.db` 644 (public data) | DONE | - | - |
| Pending kernel update | `uname -r` = 6.8.0-90, installed `linux-image-6.8.0-147`, `/var/run/reboot-required` exists, uptime 206 days | GAP | P1 | A reboot is 57 kernel builds overdue and has never been rehearsed with these units. Owner picks a window (also affects every other product on the host); 10 min |
| Auto updates | `unattended-upgrades` active | DONE | - | - |
| Blast radius (same host) | other products: Dispatch-old units disabled, hypersentinel, neobank, mprhedged, proofline-base, whale-copy cron, docker (2.7 GB), 3 shared nginx server blocks. Stealth units have `MemoryMax=512M`; the host has no swap, so a memory event kills a neighbour first | PARTIAL | P1 | Plan a separate small host for the Stealth relayer key (framework 13 recommended the same for Dispatch). Decision for owner; about 5 EUR/month (Hetzner CX22) |
| nginx hygiene | `nginx -t` printed at least 9 warnings (duplicate server names, protocol options redefined; output read only up to 10 lines); `.bak` copies in `/etc/nginx/sites-enabled/` are loaded by `include sites-enabled/*` ("conflicting server name ... ignored"); first-match wins today | PARTIAL | P2 | Move `*.bak*` out of `sites-enabled` (a reload order change could activate an old block) (10 min; the file also touches other products, owner of nginx decides) |
| Cert renewal | cert for app.deepyield.ai valid until 2026-12-31 (issued 2026-10-02); `certbot.timer` active, last run 03:53 | DONE | - | - |

### 1.6 External services as adversary (3.6)

| service | what it learns | status | prio | fix |
|---|---|---|---|---|
| Our nginx/indexer/relayer | IP + time of every scan (manifest, head, tail, stats) and, for relay calls, stealth address, destination, amount (log lines above) | PARTIAL | P1 | Log hygiene above; document in the privacy text that the operator sees IP and relayed addresses |
| RH public RPC `rpc.mainnet.chain.robinhood.com` (only endpoint) | Browser: IP + the stealth addresses whose balances are read (batched multicall) + tx broadcasts; indexer/relayer: chain data. As a single endpoint it can hide announcements or lie about balances (indexer trusts it, `rh.env.example` TRUST ASSUMPTION 1165 M-1). 478 `429` lines in the indexer journal since 2026-11-02 | GAP | P0 for 500 users, P1 for 100 | Second independent provider for indexer, relayer and the browser CSP; no second URL exists today for 4663 (config `rpcs` has one entry). Owner: pick and pay a provider (Alchemy forbidden by owner rule, so dRPC/other), about 0-50 USD/month |
| 1Click (`1click.chaindefuser.com`) | Both legs of a private withdraw (same client, same IP/TLS), amounts, recipient; custodial during a swap. Quote checks: amount, recipient, refund, slippage 3%, deadline | PARTIAL (accepted residual) | P1 | Documented in zec-hop-scope.md. Out-leg over another network path is possible (`ctx.fetchFnOut`) but not set up. No fallback if 1Click is down (private modes stop; Standard works). Probe: `/v0/tokens` 200 in 0.3 s |
| Zcash lightwalletd proxy `zcash-mainnet.chainsafe.dev` | Maximum mode only: client IP, hop wallet block ranges and viewing activity, tx broadcast timing; cannot spend; can lie or censor. One URL pinned in chains.js. Probe: `HEAD /` 301 in 0.44 s | PARTIAL (accepted) | P1 | Second lightwalletd (self-hosted `zcashd`/`lightwalletd` costs a server; or another public proxy) and failover in chains.js (1 day) |
| Blockscout / explorer | links only | DONE | - | - |

### 1.7 Product logic (3.7) and what an observer can link

| mode | observer view | status | prio | note |
|---|---|---|---|---|
| Receive (stealth address) | Payer to one-time address; the Announcer event is public; only the key holder links addresses | DONE | - | ERC-5564 keys derived from one wallet signature, domain without chainId |
| Standard withdraw | Stealth address to chosen recipient on chain, relayer submits. Anyone can link stealth address to recipient; the payer is not linked to the recipient unless amounts and timing match. Our relayer log keeps the pair | PARTIAL | P1 | Be explicit in the UI: Standard hides the payer, not the destination |
| Private fast (1Click, no Zcash) | 1Click sees in and out; chain observer sees USDG to a 1Click deposit address and later a payout from 1Click; link by amount minus fee and time | PARTIAL | P1 | Label as "hides from chain observers, not from 1Click" |
| Maximum (via Zcash) | Amount is split (random weights), random delays, shielded pool between; 1Click still sees both legs from one IP; small anonymity set | PARTIAL | P1 | Real runs lost 12-20 % on 6-10 USD (31.10: -15.9 %, -18.8 %, -11.9 %, -20.2 %); under 3 % only from about 47 USD. Owner decision: minimum amount warning or hard minimum ~50 USD |
| Fee model | pay fee 0.05 USDG; withdraw fee 0 (gas subsidised, about 2e-6 ETH each). Relayer holds 0.70 USDG | PARTIAL | P2 | Decide a withdraw fee before volume; `STEALTH_RELAY_REQUIRE_WITHDRAW_FEE` exists |
| Hop wallet counter trusts indexer b0 | audit 1180 M-2 accepted in residuals | DONE (accepted) | P2 | - |

### 1.8 Secrets handling and backups of secrets

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Where keys live | RH relayer key only in `/opt/stealth-rh/rh.env` (600); deploy key never on server; no .env in git (ops docs say so) | DONE | - | - |
| Key escrow | no encrypted copy of the RH relayer key is outside the host (`ls /root/backups`, `/var/backups`: nothing from Stealth except old web tarballs); Dispatch has escrow tooling (`/root/tools/escrow`), Stealth does not use it | GAP | P1 | Loss costs the fee income (0.70 USDG now) and a re-key; the contract has no admin, so no lock-in. Encrypt rh.env to the owner key with the existing escrow script (30 min) |
| Telegram token | none in watch.env (the key list in the file has no `TG_*` lines) | GAP | P0 | see section 2 |

### 1.9 Findings registry (summary)

Source: report headers in `/root/tools/audit_dispatch/oda/reports` on 167.235.72.45 (only reports whose title names Stealth, read-only).

| metric | value |
|---|---|
| reports with Stealth in the title | 62 (the brief says 56: the extra ones are repeated fix reviews of the same jobs) |
| severity totals from the headline counts | 0 Critical, 2 High, 80 Medium, 207 Low, 250 Informational |
| Highs | 1088 H-1 (amount linkability of the Zcash hop: closed by split payout in v2, see zec-hop-scope.md "v2 changes"); 1179 High (`rewind()` did not reset known/safe boundary: closed in 85ec39f/1b4b8ec) |
| contract rounds | 1076 (0C/0H/0M, 2L), 1078 (0C/0H/0M, 1L): L closed |
| last report 1181 (review of 1180, HEAD 1b4b8ec) | 0C/0H/2M/8L/9I: OPEN, being fixed by another agent in this worktree: M-1 hop counter is per chain but hop wallet is not, M-2 `install_base.sh` rollback broken; L-1..L-8 (reconcile edge cases, lagging endpoint, `lostShielded` birthday, installers swallow failures, symlinks, nginx -T pipe); I-1..I-8 |
| trend | rounds still return 1-3 Medium each (section 11 of the framework: patch dynamics). Contract has been quiet since 1078; Mediums are in client/ops code. Recommend freezing the feature set and requiring one clean round (0H/0M) on the final HEAD before launch |

Accepted residuals (audit/stealthpay-v3-residuals.md, summarised honestly): `used[stealth]` griefing (any of three pay paths blocks another; gasless signature dies, funds never lost); `feeRecipient == stealth` allowed by contract, refused by our client and relayer; contract-under-construction passes `code.length` check; force-fed ETH stuck; "transient lock" comment wording (bytecode hash fixed); `evm_version=cancun` assumed supported; `ephemeralPubKey` not checked for curve membership; C2 depends on the token implementing EIP-3009 as specified; hop counter start block trusts the indexer (late b0 can let a hop wallet counter be reused). From zec-hop-scope.md: 1Click and lightwalletd see their legs; Maximum needs the tab open 25-40 min; ZEC price move can halt a hop; small anonymity set.

---

## 2. RELIABILITY (framework 14)

### 2.1 Single points of failure

| SPOF | evidence | status | prio | fix |
|---|---|---|---|---|
| One host | everything on 46.224.154.72 (2 vCPU, no swap, 206 days up), shared with about 55 units | GAP | P1 | Cold standby: rsync of `/opt/stealth-rh` (without env) + encrypted env, nginx snippet, web; failover by DNS is manual. As Dispatch did with 195.201 (2-3 h to build once) |
| One RPC (RH has one official endpoint) | `chains.json` rh `rpcs` = 1 entry; 429s seen | GAP | P0 (500 users) | second provider (section 1.6) |
| One 1Click | `chains.js` single base | PARTIAL | P2 | Standard mode still works; show "private modes unavailable" banner on failure |
| One lightwalletd proxy | chains.js `zcash.lightwalletd` single URL | PARTIAL | P1 | add second URL with failover |
| One relayer key | one hot key, nonce lock serialises all sends | PARTIAL | P2 | acceptable below ~1.4 tx/s; shard keys only if growth needs it |
| One web origin | static files on the same host | PARTIAL | P2 | `ops/build_ipfs.sh` exists; pin on IPFS as a fallback copy (owner has no pinning account yet) |

### 2.2 Restart policy and what survives a reboot

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Restart policy | `systemctl show`: `stealth-indexer-rh`, `stealth-relayer-rh`, legacy and base units `Restart=always RestartSec=5s`, NRestarts=0 | DONE | - | - |
| `StartLimitIntervalSec` in the wrong section | journal: "Unknown key name 'StartLimitIntervalSec' in section 'Service', ignoring" (repo units too) | PARTIAL | P2 | Move to `[Unit]` or drop (the default limit of 5 starts in 10 s never trips with `RestartSec=5`) (2 min) |
| Enabled at boot | `systemctl list-unit-files`: RH/Base indexers and relayers enabled; `stealth-watch.timer`, `stealth-sanctions@rh/base.timer` enabled | DONE | - | - |
| Reboot actually rehearsed | host has not rebooted in 206 days; `After=network-online.target` ordering never exercised for these units | GAP | P1 | Rehearse on a clone or at the planned kernel-update window; check `systemctl --failed`, `/stealth-api/rh/head` lag, relayer stats afterwards (15 min) |
| Memory limits | `MemoryMax=512M` each; indexer peak 20 MB in prod, 74 MB in the load test | DONE | - | - |

### 2.3 Backups

| asset | what exists (evidence) | status | prio | fix |
|---|---|---|---|---|
| Relayer state `relayer_state.rh.json` | none (cron list and timers: no Stealth job; `alphacatch_backup_mirror.sh` contains no "stealth") | GAP | P1 | Loss resets daily counters and the unsure table only, so impact is low; still copy it every 15 min off-host |
| Relayer key | none off-host | GAP | P1 | escrow (1.8) |
| Indexer DB | none; rebuildable from chain | PARTIAL | P2 | no backup needed if rebuild is rehearsed |
| nginx config | manual `.bak` files in `/etc/nginx/sites-enabled` and `/root/backups` (app-deepyield.bak-stealthrh-20261029-..., -stealthzec-...) | PARTIAL | P2 | repo holds the snippets; the vhost include line is manual |
| Web files | repo + `ops/deploy_prod.sh` reproduce them; pre-deploy tarballs in `/root/backups/stealth-*` (last 2026-10-29) | DONE | - | - |
| Off-host copy of anything | none for Stealth | GAP | P1 | One cron: `rsync` of data/state + encrypted env to the Dispatch standby 195.201 (owner's existing machine) or a Storage Box. Owner decision |

### 2.4 Recovery times (estimates; the first is partly measured)

| scenario | estimate | basis |
|---|---|---|
| Indexer DB rebuild from the deploy block 100,761,230 | 2-10 minutes expected, NOT measured end to end | head is 105,030,000: 4.27 M blocks = 171 chunks of 25,000; measured `eth_getLogs` over such a chunk on the official RPC: 0.23-0.25 s (3 samples) = about 45 s of raw log fetching; plus per-block hash agreement and 429 back-offs. The Base figure of about 45 min (memory) was for a 2 s-block chain with a 31.7 M start; do not reuse it. Rehearse once on the fork (1 h) |
| Relayer restart | seconds; state loaded from disk, unsure transactions reconciled before sends | audit 1116/1120 design |
| Full host loss | 2-4 h manual: new server, install scripts (`ops/install_*`), restore env from escrow (not yet existing), fund relayer, DNS | no standby |

### 2.5 Capacity headroom and certificate

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Disk | `df -h /` 47% (17 of 38 GB); inodes 13%; journal 410 MB cap 400 MB | DONE | - | - |
| Memory | 3.8 GB total, 0.2 GB free, 1.2 GB available, no swap | PARTIAL | P1 | Add 2 GB swap as a buffer for the neighbours (5 min) |
| CPU | load 0.7-0.9 on 2 vCPU; indexer used 21 min CPU in about 44 h | DONE | - | - |
| Certificate | expires 2026-12-31, certbot timer active | DONE | - | - |

### 2.6 Monitoring and alerting

| item | evidence | status | prio | fix |
|---|---|---|---|---|
| Watchdog runs | `stealth-watch.timer` every minute, journal: "problems: none" at 11:37-11:40; checks indexer lag and age, relayer reachability and balance, relayer log ALERT lines (15 templates) | DONE | - | - |
| Alerts reach a human | `watch.env` has no `TG_BOT_TOKEN` / `TG_CHAT_ID`; `notify()` prints to the journal | GAP | **P0** | Wire to the owner bot through the `_tg_gate` rule (one summary plus new alarms, repeat once a day, `STEALTH_WATCH_REPEAT_S=86400` is already set). Owner provides the chat id / allows reuse of the existing bot token; 20 min |
| Coverage holes | not watched: nginx up, cert expiry, disk, host reboot, web-file hash drift, 1Click and lightwalletd reachability, RPC 429 rate, relayer USDG fee balance, sanctions timer failing (only via relayer log) | PARTIAL | P1 | Add 5 checks to `stealth_watch.py` (half a day) |
| Threshold mismatch | watchdog balance minimum 0.0003 ETH (chain spec in `watch.env.example`) is below the relayer's own refusal point 0.001 ETH; the relayer's ALERT line fires first, so the alarm exists but only through the log path | PARTIAL | P2 | Raise to 0.003 (the README says the watchdog warns at 0.003) |
| External uptime check | none | GAP | P1 | A free external probe of `/stealth-api/rh/head` + page load from a second location (not on this host) |

### 2.7 Runbooks

| runbook | exists | status | prio | fix |
|---|---|---|---|---|
| Deploy web / rollback | `ops/deploy_prod.sh` (gated), pre-deploy tarballs; rollback only documented for Base install (README_ops.txt:102) | PARTIAL | P1 | Add "re-run deploy_prod.sh at the previous commit" and the tarball restore (30 min) |
| Relayer out of gas | stats shows balance, refusal at 0.001 ETH; no written steps | GAP | P1 | one page: how to top up, minimum buffer, who |
| Indexer stalled | watchdog flags lag; no steps | GAP | P1 | `journalctl`, check RPC, `--rewind` option exists (85ec39f), restart |
| RPC down / 429 | indexer shrinks chunks automatically | PARTIAL | P1 | second endpoint + steps |
| 1Click down | none | GAP | P2 | banner + fall back to Standard |
| Key compromise | none | GAP | P1 | steps: stop unit, drain to new key (USDG fees + ETH), new key, update nothing on chain (no admin), rotate; 30 min to write |
| Contract incident | contract has no pause or admin by design | DONE | - | recovery = new deployment + web switch |

### 2.8 Failure drills (safe on a fork or a scratch host; none run on prod)

1. Kill the relayer mid-send (SIGKILL after the send, before the receipt) on the anvil fork and check recovery with `test_relayer_recovery.mjs`.
2. Fill the state directory (read-only mount) and confirm 503 "state save failed" with no send.
3. RPC returns 429/500 for N seconds: indexer shrinks chunks, relayer refuses without charging.
4. Fork reorg of 5 blocks (`anvil_reorg`/snapshot revert): indexer `find_common` and `/known` reconcile (tests exist: `test_indexer_fork.sh`).
5. Wipe `announcements.db`, start from the deploy block against the fork, time it (this fills the estimate in 2.4).
6. Drain the relayer ETH below 0.001 on the fork: refusal, ALERT line, watchdog output.
7. Reboot a clone host with these units installed by `ops/install_*`; compare state after.
8. Restore from backup once the backups of 2.3 exist.

---

## 3. SCALABILITY (framework 13)

### 3.1 Measurement (scratch worktree of 1b4b8ec, anvil fork of RH at nice 15, ports 8845/3993/3994)

Run: `PAYERS=10 SCAN_CLIENTS=50 SCAN_SECONDS=20 SEED_ROWS=20000 node load_test.mjs`. RESULT PASS, all checks green (nonce errors 0, supply conserved, no ALERT in log).

| phase | result |
|---|---|
| 10 concurrent `/relay/pay` (burst 1.5 s, fork block time 1 s) | 10/10 accepted; HTTP latency p50 584 ms, p95 1128 ms; request to mined p50 1281 ms, p95 1881 ms; pay gas 185,007 |
| 10 concurrent `/relay` withdrawals | 10/10; HTTP p50 172 ms, p95 382 ms; mined p50 1109 ms, p95 1441 ms; withdraw gas 102,497 |
| 50 scan clients for 20 s against the indexer (20,000 synthetic rows) | 706 requests, 35 req/s, 9.6 MB/s, 0 non-200; `/head` p50 79 ms; `/announcements` p50 2782 ms, p95 4880 ms; `/balances` p50 34 ms; indexer CPU avg 126 %, max 242 %, RSS 74 MB |
| Mac load | the one-minute load average went from 4.7 to 10.2 during the run (other work was already at 4.5-6.9); I stopped there per the load limit (6) and did not raise to 100/500 scale |

Not measured here: the production read path (static history pages + nginx 1 s micro-cache): `load_test.mjs` phase 3 calls the paged `/announcements` API on the Python process directly, so it measures the old path. Earlier note (28.10): 500 scanners made that path return 74 % 503. Prod today has 0 full pages (27 rows), so every scan is one `/head`, one manifest and one tail fetch. The 500-user figure below for scanning is therefore a design estimate, not a measurement (P1 to measure).

### 3.2 Capacity table

Assumptions: a user does 1 scan, 1 pay and 1 withdraw per day, bursts are 10 % of users inside 60 s. Gas per payment from live logs: pay 3.67e-6 ETH, withdraw 1.96e-6 ETH.

| resource | at 100 users | at 500 users | first wall | fix |
|---|---|---|---|---|
| Relayer nonce lock | 200 sends/day; burst of 10 users = 20 sends in 60 s; lock hold about 0.71 s (`avg_send_ms` 713, 4 samples) = about 1.4 sends/s | 1000 sends/day; burst of 50 users = 100 sends in 60 s = 1.7/s: over capacity, queue grows. A request waits for the lock; nginx `proxy_read_timeout 30s`, `LOCK_MS` 40 s, `MAX_CONCURRENT` 64: beyond about 40 queued requests the tail times out (30 s / 0.71 s) and above 64 gets refused | about 40 simultaneous relay/pay requests | keep the lock only around nonce + broadcast (already so; the 0.71 s includes RPC reads), raise `MAX_CONCURRENT` only with a second key; measure the 100/100 burst on the fork at quiet Mac load; a second relayer key (shard) doubles throughput (1 day) |
| Daily gas budget 0.01 ETH | 200 sends = 1.1e-3 ETH/day (11 %) | 1000 sends = 5.6e-3 ETH/day (56 %); budget is not hit but a budget reservation of `maxFee x 1.25` is held per in-flight request (about 1e-3 ETH per 100 in flight) | budget is fine; the balance is the issue | see next row |
| Relayer ETH balance 0.00692 | lasts about 6 days | lasts about 1.2 days | balance, not budget; refusal at 0.001 ETH, alarm goes to the journal only | auto top-up is not possible without a second funded key; alert via Telegram (P0) and a runbook; fund 0.05 ETH (about 8 days at 500 users); owner decision |
| Fee income vs gas | pay fee 0.05 USDG/payment; withdraw fee 0 | same: 500 pay fees = 25 USDG/day against about 2.8e-3 ETH gas | subsidised withdrawals | set a withdraw fee before volume (owner) |
| nginx per-IP limits | `st_rh_post` 10 r/m + burst 5: a user does 2-4 posts, fine; shared NAT of 5 users inside a minute is borderline | CGNAT/office networks (many users, one IPv4) hit 10 r/m: "429" for honest users; IPv6 users can rotate addresses | CGNAT sharing | allow burst 10-20 for relay POSTs; relayer already limits per signer (1116 M-2); key IPv6 zones by /64 |
| `STEALTH_RELAY_PAY_PER_PAYER` 20/day, `PER_FROM` 3 | not a limit for normal users | not a limit | - | - |
| `MAX_PER_IP=60` | dead variable (code removed in audit 1116 M-2) | dead | - | delete the line |
| Indexer HTTP | tail only, cached 1 s: 100 scans cost 1-2 upstream hits per second | 500 scans: still about 1 upstream/s if the micro-cache works; if cache misses, Python (one core, GIL) saturates: 50 clients on the old path already gave 126 % CPU and p95 4.9 s | untested prod path | run the load test against nginx + pages (add a phase to `load_test.mjs`) (half a day); as history grows pages are immutable and cached 1 year |
| Indexer history size | 27 rows today | tail grows by 1 page (1024 rows) per full page; first `manifest.json` max-age 5 s | none | - |
| Public RPC rate limit (single official endpoint) | indexer polls every 2 s; relayer about 8 RPC calls per request (nginx comment); 478 `429` lines already in the indexer journal since 2026-11-02 at about 0 users | relayer 1.4 req/s x 8 = 11 calls/s plus indexer plus every browser reading balances | the endpoint's unknown limit; first real wall for both sizes | paid second RPC (P0) and put it first in `STEALTH_RPC`; keep official as fallback |
| Browser RPC per user | per scan: `ceil(found/50)` multicall batches for balances (1 for most users) + ETH fee probe (about 3 calls) + `checkLost` up to 10 lightwalletd UTXO lookups per pass; per Standard withdraw: `waitFinal` polls every 2 s up to 60 times (up to 120 calls, usually 5-10) | 500 users x about 10 calls per scan, spread over a day: low; a burst of 50 users x 10 = 500 calls in one minute: 8 calls/s to the same endpoint | same RPC | per-origin RPC caching is impossible (CSP is direct); move balance reads behind our `/balances` micro-cache only if the privacy trade is accepted (not recommended) |
| Per Private fast withdraw | 1Click status poll every 3 s (`pollMs`) for up to 20 min = up to 400 calls to 1Click per withdraw (usually 20-60) | 50 concurrent = 17 calls/s from different browsers (different IPs): acceptable | 1Click's own limits (unknown) | - |
| Per Maximum hop (lightwalletd proxy) | wallet sync of compact blocks from the birthday, then 10 s polls while waiting for spendable; 25-40 min per hop; 60 MB wasm per cold load | 50 concurrent hops = 50 full syncs through one third-party proxy; likely throttled | the proxy | second lightwalletd and cap concurrency; measure with 5 hops on a testnet-style dry mode |
| Host CPU/RAM | indexer + 2 relayers + watch: under 300 MB, under 3 % CPU | tails + relays at 500 users: under 20 % CPU estimated; 0.2 GB free and no swap is the risk when a neighbour spikes | memory pressure from other products | swap + own host |
| Egress | wasm is 60 MB, cached immutable; 100 first-time users = 6 GB; 500 = 30 GB | host bandwidth (Hetzner 20 TB) is fine, nginx serves it from disk | first visit time on slow links | serve gz/br wasm (wasm compresses about 3x) and put the wasm behind a CDN only if the owner accepts a third party in the integrity path (no) |

---

## 4. Ranked launch list (top 10)

| # | item | prio | owner decision needed | rough cost |
|---|---|---|---|---|
| 1 | Wire watchdog alerts to Telegram (`TG_BOT_TOKEN`, `TG_CHAT_ID` in `/opt/stealth-watch/watch.env`) and test with a forced low-balance alert | P0 | chat id / token reuse | 20 min |
| 2 | Second independent RH RPC provider for indexer, relayer and the web CSP; put it first; keep official as fallback | P0 | choose and pay provider (no Alchemy) | 0-50 USD/month, 2 h |
| 3 | Close the relayer funding path: fund 0.05 ETH, write the out-of-gas runbook, set the watchdog warning to 0.003 | P0 | send ETH on RH from the owner wallet | about 0.05 ETH (about 150 USD at 3,000 USD/ETH; confirm price), 30 min |
| 4 | Measure the production read path and a 100/100/100 relay burst on the fork at quiet Mac load; fix whatever breaks first | P1 (gate to P0 if launch is above 100 users) | none | half a day |
| 5 | Off-host backup of relayer state + escrow of `rh.env` + nginx/web copy to the standby host | P1 | storage target (195.201 standby or Storage Box) | 2 h, 0-4 EUR/month |
| 6 | Privacy hygiene: `UMask=0077` + chmod 600 on relayer log, no query strings in nginx access log for `/stealth-api/`, retire legacy root v2 relayer/indexer and its two nginx locations | P1 | OK to switch off Base v2 URL | 1 h |
| 7 | Own `node_modules` (npm ci from lockfile) and one uid per role/chain | P1 | none | 1.5 h |
| 8 | Schedule and rehearse the overdue reboot (kernel 6.8.0-90 to 147, 206 days up); add swap | P1 | maintenance window (affects all products on the host) | 30 min + risk |
| 9 | Close audit 1181 (2M/8L/9I) and get one clean external round (0H/0M) on the launch HEAD; freeze features | P1 | accept a launch gate of "one clean round" | 1-2 days, audit cost per job |
| 10 | Decide on Maximum mode economics (loses 12-20 % under about 50 USD; 25-40 min) and add a withdraw fee; show honest per-mode privacy labels | P1 | product decision | 2 h UI + decision |

Further (P2): wasm hash check in the browser, CSP and HSTS in nginx headers, IPv6 /64 zones, systemd sandbox hardening lines, `.bak` files out of `sites-enabled`, dead `MAX_PER_IP`, second lightwalletd with failover, separate host for the relayer key.

## 5. One-line verdict per section

- Security: the contract and relayer logic are strong (immutable, verified, no admin, limits and locks audited 60+ times, web and vendor hashes match HEAD), but on the host the key shares a uid and `node_modules` with other things, logs link stealth addresses to destinations in a world-readable file, and a root-run legacy v2 relayer is still publicly reachable.
- Reliability: units restart and start at boot and the watchdog runs every minute, but no alert can reach a human, there is no off-host backup of anything Stealth, RH depends on one RPC, one 1Click and one lightwalletd proxy, and the host has not rebooted in 206 days with a kernel update pending.
- Scalability: one relayer key handles about 1.4 sends/s (a 40-request burst is its first wall), the gas budget is fine but the 0.0069 ETH balance lasts about 6 days at 100 users and 1 day at 500, and the single official RPC (already returning 429s) is the first real wall; the production scan path and the 100/500 tests are not yet measured (this pass ran 10 pays, 10 withdrawals and 50 scanners only, then stopped at Mac load above 6).

Notes on method: one temporary file was created and removed on 167.235.72.45 /tmp while counting report headers; no Dispatch file was modified. Env files on 46.224 were not read (only key names, mode and owner). Measured numbers carry the sample sizes stated; items marked estimate or "not measured" were not run.
