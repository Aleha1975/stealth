Install notes (NOT done; files only)
  useradd --system --home /opt/stealth --shell /usr/sbin/nologin stealth   (if absent)
  install -d -o stealth -g stealth -m 750 /opt/stealth/data-rh /opt/stealth/data-watch
  /opt/stealth/{stealth_indexer.py,relayer.mjs,relay-util.mjs,sanctions/,chains.json,stealth_watch.py,node_modules->symlink,package.json} readable by user stealth
  install -m 600 -o stealth -g stealth rh.env /opt/stealth/rh.env ; watch.env likewise
  cp stealth-*.service stealth-watch.timer /etc/systemd/system/ ; systemctl daemon-reload
  systemctl enable --now stealth-indexer-rh stealth-relayer-rh stealth-watch.timer
  nginx: zones into http{} (see header of stealth-rh.conf), the locations into the app.deepyield.ai server{}; nginx -t && systemctl reload nginx
  Base units keep running untouched on 3873/3874; RH uses 3883/3884 and /opt/stealth/data-rh.
  Watchdog log of RH relayer = /opt/stealth/data-rh/relayer.rh.log (set STEALTH_RELAY_LOG above).

Allow-list for trusted test clients (audit 1108; empty = off, NOT set in any committed config)
  STEALTH_RELAY_ALLOW_KEYS=<trusted host IP>       (comma-separated IPv4 addresses or IPv6 addresses / /64 keys: an IPv6 entry covers its whole /64; put it in rh.env / relayer.env on the host only)
  Requests from these networks skip the per-key token bucket, the per-IP and per-payer daily counters and the failure counter. They still pass EVERY validation, the sanctions check,
  MAX_CONCURRENT and the daily gas budget. The relayer logs one fixed line per allowed request ("allow-listed request <key> relay|pay").
  nginx needs the same exemption from limit_req: see the "allow-list" snippet in stealth-rh.conf (keep both lists identical).

Known limits and accepted risks (audit 1116)
  M-2  (revised decision) Accounting is split by who the request proves to be. A request whose EIP-712 signature recovers to `from` is charged to that SIGNER (lower-cased `from`): per-signer failure
       budget (STEALTH_RELAY_FAIL_PER_SIGNER, default = FAIL_PER_IP, per hour), per-signer RPC token bucket, and the per-address daily counters. Only requests WITHOUT a valid signature (offline junk)
       are charged to the network key (IPv4 / IPv6 /64, STEALTH_RELAY_FAIL_PER_IP), and that junk counter never blocks a request that carries a valid signature. The per-network daily cap
       (STEALTH_RELAY_MAX_PER_IP) was removed; users behind one carrier NAT do not share fate. A signed request is still bounded by its signer's budget, MAX_CONCURRENT and the daily gas budget.
       All per-signer / per-network maps are LRU-bounded. nginx limit_req is still per network and is the outer rate limit.
  I-1  Real client IP: if Cloudflare (or any proxy) is in front of nginx, the real_ip block in stealth-rh.conf (set_real_ip_from <proxy ranges>; real_ip_header CF-Connecting-IP) MUST be active
       in the deployed vhost. Without it every per-key limit sees only the proxy's addresses and the shared-fate problem above becomes a global lockout. Check with a request log after deploy.
  I-3  EIP-3009 authorizations are public once broadcast: anyone may submit the same transferWithAuthorization first. The funds still reach the signed recipient; the relayer's own transaction
       then reverts and its gas is lost. Inherent to the pattern, bounded by the daily gas budget (STEALTH_RELAY_GAS_BUDGET_WEI).

Relayer state (audit 1116)
  The state file is written with fsync (file and directory). A send is only made after its "unsure" record is durable; if the state directory is full / read-only / not writable the relayer
  answers 503 and sends nothing ("ALERT state save failed"). A state file that exists but cannot be loaded makes the relayer REFUSE TO START ("ALERT state load failed"); fix or move the file
  deliberately (a missing file is a normal fresh start). The unsure table is capped (STEALTH_RELAY_UNSURE_MAX, 2000): when full, new sends get 503 ("ALERT unsure table full") instead of evicting.
  A pair (feeAuth + main) is relayed fee first; if the main send fails, the retry with the same signatures skips the already collected fee.

Charging model and nonce model (audit 1120, round 8; supersedes the M-2 text above where they differ)
  Charging.  A signer's budgets (STEALTH_RELAY_FAIL_PER_SIGNER, the RPC token bucket, the daily per-address / per-payer counters) are charged ONLY by a request that carries a valid signature
       over an authorization that is still UNUSED (the relayer reads authorizationState once, before it charges anyone). Replays of public signatures (dedupe hit, known-used cache, used on chain,
       expired, not yet valid, "still being confirmed") are charged to the NETWORK key (STEALTH_RELAY_FAIL_PER_IP, weight 0.2 for honest-class refusals) and never to the signer. A fresh signed
       request that fails is charged to its signer AND to the network's signed-failure budget (STEALTH_RELAY_FAIL_PER_NET_SIGNED, default 10 x FAIL_PER_SIGNER per hour): throwaway signers are
       bounded by it (429 "too many failed requests from this network", before any RPC). Offline junk only fills the junk counter, which never blocks a fresh signed request.
       Cost: a valid-signature request costs one authorizationState read before the other checks (an empty-wallet pay: 2 reads, was 1).
       ACCEPTED (unchanged): availability against distributed IP rotation. No global ceiling exists or is to be added; nginx limit_req + MAX_CONCURRENT + the daily gas budget are the outer bounds.
       Accepted residual: an attacker who bypasses nginx per-IP limits (rotating IPs) can still spend one authorizationState read per distinct (victim, nonce) once; the result is cached forever (used is permanent).
  Nonce.  The local nonce is reconciled with the node's PENDING count at every lock acquisition. A send on the wire (also one whose holder hit the lock deadline) is tracked in `flights` until it
       settles; later sends stay above it. If it then never reached the node, the next holder finds a gap (local > pending, nothing on the wire, no recent send of ours at the pending nonce:
       STEALTH_RELAY_GAP_GRACE_MS, 15 s) and fills it with a self-transfer (signed locally, deadline checked, broadcast without an await in between), or simply resets. No restart is ever needed.
  Counters. The daily per-address / per-payer count is incremented and decremented through ONE flag, `counted` on the shared `unsure` entry of the authorization (audit 1124 F5: never copied into a per-request object), also for a send that settles after the lock deadline. One watcher per hash (a late orphan and a retry cannot double-charge or double-watch; the second owner returns its own gas reservation).
  I-1 (1120)  rh.env.example sets STEALTH_RELAY_FEE_MIN=0: the withdraw-fee path (and the fee-skip-on-retry logic, audit 1116 L-5) is dormant on RH. feePaid is capped at 2000 entries: if a pair retry came
       after 2000 other fee sends, the retry would be refused "authorization already used" after the fee was collected (bounded by the daily gas budget). Enable fees only after re-running the pair tests.
  I-2 (1120)  FIXED: the dedupe key covers from, nonce, recipient, value and validBefore (pay: nonce, amount, validBefore), so a re-signed different transfer under an old nonce is never answered with
       the old hash (it gets "authorization already used").
  I-3 (1120)  FIXED for the second "nonce too low" attempt (its unsure entry is removed). A record that was written but whose send never happened (directory fsync failure after the rename) is
       rewritten away by the next successful state write (the failed write sets the dirty flag); until then it blocks only that authorization's retry, for at most DEDUPE_MS, and counts toward UNSURE_MAX.

  Audit 1124 (round 9). All findings are non-fund-loss: an EIP-3009 authorization is one-use on chain.
  F1  FIXED: gas-budget and low-balance refusals are net:true (relayer-wide state, not the signer's doing): charged to the network key, never to the signer.
  F2/F3/F4 FIXED at the root: nonce truth and every transaction probe (pending/latest count, getTransaction, receipt, authorizationState as a proof, sendRawTransaction) go to ONE sticky RPC
       (the first STEALTH_RPC entry); it moves to the next entry only when the endpoint is unusable (5xx, timeout, connection, 429, HTTP 401/402/403/408, JSON-RPC limit exceeded / header not found / missing trie node; audit 1128 L-1) and the switch is logged ("rpc endpoint switched"). Balances, gas and fee
       estimates keep the failover transport. A gap fill needs two pending-count reads STEALTH_RELAY_GONE_GAP_MS apart that agree. Restart: the persisted unsure records (written before every send, with
       the nonce) refill nonceOfHash and lift the starting local nonce for sends younger than STEALTH_RELAY_GAP_GRACE_MS; nothing new is persisted.
  F4 residual (documented): provenGone() can still be wrong if a node lies consistently for >= 2 probes. A false "gone" makes the relayer sign a second transaction for the same authorization; because the
       on-chain authorization is one-use, only one of the two can succeed and the other reverts: the cost is the reverted transaction's gas (bounded by the daily gas budget), NEVER funds.
  F6  FIXED: sendAndTrack receives the caller's d0 (the day the reservation was credited under) instead of recapturing st.day.
  I2  FIXED: a variable that is present but empty in the own environment is no longer refilled from the foreign env file.
  I1  Partly covered: test_fork_e2e.mjs now exercises the sticky endpoint with a dead first RPC and a lagging pending read; a full two-backend divergence harness is not built.
  I3  ACCEPTED: a malformed numeric field (BigInt SyntaxError) is thrown before any state-dependent step and answered 400 from the generic handler; it is charged to the network key as junk (ctx.signer unset). The message only echoes the caller's own input.

  Audit 1128 (round 10). No fund loss.
  L-1 FIXED: an endpoint refused for auth / quota / lag is left like a dead one; when every endpoint refuses, the answer is Upstream (503), the signer is not charged.
  L-2 FIXED: provenGone() reads its whole proof from one endpoint; a switch during the proof means "not proven" (keep waiting). The watcher's two "dropped" probes are pinned the same way.
  L-3 FIXED: only a receipt-wait TIMEOUT means "stuck"; an RPC error is retried twice (GONE_GAP_MS apart) and then logged as "ALERT receipt wait failed" with the reservation kept; the wait fails over like every node call.
  L-4 FIXED: a feeAuth with the same nonce as the transfer is refused offline.
  L-5 FIXED: an unconfirmed (ambiguous) send keeps its gas reservation (the day budget never undercounts); a retry reserves again (safe direction, like I-1).
  I-1 ACCEPTED (safe direction, now also true for L-5). I-2 ACCEPTED (self-healing within GAP_GRACE_MS, delay only; the lift is what protects a real recent send). I-3 ACCEPTED (availability, per the client's decision).

Base v3 (StealthPay 0xC07f54984AbDa1EF76DaB6F602270B76a04E916d, block 53408013) -- NEW stack next to the live Base v2 stack
  Files: base.env.example, stealth-indexer-base.service, stealth-relayer-base.service, stealth-base.conf (nginx snippet), ../../ops/install_base.sh.
  Live v2 stack (stealth-indexer / stealth-relayer, 3873/3874, /opt/stealth, StealthPay v2 0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76) is never touched. RH (3883/3884, /opt/stealth-rh) is never touched.
  New: code and state in /opt/stealth-base (state in /opt/stealth-base/data), ports 127.0.0.1:3893 (indexer) and :3894 (relayer), nginx https://app.deepyield.ai/stealth-api/base/ .
  Old payments: the indexer reads EVERY Announcer event from STEALTH_START_BLOCK=31700000 (the live indexer's start, before v2), so the new database contains the v2 payments, and the client scan
  (view tag + key, no contract check) finds them. STEALTHPAY_LEGACY=<v2> makes /known accept v2-announced addresses: without it the relayer refuses to withdraw from a v2-paid address ("not a stealth address paid through Stealth").

  1. Create /opt/stealth-base/base.env WITHOUT the key passing through a terminal (run as root on the host, from the repo's server/ directory; prints only a yes/no):
       ( umask 077; install -d -m 755 /opt/stealth-base; { grep -v '^RELAYER_KEY=' deploy/base.env.example; grep -m1 -E '^RELAYER_KEY=0x[0-9a-fA-F]{64}$' /opt/stealth/relayer.env; } > /opt/stealth-base/base.env ) && chown stealth:stealth /opt/stealth-base/base.env && chmod 600 /opt/stealth-base/base.env && [ "$(grep -c '^RELAYER_KEY=0x' /opt/stealth-base/base.env)" = 1 ] && echo KEY-LINE-COPIED
     (The key line is read from the root-only file /opt/stealth/relayer.env straight into base.env; /opt/mprhedged/exec/.env is not used. If the old file stores the value quoted or in another form the count is 0 and nothing usable was written: fix by hand, do not paste a key into a terminal.)
     Alternative with its OWN key (no shared account): { grep -v '^RELAYER_KEY=' deploy/base.env.example; node --input-type=module -e 'import{generatePrivateKey}from"viem/accounts";console.log("RELAYER_KEY="+generatePrivateKey())'; } > ... (run in /opt/stealth-base so viem resolves), then read the address
     with the relayer's own start line (journalctl -u stealth-relayer-base | grep " as ") and fund it with ETH on Base. Default above = the live relayer's funded key.
  2. Dry run, read the output:   ops/install_base.sh            (prints every action; changes nothing)
  3. Apply:                      ops/install_base.sh --apply --add-include
     (copies code, installs the two units, nginx zones + snippet + the include line in the app.deepyield.ai vhost, nginx -t, reload, starts only the two new units; backups in /var/backups/stealth-base/<time>/.
      Without --add-include it prints the include line for you to add by hand.)
  4. Checks (the first run indexes Base from 31.7M: minutes; head must reach the chain):
       curl -s 127.0.0.1:3893/stealth-api/head          -> chain base, start 31700000, count >= the live indexer's count (curl -s 127.0.0.1:3873/stealth-api/head), lag small
       curl -s 127.0.0.1:3894/stealth-api/relay/stats   -> chain base, stealthpay 0xC07f...916d (checksummed), pay_enabled true, relayer balance > 0
       curl -s "127.0.0.1:3893/stealth-api/known?addr=<a v2-paid stealth address>"   -> {"known":true}
       curl -s https://app.deepyield.ai/stealth-api/base/head ; curl -s https://app.deepyield.ai/stealth-api/base/pages/manifest.json
       systemctl is-active stealth-indexer stealth-relayer stealth-indexer-base stealth-relayer-base      (all four active)
  5. Only then publish the web copy whose chains.js has base.stealthPay = v3 and base.api = "/stealth-api/base" (lab first: ops/deploy_lab.sh).
  Rollback (touches only new things; the live stack never stopped):
       systemctl disable --now stealth-relayer-base stealth-indexer-base
       restore the vhost: cp -p /var/backups/stealth-base/<time>/etc/nginx/sites-enabled/app-deepyield /etc/nginx/sites-enabled/app-deepyield   (or delete the include line), rm /etc/nginx/snippets/stealth-base.conf /etc/nginx/conf.d/stealth-base-zones.conf, nginx -t && systemctl reload nginx
       rm /etc/systemd/system/stealth-{indexer,relayer}-base.service && systemctl daemon-reload ; (optional) rm -r /opt/stealth-base
       web: redeploy the previous web copy (base.stealthPay v2, api /stealth-api).
  Risks (Base v3):
   - Shared relayer key: while stealth-relayer (v2) and stealth-relayer-base run, both send from ONE account. Each reconciles its nonce with the node's pending count and fills gaps (see "Nonce" above), so a collision
     costs at most a failed attempt that the client retries, but it is real. Use the own-key alternative in step 1, or stop the v2 relayer once the web no longer points at it.
   - Funds: the v2 contract holds no user money (payToken moves tokens straight to the stealth address). Funds sit at the stealth addresses; withdrawal is USDC transferWithAuthorization from the stealth address, independent of either StealthPay.
   - Cut-over is per web copy: an open old page keeps using v2 API and v2 contract until reloaded. Keep the v2 stack running while old pages may exist.
   - The pages cache in the browser is keyed chain|page|version (not by API): a rebuilt database with the same version would be served stale pages. Do not delete /opt/stealth-base/data after users have scanned; if you must, bump the manifest version.
   - Not installed by this script (not installed for RH on the host either): stealth-watch.timer and stealth-sanctions.timer. If the watchdog is added later, append base=http://127.0.0.1:3893|http://127.0.0.1:3894|/opt/stealth-base/data/relayer.base.log|0.0003 to STEALTH_WATCH_CHAINS.
     The sanctions list in /opt/stealth-base/sanctions/evm.json is the repo copy; refresh it before launch.
   - install_rh.sh does not copy relay-util.mjs (current relayer.mjs imports it); install_base.sh does. Re-running install_rh.sh --apply on a fresh host would fail for that reason.

Audit 1158 (indexer + nginx isolation conf) -- what changes on deploy
  1. STEALTHPAY is REQUIRED in every indexer env file (0x + 40 hex). The indexer exits at start without it (it used to accept any announcer caller). Check first:
       grep -c '^STEALTHPAY=0x' <env file>      (count only; must print 1 for each indexer env: live Base, RH, Base v3)
  2. The database gets a new column ann.paid (added automatically at start, no data lost). /known now needs a settled Transfer of the chain token to the stealth address
     in the announcing transaction's receipt (>= MIN_KNOWN_USDC) AND a row at or below the safe block. Old rows are filled by the indexer itself (50 receipts per cycle, ring cursor);
     to do it at once, stop nothing and run:  python3 stealth_indexer.py --backfill-paid   (same job as --refill-payers; also fixes payer NULL rows and rewrites history pages).
     Until a row is filled /known answers false for it (fail closed). On RH the safe tag lags the head, so a fresh payment becomes withdrawable when the safe block passes it.
  3. New fields (additive): /head {final_block, safe_block, epoch}; /announcements rows {final} and top-level {final_block, epoch}. epoch rises whenever a reorg removed rows.
  4. New optional env: STEALTH_REQ_DEADLINE (30 s, whole request), STEALTH_ANN_CACHE_BYTES (16 MiB). Paths are matched exactly: /<name>, /stealth-api/<name>, /stealth-api/<chain>/<name>.
  5. nginx: ops/nginx-stealth-zec.conf now includes mime.types, sets nosniff / no-referrer / frame-ancestors 'none', and the wasm year-cache header has no `always`. nginx -t, reload,
     then check: curl -sI https://app.deepyield.ai/stealth-zec/ | grep -iE 'content-security|x-content|referrer|cross-origin' ; and open the wallet page once (crossOriginIsolated === true).

Audit 1160 (relayer.mjs). Operator notes
  M-1  Stuck sends. A replacement is priced max(stuck price, CURRENT market price) + STEALTH_RELAY_BUMP_PCT, at most STEALTH_RELAY_MAX_REPLACE (3, max 4) times, STEALTH_RELAY_STUCK_S apart. After a restart every persisted
       unsure send gets its watcher back ("re-attached watchers to unconfirmed sends N" in the log). Every STEALTH_RELAY_WEDGE_S/2 (default WEDGE_S = 2 x STUCK_S) the relayer compares its latest and pending nonce; a pending nonce
       older than WEDGE_S with no watcher is re-sent from the pool at the market fee, or, if it cannot be re-sent, replaced by a self-transfer ("ALERT wedged nonce"). It also frees a nonce stuck by ANOTHER process using the same key
       (the Base v3 relayer shares the key and nonce with the live Base relayer).
  M-2  Client address = rightmost X-Forwarded-For hop, honoured only when the TCP peer is loopback. nginx must OVERWRITE the header (proxy_set_header X-Forwarded-For $remote_addr;) in every relayer location
       (stealth-rh.conf / stealth-base.conf do; so do the live vhosts, checked 02.11). Never $proxy_add_x_forwarded_for. The nginx POST timeout is 45 s (> STEALTH_RELAY_LOCK_MS 40 s).
  L-1  The collected-fee marker is written in the same durable save as the unsure record of the fee send, before the fee is sent.
  L-2  STEALTH_RELAY_MAX_FEE_WEI = hard ceiling on maxFeePerGas / gasPrice of every transaction we sign. Default = GAS_BUDGET / 4 / 250000 (one pay-sized transaction costs at most a quarter of the day):
       Base 0.0002 ETH -> 0.2 gwei, RH 0.01 ETH -> 10 gwei. Above it: 503 "network fees are very high", "ALERT fee ceiling exceeded". Replacements are charged to the day's budget and refused past it;
       a gap fill is charged too but may pass the budget by at most budget/4 (it unblocks sends that were already paid for).
  L-3  Startup refuses: STEALTHPAY set and STEALTH_RELAY_PAY_FEE_MIN=0. STEALTH_RELAY_REQUIRE_WITHDRAW_FEE=1 additionally refuses STEALTH_RELAY_FEE_MIN=0 (default off: the withdraw fee is off by product decision, logged at start).
  I-3  <state file>.lock holds the pid; a second process on the same state file refuses to start (a lock of a dead pid is taken over). Deploy: stop the old unit before starting the new one (systemd does).
  I-1  The "allow-listed request" line is rate limited (STEALTH_RELAY_ALLOW_LOG_PER_MIN, 600).
  I-2  nginx POST timeout 45 s instead of 30 s (see M-2). L-4 (front-run burn of a /relay authorization) is inherent to EIP-3009 and stays accepted: bounded by 3 per address per day and the gas budget.
Audit 1164 (re-review of the 1160 / 1161 fixes), operations notes
  M-1  A replacement of a stuck send is signed from the call the relayer itself signed and persisted in the unsure record (`tx`: to, data, gas; value 0; the record's nonce), never from what an RPC node returns for the
       stuck hash. The node is asked only for the stuck transaction's FEES, and must show OUR transaction (from = relayer, same nonce / target / data, value 0) or nothing is signed. UNSURE RECORDS WRITTEN BY AN OLDER
       VERSION have no `tx`: after the upgrade they are only watched (log "stuck transaction has no persisted call, watched only"); if such a transaction wedges the nonce for WEDGE_S, the periodic check cancels it
       with a 0-value self-transfer at the same nonce (the authorization stays unused, the client may retry; gas is charged to the day, see L-3). No operator step is needed; new sends carry `tx` from the first save.
  L-1/L-4  The lock file holds "<pid>:<process start time>". A live pid with another start time (reused by an unrelated process) is a stale lock; the check also runs for pids of other users. A stale lock is moved to
       a unique name and compared before it is removed; if a concurrent starter's live lock was moved by mistake it is put back and this process exits (systemd starts it again). Linux only for the /proc checks.
  L-2  The wedge check skips a round on any lookup error other than "not found" (no fill over a transaction that may exist). L-3 A gap fill is checked against and charged to the current day.
  L-5  /relay/status follows the whole chain of replacements again after a restart, and asks every hash of the send (newest first).
  I-1  An STEALTH_RELAY_ALLOW_KEYS entry that is not an IPv4 / IPv6 address is dropped at start with a log line ("ALLOW_KEYS entry dropped"); check the log after changing the list. clientIp() returns only a real address or "-".
  I-2  An IPv6 allow-list entry covers its whole /64 (the same unit as every per-network limit, one customer owns a /64): do not allow-list a shared hosting address that way; IPv4 entries match one address.
  I-3  If the nonce-lock deadline passes before the broadcast, the unsure record and the fee marker written for it are taken back (nothing was sent).
  I-4  For client authors: after a half-failed pair (fee leg mined, main leg failed) RETRY WITH THE SAME SIGNATURES. A client that signs new authorizations (new nonces) pays the fee a second time; EIP-3009 gives the
       relayer no way to tell the two requests apart. Bounded by MAX_PER_FROM and the small fee.
  I-5  Accepted residual: someone who lands payETH / payToken on the destination between the relayer's used[] read / gas estimate and inclusion makes the relayer's transaction revert on the relayer's gas. On Base
       the sequencer has no public mempool; the cost is bounded by MAX_PER_PAYER_PER_DAY (20) per payer and the daily gas budget.
  Deploy order: relayer.mjs + relay-util.mjs + stealth_watch.py, restart the relayer unit (brief 503s), regenerate the nginx snippets from the two .conf files, nginx -t, reload.
  First start on an existing state file: unsure records written before this version carry no reserve; their watchers do not adjust the day's gas (conservative), and their send-time reservation stays until midnight.

StealthPay used[] griefing and fee collision (audit 1161; contracts unchanged, full text in audit/stealthpay-v3-residuals.md)
  M-1  Anyone can mark a one-time stealth address "used" first (payETH with 1 wei is the cheapest way; it works across payToken / payWithAuthorization / payETH, needs no mempool or
       sequencer access when the attacker sees the request, e.g. a relayer). For payWithAuthorization this kills the payer's signature (it is bound to that address): a new signature is
       needed. No funds are lost. /relay/pay therefore reads StealthPay.used(stealth) before it spends gas and refuses with "stealth address already used: ..." (honest, charged to the network);
       the web client checks used[] before asking the wallet and derives a new one-time address automatically (gasless: up to 2 retries with "please sign again"; own gas: 1 retry after a confirm).
  L-1  feeRecipient == stealth makes the Paid event under-report; the relayer answers "bad destination" and the client refuses to sign. The indexer's paid column sums all Transfers to the stealth address.
  The NatSpec text in src/StealthPay.sol is NOT changed (it would change the metadata hash of the verified deployed bytecode).

Audit 1163 (indexer re-review) -- what changes on deploy
  M-1  Head trust. With >= 2 endpoints the indexer takes the SECOND-highest head (a node that overstates its head cannot move the index over unmined blocks); with one endpoint every step is cut to the highest block that endpoint returns
       (eth_getBlockByNumber) and a lower head is a rollback only after two reads in a row. Base ships two endpoints: live Base = dRPC (STEALTH_RPC, key only in the root-only env file) + publicnode, see base.env.example.
       Tolerance STEALTH_HEAD_SKEW_S: 300 s on Base (the safe tag moves in L1-batch jumps of minutes), 30 s on RH (latest, seconds); beyond it for STEALTH_FALLBACK_S (600 s) the lagging endpoint is treated as stuck and the single-endpoint rule applies.
       RH chains.json has one official endpoint: add a second one in STEALTH_RPC when one exists. block_ms in chains.json (Base 2000, RH 104: measured over 100k blocks on 02.11.2026) converts seconds to blocks.
       RECOVERY after a past lie (rows missing): stop the service, then  python3 stealth_indexer.py --rewind <N blocks>  (same env file), start the service. Rows above stay; the re-read only inserts the missing ones. N = blocks since the first bad head.
  L-1  paid = the one Transfer to the stealth address whose amount equals the announced amount and that StealthPay made (from = StealthPay) or that precedes the announce log in the receipt (payToken: transferFrom by the payer, then announce;
       payWithAuthorization: payer -> StealthPay -> stealth, then announce; v2 and v3 have the same layout). Extra Transfers in the same tx no longer count. This replaces the 1161 L-1 "sum of all Transfers" (feeRecipient == stealth now gives paid = the net, as announced).
       After deploy run once:  python3 stealth_indexer.py --backfill-paid  (rows filled earlier keep the old sum until then; /known only needs paid >= MIN, so nothing is refused that was accepted for a real payment).
  L-2/L-3  reorg delete + epoch bump in one transaction; the request watchdog starts inside the permit-releasing try.
  L-4  /balances without Multicall3 takes at most STEALTH_MAX_SINGLE (20) addresses; every API request has an RPC-call budget STEALTH_REQ_MAX_CALLS (100). limit_req for /stealth-api/base/ and /stealth-api/rh/ is in stealth-base.conf / stealth-rh.conf (st_*_read on every
       indexer location). The OLD live Base location (/stealth-api/ -> 3873, outside this repo) must carry its own limit_req_zone/limit_req on the same routes: check it on the host.
  I-1  announcement cache: also <= STEALTH_ANN_CACHE_ENTRIES (2048) entries, and only for since <= current max id.
  I-2  one configured endpoint: a lower head must repeat on the next read; several configured but one answering and lagging: accepted as a rollback after STEALTH_FALLBACK_S instead of stalling forever.
  I-3  ops/nginx-stealth-zec.conf: no types{} override at the zec location any more (inherits the http map); the .wasm location has an empty types{} + default_type application/wasm. nginx -t before reload.
  I-4  STEALTH_KNOWN_SAFE=0 refused unless every RPC is loopback or STEALTH_FORK=1; final_block and the pages margin use one formula; a failing DB open answers 500.
