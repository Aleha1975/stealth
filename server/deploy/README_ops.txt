Install notes (NOT done; files only). Production layout on the app server (audit 1179 F2):
  /opt/stealth        live Base v2 code (stealth-indexer / stealth-relayer, 3873/3874): never overwritten by any script of this repo
  /opt/stealth-rh     RH stack: rh.env (chmod 600, owner stealth), code, data in /opt/stealth-rh/data, sanctions in /opt/stealth-rh/sanctions
  /opt/stealth-base   Base v3 stack (ops/install_base.sh): base.env, data in /opt/stealth-base/data, sanctions in /opt/stealth-base/sanctions
  /opt/stealth-watch  watchdog (ops/install_watch.sh): stealth_watch.py, chains.json, watch.env (chmod 600), data/watch_state.json
  Watchdog and OFAC refresh: ops/install_watch.sh [--apply] (dry run by default) installs stealth-watch.service/.timer and stealth-sanctions@.service/.timer, enables stealth-watch.timer, stealth-sanctions@rh.timer and
    stealth-sanctions@base.timer, chowns the two sanctions directories to stealth, runs the first refresh. watch.env is created WITHOUT Telegram lines: add TG_BOT_TOKEN / TG_CHAT_ID by hand (chmod 600).
  ops/install_rh.sh is the LEGACY installer (writes into /opt/stealth); its --apply refuses while /opt/stealth-rh exists. Update the RH stack by hand: copy the files, then restart stealth-indexer-rh / stealth-relayer-rh.
  The *-rh.service units in this directory still show the legacy /opt/stealth paths: on the host the installed copies point to /opt/stealth-rh; compare before copying (diff against /etc/systemd/system).
  nginx: zones into http{} (see header of stealth-rh.conf), the locations into the app.deepyield.ai server{}; nginx -t && systemctl reload nginx
  Base units keep running untouched on 3873/3874; RH uses 3883/3884 and /opt/stealth-rh/data.
  Watchdog log of RH relayer = /opt/stealth-rh/data/relayer.rh.log (set STEALTH_RELAY_LOG above).
  Gas budget: the shared daily gas budget (GAS_BUDGET_WEI_PER_DAY, per chain) is the only bound on reverted relays (a stale or reorged /known answer, many fresh addresses; audit 1179 F3). Watch the watchdog ALERT / 'reverted' lines.

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
   - Not installed by this script: the watchdog and the OFAC refresh timers; ops/install_watch.sh does it (stealth-watch.timer, stealth-sanctions@base.timer, stealth-sanctions@rh.timer). The base chain line in watch.env.example is already there.
     The sanctions list in /opt/stealth-base/sanctions/evm.json is the repo copy until the first refresh.
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
  M-1  (REPLACED by the single rule of audit 1165 below: second-highest head, pinning, fallback, STEALTH_HEAD_SKEW_S, STEALTH_FALLBACK_S and the per-step block-number probe are gone.)
       RECOVERY after a past lie (rows missing): stop the service, then  python3 stealth_indexer.py --rewind <N blocks>  (same env file), start the service. Rows above stay; the re-read only inserts the missing ones.
       N = blocks since the first bad head. Since 1165 it also bumps `epoch` (clients re-read) and drops the stored head hash.
  L-1  paid = the one Transfer to the stealth address whose amount equals the announced amount and that StealthPay made (from = StealthPay) or that precedes the announce log in the receipt (payToken: transferFrom by the payer, then announce;
       payWithAuthorization: payer -> StealthPay -> stealth, then announce; v2 and v3 have the same layout). Extra Transfers in the same tx no longer count. This replaces the 1161 L-1 "sum of all Transfers" (feeRecipient == stealth now gives paid = the net, as announced).
       After deploy run once:  python3 stealth_indexer.py --backfill-paid  (rows filled earlier keep the old sum until then; /known only needs paid >= MIN, so nothing is refused that was accepted for a real payment).
  L-2/L-3  reorg delete + epoch bump in one transaction; the request watchdog starts inside the permit-releasing try.
  L-4  /balances without Multicall3 takes at most STEALTH_MAX_SINGLE (20) addresses; every API request has an RPC-call budget STEALTH_REQ_MAX_CALLS (100). limit_req for /stealth-api/base/ and /stealth-api/rh/ is in stealth-base.conf / stealth-rh.conf (st_*_read on every
       indexer location). The OLD live Base location (/stealth-api/ -> 3873, outside this repo) must carry its own limit_req_zone/limit_req on the same routes: check it on the host.
  I-1  announcement cache: also <= STEALTH_ANN_CACHE_ENTRIES (2048) entries, and only for since <= current max id.
  I-2  (REPLACED by 1165: a head below head_done is never a rollback by itself; the loop waits, a real fork shows as a parentHash mismatch, see below.)
  I-3  ops/nginx-stealth-zec.conf: no types{} override at the zec location any more (inherits the http map); the .wasm location has an empty types{} + default_type application/wasm. nginx -t before reload.
  I-4  STEALTH_KNOWN_SAFE=0 refused unless every RPC is loopback or STEALTH_FORK=1; final_block and the pages margin use one formula; a failing DB open answers 500.

Audit 1165 (indexer, third re-review) -- ONE trust rule instead of pinning / second-highest / fallback / skew
  Rule.  head_done moves to block b only when b's hash is confirmed. >= 2 configured endpoints: the SAME hash must come from two different endpoints (a block hash covers the whole chain under it); logs for [a,b]
         come from one of those two, every log must lie in [a,b] and carry the agreed blockHash of its block (a log of another chain / an invented block is refused). Disagreement, one endpoint down, or a block only
         one endpoint has -> indexing WAITS, it never advances on one endpoint's word. Exactly ONE configured endpoint (RH today): a trusted provider by configuration (stated in rh.env.example); the only check is that
         block a's parentHash equals the stored hash of head_done (meta head_hash), so a switched or forking backend makes the indexer step back 100 blocks and re-read (INSERT OR IGNORE, a non-insert-only reconcile
         follows) instead of skipping. Residual: an endpoint that agrees on the hash at b but OMITS logs inside [a,b] is not detected (the 60 s reconcile window re-reads the last 100 blocks); a lying single provider
         is not detected at all.
  Wait.  No progress for STEALTH_WAIT_ALERT_S (default 600 s = a node restart or resync; longer is an outage someone must see) -> "ALERT indexing has not advanced ..." in the log, repeated every 600 s; /head `ts` stops
         moving meanwhile, so the stealth_watch lag check fires too. Base with two providers: if one is down the index stalls until it is back (by design); remove its URL from STEALTH_RPC to run on one, knowingly.
  Safe.  With >= 2 endpoints the safe tag is the lower of the two (second-highest of >= 3), never one endpoint's.
  Receipts.  With >= 2 endpoints a receipt (payer, paid, therefore /known) counts only if its blockHash equals the agreed hash of its block (blockNumber alone is not enough). A receipt that fails stays NULL and fix_rows retries.
  Removed.  pick_head, _pin, _confirm_upto, _blk_exists, HEAD_SKEW (STEALTH_HEAD_SKEW_S), FALLBACK_S (STEALTH_FALLBACK_S), automatic head rollback on a low read. An old STEALTH_HEAD_SKEW_S / STEALTH_FALLBACK_S in the env file is ignored.
  L-2  One process-wide token bucket for API-originated RPC calls: STEALTH_API_RPC_RATE 20 calls/s, STEALTH_API_RPC_BURST = STEALTH_REQ_MAX_CALLS (100). Empty bucket -> HTTP 429 (retryable). The Base nginx zones now key on $st_ipkey
       (one IPv6 /64 = one client) like RH; the map is deploy/stealth-ipkey-map.conf, written by the installers. EXISTING hosts: the zones file already exists with $binary_remote_addr (the installers only print a [todo]); edit
       conf.d/stealth-base-zones.conf (and stealth-rh-zones.conf) to $st_ipkey, make sure `map $remote_addr $st_ipkey` is defined once, nginx -t, reload.
  I-1  limit_conn on /announcements, limit_req + limit_conn on the pages locations (pages burst 300: the client downloads missing pages with 6 workers and fails on 429; raise the burst before the history passes 300 pages).
  I-2  STEALTH_KNOWN_SAFE=0 loopback check parses the URL (urlparse hostname) instead of a regex.
  I-3  `verified` = our StealthPay announced it AND the receipt was parsed AND, for a token row, a Transfer to the stealth address of exactly the announced amount was found in it (paid > 0). payETH rows (selector 0xeeeeeeee):
       logs do not show native ETH, the contract itself guarantees the amount (the call to the stealth address succeeded, msg.value is announced), so a parsed receipt is enough (paid = 0). Token rows with paid = 0, unknown selectors
       and foreign callers are unverified. Rows verified earlier that no longer qualify flip to 0: run  --backfill-paid  once after deploy so the history pages (and their manifest version) are rewritten.
  I-4  moot: the skew default is gone; the mode everywhere is MODE (STEALTH_HEAD_MODE override).
  I-5  --rewind bumps epoch.
  DEPLOY ORDER  (1) on the host: edit the nginx zones to $st_ipkey (above), nginx -t; (2) stop the indexer, deploy stealth_indexer.py (the DB needs no migration; meta head_hash appears after the first step), start it, watch the log
       for "index error" lines: "no 2 endpoints agree" means the two providers really differ; (3) --backfill-paid once; (4) RH: nothing to configure (one endpoint = stated trust); add a second URL when one exists;
       (5) Base: STEALTH_RPC must hold TWO independent providers (dRPC + publicnode), as in base.env.example.

Audit 1167/1169 (indexer fork recovery, relayer lock and wedge)
  find_common  The parentHash of block a = head_done+1 differs from the stored hash of head_done (backend switch or reorg). With >= 2 endpoints the mismatch must be confirmed by a SECOND endpoint of the agreed set
         (its parentHash for block a must also differ); one endpoint saying so alone -> "endpoints disagree on the parentHash ...: waiting", nothing is rolled back or deleted (audit 1169 M-1). Confirmed ->
         find_common first re-checks that the stored hash of head_done is not still agreed (then nothing to roll back: wait), and otherwise walks back through the bh table (stored block hashes, BH_KEEP blocks):
         REORG_WIN (100) blocks, then 200, 400, ... (never below START-1), until a stored hash equals the hash the endpoints agree on now. Rows above that block are deleted when it is deeper than the reconcile window
         (REORG_WIN), epoch is bumped, and the indexer re-reads from there (INSERT OR IGNORE).
  ALERT + --rewind N  No stored hash matches (a database older than bh, or a divergence deeper than BH_KEEP): "ALERT no stored block hash matches the chain" (at most once per STEALTH_WAIT_ALERT_S), the indexer keeps
         waiting and head_done does not move. Operator: stop the service, run  stealth_indexer.py --rewind N  with N large enough to reach below the divergence (it bumps epoch), start the service.
  STEALTH_RELAY_SOLE_KEY  Default off (unset / anything but 1). Off: unwedge never cancels (self-transfer over) a pool transaction at the stuck nonce that is not one of OUR records, and never treats our own record as gone
         without the double probe; it logs "ALERT wedged nonce ... not in our records". Why: on Base this key is shared with an older relayer, so an unknown transaction at that nonce may be THEIRS; cancelling it would
         destroy a payment. Set 1 only when this process is the only user of the relayer key: then an unknown transaction, or our record proven gone (allGone, two probes), is replaced by a 0-value self-transfer.
  Old lock files (pid only)  alive only if argv[0] is node and the first argument that does not start with "-" is exactly the relayer script. Node flags with a SEPARATE value (--require x) are not supported: use --flag=value.
         1171 I-3: also judged stale (a new relayer then takes the lock, and two relayers on one key collide on the nonce): a relative script path, a wrapper (env, npx, sh -c), and `node --require x script`.
         Stop the old relayer BEFORE starting the new one. When an old pid-only lock is judged stale the relayer logs one line "old pid-only lock of pid N judged stale: ...".
  RPC independence  STEALTH_RPC with two URLs must be two independent providers (different backends); the indexer warns at start when two URLs share a host (see base.env.example).

Known-gate lag on Robinhood (02.11.2026): /known trusts a row once it is STEALTH_KNOWN_LAG_S (default 120) seconds behind the indexed head (meta key known_block); the node's safe tag moves in L1-batch jumps and lagged 10-15 min, which made a fresh payment unwithdrawable (relayer: "not a stealth address paid through Stealth"). safe_block and final_block (history pages) still follow the safe tag. Base is unchanged (known_block = safe_block). Bounded risk: a reorg deeper than the lag costs relayer gas (daily budget); the transfer from an empty address reverts, no funds leave.
