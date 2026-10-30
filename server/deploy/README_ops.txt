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
  STEALTH_RELAY_ALLOW_KEYS=195.201.164.56        (comma-separated IPv4 addresses or IPv6 addresses/ /64 keys; put it in rh.env / relayer.env on the host only)
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
       (the first STEALTH_RPC entry); it moves to the next entry only on a transport failure (5xx, timeout, connection, 429) and the switch is logged ("rpc endpoint switched"). Balances, gas and fee
       estimates keep the failover transport. A gap fill needs two pending-count reads STEALTH_RELAY_GONE_GAP_MS apart that agree. Restart: the persisted unsure records (written before every send, with
       the nonce) refill nonceOfHash and lift the starting local nonce for sends younger than STEALTH_RELAY_GAP_GRACE_MS; nothing new is persisted.
  F4 residual (documented): provenGone() can still be wrong if a node lies consistently for >= 2 probes. A false "gone" makes the relayer sign a second transaction for the same authorization; because the
       on-chain authorization is one-use, only one of the two can succeed and the other reverts: the cost is the reverted transaction's gas (bounded by the daily gas budget), NEVER funds.
  F6  FIXED: sendAndTrack receives the caller's d0 (the day the reservation was credited under) instead of recapturing st.day.
  I2  FIXED: a variable that is present but empty in the own environment is no longer refilled from the foreign env file.
  I1  Partly covered: test_fork_e2e.mjs now exercises the sticky endpoint with a dead first RPC and a lagging pending read; a full two-backend divergence harness is not built.
  I3  ACCEPTED: a malformed numeric field (BigInt SyntaxError) is thrown before any state-dependent step and answered 400 from the generic handler; it is charged to the network key as junk (ctx.signer unset). The message only echoes the caller's own input.
