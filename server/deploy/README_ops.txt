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
