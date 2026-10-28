#!/usr/bin/env bash
# Install the Robinhood Chain stealth stack (indexer :3883, relayer :3884, watchdog, sanctions refresh) on the app server.
# DEFAULT = DRY RUN: prints every action and runs only read-only checks. Pass --apply (as root) to execute.
# Idempotent: every step checks current state and skips when already done. It NEVER stops, restarts, disables or rewrites the Base
# units (stealth-indexer.service, stealth-relayer.service on 3873/3874) and refuses any systemctl action on a name not in RH_UNITS.
# It never generates, prints or copies secrets: you create /opt/stealth/rh.env yourself from server/deploy/rh.env.example.
# Usage:  ops/install_rh.sh [--apply] [--src <repo>/server] [--no-start]
set -euo pipefail
APPLY=0; START=1; SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../server" && pwd)"
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --no-start) START=0;; --src) SRC="$2"; shift;; -h|--help) sed -n 2,9p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
OPT=/opt/stealth; D="$SRC/deploy"; ENVF=$OPT/rh.env
RH_UNITS="stealth-indexer-rh.service stealth-relayer-rh.service stealth-watch.service stealth-watch.timer stealth-sanctions.service stealth-sanctions.timer"
BASE_UNITS="stealth-indexer.service stealth-relayer.service"
say() { printf '%s %s\n' "$([ $APPLY = 1 ] && echo '[do] ' || echo '[dry]')" "$*"; }
ok()  { printf '[ok]  %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() { say "$*"; [ $APPLY = 1 ] && "$@" || true; }
guard_unit() { local b; for b in $BASE_UNITS; do [ "$1" = "$b" ] && die "refusing to touch Base unit $b"; done; case " $RH_UNITS " in *" $1 "*) ;; *) die "unit $1 not in RH_UNITS";; esac; }
soft() { if [ $APPLY = 1 ]; then die "$*"; else echo "[warn] (dry run continues) $*"; fi; }
need() { command -v "$1" >/dev/null || soft "missing command: $1"; }
[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die "--apply needs root"
for c in node python3 nginx systemctl install diff; do need $c; done
[ -d "$D" ] || die "no deploy dir $D"
echo "mode: $([ $APPLY = 1 ] && echo APPLY || echo 'DRY RUN (nothing is changed)'); source: $SRC"

# 1. preconditions (read-only)
node -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' || soft "node >= 18 required"
[ -d $OPT ] || soft "$OPT missing (Base stack not installed here?)"
[ -e $OPT/node_modules ] || soft "$OPT/node_modules missing: viem must be installed (npm i in $OPT)"
for u in $BASE_UNITS; do systemctl is-active --quiet $u && ok "Base unit $u active (left untouched)" || echo "[warn] Base unit $u not active"; done
if [ -f $ENVF ]; then
  ok "$ENVF exists"
  [ "$(stat -c %a $ENVF 2>/dev/null || stat -f %Lp $ENVF)" = 600 ] || echo "[warn] $ENVF mode is not 600"
  grep -q '<' $ENVF && soft "$ENVF still contains <placeholders>"
  grep -Eq '^STEALTHPAY=0x[0-9a-fA-F]{40}$' $ENVF || soft "STEALTHPAY not set to an address in $ENVF"
  grep -Eq '^RELAYER_KEY=0x[0-9a-fA-F]{64}$' $ENVF || soft "RELAYER_KEY missing/invalid in $ENVF (value not shown)"
  grep -Eq '^STEALTH_CHAIN=rh$' $ENVF || soft "STEALTH_CHAIN=rh missing in $ENVF"
  grep -Eq '^STEALTH_ENV_ONLY=1$' $ENVF || soft "STEALTH_ENV_ONLY=1 missing (would fall back to the Base key)"
else
  [ $APPLY = 1 ] && die "$ENVF missing: create it from $D/rh.env.example (chmod 600, owner stealth) first"
  echo "[warn] $ENVF missing: a real run stops here until you create it from $D/rh.env.example"
fi

# 2. user and directories
if id stealth >/dev/null 2>&1; then ok "user stealth"; else run useradd --system --home $OPT --shell /usr/sbin/nologin stealth; fi
for d in $OPT/data-rh $OPT/data-watch; do [ -d $d ] && ok "dir $d" || run install -d -o stealth -g stealth -m 750 $d; done
[ -d $OPT/sanctions ] && ok "dir $OPT/sanctions" || run install -d -o stealth -g stealth -m 755 $OPT/sanctions

# 3. code (shared files: Base units pick up new code only at THEIR next restart, which this script never triggers)
sync_file() { # src dst mode owner
  if [ -f "$2" ] && cmp -s "$1" "$2"; then ok "up to date $2"; else
    [ -f "$2" ] && say "update $2 (diff follows)" && { diff -u "$2" "$1" | head -20 || true; }
    run install -m "$3" -o "$4" -g "$4" "$1" "$2"; fi; }
for f in relayer.mjs chains.json stealth_indexer.py stealth_watch.py erc5564_ref.py; do [ -f "$SRC/$f" ] && sync_file "$SRC/$f" $OPT/$f 644 root; done
sync_file "$SRC/sanctions/screen.mjs" $OPT/sanctions/screen.mjs 644 root
sync_file "$SRC/sanctions/update.py"  $OPT/sanctions/update.py  755 root
# evm.json: never overwrite a newer list with the repo copy
if [ -f $OPT/sanctions/evm.json ]; then ok "evm.json present (kept; refreshed by stealth-sanctions.timer)"; else run install -m 644 -o stealth -g stealth "$SRC/sanctions/evm.json" $OPT/sanctions/evm.json; fi

# 4. systemd units
CH=0
for f in stealth-indexer-rh.service stealth-relayer-rh.service stealth-watch.service stealth-watch.timer stealth-sanctions.service stealth-sanctions.timer; do
  guard_unit $f
  if [ -f /etc/systemd/system/$f ] && cmp -s "$D/$f" /etc/systemd/system/$f; then ok "unit $f"; else run install -m 644 "$D/$f" /etc/systemd/system/$f; CH=1; fi
done
[ $CH = 1 ] && run systemctl daemon-reload
if [ -f $OPT/watch.env ]; then ok "watch.env present"; else echo "[warn] $OPT/watch.env missing: create from $D/watch.env.example (watchdog will run without Telegram)"; fi

# 5. nginx (zones, snippet, include check, nginx -t; reload only after a passing test)
ZONES=/etc/nginx/conf.d/stealth-rh-zones.conf; SNIP=/etc/nginx/snippets/stealth-rh.conf
if nginx -T 2>/dev/null | grep -q 'zone=st_rh_read'; then ok "nginx zones st_rh_* already defined"; else
  say "write $ZONES (limit_req/limit_conn zones + st_tail cache path)"
  if [ $APPLY = 1 ]; then
    grep -rq 'keys_zone=st_tail' /etc/nginx 2>/dev/null && TAIL="" || TAIL='proxy_cache_path /var/cache/nginx/stealth_tail levels=1 keys_zone=st_tail:2m max_size=64m inactive=1m use_temp_path=off;'
    install -d /var/cache/nginx
    printf '%s\n' 'limit_req_zone $binary_remote_addr zone=st_rh_read:10m rate=10r/s;' 'limit_req_zone $binary_remote_addr zone=st_rh_post:10m rate=10r/m;' 'limit_conn_zone $binary_remote_addr zone=st_rh_conn:10m;' "$TAIL" > $ZONES
  fi
fi
if [ -f $SNIP ] && cmp -s "$D/stealth-rh.conf" $SNIP; then ok "snippet $SNIP"; else run install -D -m 644 "$D/stealth-rh.conf" $SNIP; fi
if grep -rqs 'snippets/stealth-rh.conf' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null; then ok "snippet is included"; else
  echo "[todo] add this line INSIDE the server{} of app.deepyield.ai (file in sites-enabled; if it is a symlink, edit the target):"
  echo "         include /etc/nginx/snippets/stealth-rh.conf;"
  echo "       limit_req_status 429; must exist once at http level. Re-run this script afterwards."; fi
if [ $APPLY = 1 ]; then nginx -t && ok "nginx -t" || die "nginx -t failed: NOT reloading"; else say "nginx -t (then reload only if it passes)"; fi

# 6. start RH units only
if [ $START = 1 ]; then
  for u in stealth-indexer-rh.service stealth-relayer-rh.service stealth-watch.timer stealth-sanctions.timer; do
    guard_unit $u
    systemctl is-active --quiet $u && ok "$u already active" || run systemctl enable --now $u
  done
  if systemctl is-active --quiet stealth-relayer-rh.service 2>/dev/null && [ $CH = 1 ]; then say "restart stealth-relayer-rh.service picks up new code/env"; [ $APPLY = 1 ] && systemctl restart stealth-relayer-rh.service; fi
  [ $APPLY = 1 ] && nginx -t 2>/dev/null && systemctl reload nginx && ok "nginx reloaded"
fi

# 7. smoke tests (real run only)
if [ $APPLY = 1 ]; then
  sleep 3; H=http://127.0.0.1
  curl -fsS $H:3883/stealth-api/head >/dev/null && ok "indexer /head" || echo "[warn] indexer /head failed (still syncing?)"
  curl -fsS $H:3884/stealth-api/relay/stats | head -c 300; echo
  curl -fsS "$H:3884/stealth-api/relay/screen?addr=0x0000000000000000000000000000000000000001" && echo
else
  say "smoke: curl :3883/stealth-api/head, :3884/stealth-api/relay/stats, :3884/stealth-api/relay/screen?addr=..., https://app.deepyield.ai/stealth-api/rh/pages/manifest.json"
fi
echo "done ($([ $APPLY = 1 ] && echo applied || echo 'dry run, nothing changed'))"
