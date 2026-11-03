#!/usr/bin/env bash
# Install the Robinhood Chain stealth stack (indexer :3883, relayer :3884) into /opt/stealth: a LEGACY layout. The watchdog and the OFAC refresh timers are installed by ops/install_watch.sh.
# On the production host the live RH stack lives in /opt/stealth-rh (rh.env, data in /opt/stealth-rh/data) and /opt/stealth is the live Base code: --apply therefore REFUSES when /opt/stealth-rh exists (audit 1179 F2).
# DEFAULT = DRY RUN: prints every action and runs only read-only checks. Pass --apply (as root) to execute.
# Idempotent: every step checks current state and skips when already done. It NEVER stops, restarts, disables or rewrites the Base
# units (stealth-indexer.service, stealth-relayer.service on 3873/3874) and refuses any systemctl action on a name not in RH_UNITS.
# It never generates, prints or copies secrets: you create /opt/stealth/rh.env yourself from server/deploy/rh.env.example.
# Usage:  ops/install_rh.sh [--apply] [--src <repo>/server] [--no-start]
set -euo pipefail
APPLY=0; START=1; SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../server" && pwd)"
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --no-start) START=0;; --src) SRC="$2"; shift;; -h|--help) sed -n 2,9p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
OPT=/opt/stealth; D="$SRC/deploy"; ENVF=$OPT/rh.env
NGX="${STEALTH_NGINX_DIR:-/etc/nginx}"; NGX_CACHE="${STEALTH_NGINX_CACHE:-/var/cache/nginx}"      # overrides for the offline test only
TS="$(date -u +%Y%m%d-%H%M%S)"; BK="${STEALTH_BACKUP_DIR:-/var/backups/stealth-rh}/$TS"
RH_UNITS="stealth-indexer-rh.service stealth-relayer-rh.service"
BASE_UNITS="stealth-indexer.service stealth-relayer.service"
say() { printf '%s %s\n' "$([ $APPLY = 1 ] && echo '[do] ' || echo '[dry]')" "$*"; }
ok()  { printf '[ok]  %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() { say "$*"; if [ $APPLY = 1 ]; then "$@"; fi; }      # audit 1180 L-2: a failing command under --apply stops the script (set -e)
guard_unit() { local b; for b in $BASE_UNITS; do [ "$1" = "$b" ] && die "refusing to touch Base unit $b"; done; case " $RH_UNITS " in *" $1 "*) ;; *) die "unit $1 not in RH_UNITS";; esac; }
soft() { if [ $APPLY = 1 ]; then die "$*"; else echo "[warn] (dry run continues) $*"; fi; }
need() { command -v "$1" >/dev/null || soft "missing command: $1"; }
[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die "--apply needs root"
if [ -d /opt/stealth-rh ]; then
  if [ $APPLY = 1 ]; then die "/opt/stealth-rh exists: the live RH stack is there, and this script writes to $OPT (the live Base code). Refusing. Update RH by hand from server/deploy; the watchdog and sanctions timers: ops/install_watch.sh"; fi
  echo "[warn] /opt/stealth-rh exists: --apply would refuse (this script targets the legacy $OPT layout)"
fi
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
  grep -Eq '^STEALTHPAY=0x[0-9a-fA-F]{40}$' $ENVF || die "STEALTHPAY not set to an address in $ENVF (audit 1158 F-2: the indexer refuses to start without it, and without the caller filter /known would accept any announcement)"   # die even in a dry run
  grep -Eq '^RELAYER_KEY=0x[0-9a-fA-F]{64}$' $ENVF || soft "RELAYER_KEY missing/invalid in $ENVF (value not shown)"
  grep -Eq '^STEALTH_CHAIN=rh$' $ENVF || soft "STEALTH_CHAIN=rh missing in $ENVF"
  grep -Eq '^STEALTH_ENV_ONLY=1$' $ENVF || soft "STEALTH_ENV_ONLY=1 missing (would fall back to the Base key)"
else
  [ $APPLY = 1 ] && die "$ENVF missing: create it from $D/rh.env.example (chmod 600, owner stealth) first"
  echo "[warn] $ENVF missing: a real run stops here until you create it from $D/rh.env.example"
fi

# 2. user and directories
if id stealth >/dev/null 2>&1; then ok "user stealth"; else run useradd --system --home $OPT --shell /usr/sbin/nologin stealth; fi
for d in $OPT/data-rh; do [ -d $d ] && ok "dir $d" || run install -d -o stealth -g stealth -m 750 $d; done
[ -d $OPT/sanctions ] && ok "dir $OPT/sanctions" || run install -d -o stealth -g stealth -m 755 $OPT/sanctions

# 3. code (shared files: Base units pick up new code only at THEIR next restart, which this script never triggers)
sync_file() { # src dst mode owner
  if [ -f "$2" ] && cmp -s "$1" "$2"; then ok "up to date $2"; else
    [ -f "$2" ] && say "update $2 (diff follows)" && { diff -u "$2" "$1" | head -20 || true; }
    run install -m "$3" -o "$4" -g "$4" "$1" "$2"; fi; }
for f in relayer.mjs chains.json stealth_indexer.py erc5564_ref.py; do [ -f "$SRC/$f" ] && sync_file "$SRC/$f" $OPT/$f 644 root; done
sync_file "$SRC/sanctions/screen.mjs" $OPT/sanctions/screen.mjs 644 root
sync_file "$SRC/sanctions/update.py"  $OPT/sanctions/update.py  755 root
# evm.json: never overwrite a newer list with the repo copy
if [ -f $OPT/sanctions/evm.json ]; then ok "evm.json present (kept; refreshed by stealth-sanctions@rh.timer, ops/install_watch.sh)"; else run install -m 644 -o stealth -g stealth "$SRC/sanctions/evm.json" $OPT/sanctions/evm.json; fi

# 4. systemd units
CH=0
for f in $RH_UNITS; do
  guard_unit $f
  if [ -f /etc/systemd/system/$f ] && cmp -s "$D/$f" /etc/systemd/system/$f; then ok "unit $f"; else run install -m 644 "$D/$f" /etc/systemd/system/$f; CH=1; fi
done
[ $CH = 1 ] && run systemctl daemon-reload

# 5. nginx (zones, snippet, include check, nginx -t; reload only after a passing test; a failure puts back what THIS run wrote, audit 1181 M-2: same scheme as install_base.sh)
backup() { [ -f "$1" ] || return 0; say "backup $1 -> $BK$1"; if [ $APPLY = 1 ]; then mkdir -p "$BK$(dirname "$1")" && cp -p "$1" "$BK$1" || true; fi; }
UNDO=(); NGX_GUARD=0
track() { # path : before writing; the real run refuses when the backup of an existing file is not there
  backup "$1"; [ $APPLY = 1 ] || return 0
  if [ -f "$1" ]; then [ -f "$BK$1" ] || die "no backup of $1 in $BK: refusing to change it"; UNDO+=("restore:$1"); else UNDO+=("remove:$1"); fi; NGX_GUARD=1; }
rollback() {
  [ "$NGX_GUARD" = 1 ] || return 0; NGX_GUARD=0
  local i e p; i=${#UNDO[@]}
  while [ $i -gt 0 ]; do i=$((i - 1)); e="${UNDO[$i]}"; p="${e#*:}"
    case "${e%%:*}" in
      restore) if cat "$BK$p" > "$p"; then echo "[undo] restored $p from $BK"; else echo "[FAIL] could not restore $p: copy $BK$p back by hand" >&2; fi;;
      remove) if rm -f "$p"; then echo "[undo] removed $p (this run created it)"; else echo "[FAIL] could not remove $p" >&2; fi;;
    esac
  done; }
trap 'rc=$?; if [ $rc != 0 ]; then rollback; fi' EXIT
ZONES=$NGX/conf.d/stealth-rh-zones.conf; SNIP=$NGX/snippets/stealth-rh.conf; NGX_CH=0
if NGXT="$(nginx -T 2>/dev/null)"; then :; else NGXT=""; soft "nginx -T failed: cannot tell which zones are defined"; fi      # the dump once, grepped as a variable (a `| grep -q` under pipefail reports "not found" when nginx dies of SIGPIPE)
cfg_without() { awk -v f="$1:" '/^# configuration file /{skip=($4==f)} !skip' <<<"$NGXT"; }      # the dump without the section of a file about to be replaced
if grep -q 'zone=st_rh_read' <<<"$NGXT"; then ok "nginx zones st_rh_* already defined"
  if grep 'zone=st_rh_' <<<"$NGXT" | grep -q 'binary_remote_addr'; then echo "[todo] the st_rh_* zones still key on \$binary_remote_addr: switch them to \$st_ipkey (map: $D/stealth-ipkey-map.conf)"; fi
else
  say "write $ZONES (limit_req/limit_conn zones + st_tail cache path)"
  if [ $APPLY = 1 ]; then
    OTHERS="$(cfg_without "$ZONES")"
    if grep -q 'keys_zone=st_tail' <<<"$OTHERS"; then TAIL=""; else TAIL='proxy_cache_path /var/cache/nginx/stealth_tail levels=1 keys_zone=st_tail:2m max_size=64m inactive=1m use_temp_path=off;'; fi
    install -d "$NGX_CACHE"
    if grep -q 'map $remote_addr $st_ipkey' <<<"$OTHERS"; then MAP=""; else MAP="$(cat "$D/stealth-ipkey-map.conf")"; fi       # the conf header calls the map REQUIRED (audit 1099 M-2); the zones below key on it
    track "$ZONES"; ZT="$(mktemp "$ZONES.XXXXXX")"
    if printf '%s\n' "$MAP" 'limit_req_zone $st_ipkey zone=st_rh_read:10m rate=10r/s;' 'limit_req_zone $st_ipkey zone=st_rh_post:10m rate=10r/m;' 'limit_conn_zone $st_ipkey zone=st_rh_conn:10m;' "$TAIL" > "$ZT" && chmod 644 "$ZT" && mv -f "$ZT" "$ZONES"; then :; else rm -f "$ZT"; die "could not write $ZONES"; fi
  fi
  NGX_CH=1
fi
if [ -f $SNIP ] && cmp -s "$D/stealth-rh.conf" $SNIP; then ok "snippet $SNIP"; else if [ $APPLY = 1 ]; then track $SNIP; else backup $SNIP; fi; run install -D -m 644 "$D/stealth-rh.conf" $SNIP; NGX_CH=1; fi
if grep -rqs 'snippets/stealth-rh.conf' $NGX/sites-enabled $NGX/conf.d 2>/dev/null; then ok "snippet is included"; else
  echo "[todo] add this line INSIDE the server{} of app.deepyield.ai (file in sites-enabled; if it is a symlink, edit the target):"
  echo "         include /etc/nginx/snippets/stealth-rh.conf;"
  echo "       limit_req_status 429; must exist once at http level. Re-run this script afterwards."; fi
if [ $APPLY = 1 ]; then
  if NGT="$(nginx -t 2>&1)"; then ok "nginx -t"; NGX_GUARD=0; else printf '%s\n' "$NGT" | tail -5 || true; die "nginx -t failed: the files this run changed are put back (see [undo] lines), NOT reloading"; fi
else say "nginx -t (then reload only if it passes)"; fi

# 6. start RH units only
if [ $START = 1 ]; then
  for u in $RH_UNITS; do
    guard_unit $u
    systemctl is-active --quiet $u && ok "$u already active" || run systemctl enable --now $u
  done
  if systemctl is-active --quiet stealth-relayer-rh.service 2>/dev/null && [ $CH = 1 ]; then say "restart stealth-relayer-rh.service picks up new code/env"; [ $APPLY = 1 ] && systemctl restart stealth-relayer-rh.service; fi
  if [ $APPLY = 1 ]; then      # audit 1181 L-7: an explicit if/else; a failing test or reload is an error, not a silent skip
    if nginx -t >/dev/null 2>&1; then if systemctl reload nginx; then ok "nginx reloaded"; else die "systemctl reload nginx failed (the config on disk passes nginx -t): check journalctl -u nginx"; fi; else die "nginx -t failed before the reload: NOT reloading"; fi
  fi
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
