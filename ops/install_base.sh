#!/usr/bin/env bash
# Install the Base stealth stack for StealthPay v3 (indexer :3893, relayer :3894, nginx path /stealth-api/base/) next to the live Base v2 stack.
# DEFAULT = DRY RUN: prints every action and runs only read-only checks. Pass --apply (as root) to execute.
# Idempotent: every step checks current state and skips when already done. Everything new lives in /opt/stealth-base and in units/snippets with "base" in the name.
# It NEVER stops, restarts, disables, reloads or rewrites the live Base units (stealth-indexer.service, stealth-relayer.service on 3873/3874, code in /opt/stealth), the RH units
# (stealth-*-rh.service, /opt/stealth-rh) or any other product's unit, and refuses a systemctl action or a write outside its own paths. It never edits /opt/mprhedged/exec/.env
# and never writes, copies or prints a secret: you create /opt/stealth-base/base.env yourself (README_ops.txt, "Base v3"); the script only checks it and compares the key line with the
# live relayer's file (yes/no, never the value). Every file it replaces is first copied to /var/backups/stealth-base/<time>/. nginx -t runs before every reload; a failing test restores the backup.
# Usage:  ops/install_base.sh [--apply] [--src <repo>/server] [--no-start] [--add-include]
#   --add-include  (with --apply) inserts `include /etc/nginx/snippets/stealth-base.conf;` into the app.deepyield.ai vhost right after the RH include (backup first, nginx -t, restore on failure)
set -euo pipefail
APPLY=0; START=1; INCLUDE=0; SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../server" && pwd)"
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --no-start) START=0;; --add-include) INCLUDE=1;; --src) SRC="$2"; shift;; -h|--help) sed -n 2,12p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
OPT=/opt/stealth-base; DATA=$OPT/data; D="$SRC/deploy"; ENVF=$OPT/base.env
OLDKEY=/opt/stealth/relayer.env                      # the live Base relayer's key file: read by the operator's one-liner, only compared (never shown) here
VHOST=/etc/nginx/sites-enabled/app-deepyield; RH_SNIP=/etc/nginx/snippets/stealth-rh.conf
NEW_UNITS="stealth-indexer-base.service stealth-relayer-base.service"
OLD_UNITS="stealth-indexer.service stealth-relayer.service stealth-indexer-rh.service stealth-relayer-rh.service stealth-watch.service stealth-watch.timer stealth-sanctions.service stealth-sanctions.timer"
SP3=0xC07f54984AbDa1EF76DaB6F602270B76a04E916d; SP2=0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76
IDX_PORT=3893; REL_PORT=3894
TS="$(date -u +%Y%m%d-%H%M%S)"; BK=/var/backups/stealth-base/$TS
say() { printf '%s %s\n' "$([ $APPLY = 1 ] && echo '[do] ' || echo '[dry]')" "$*"; }
ok()  { printf '[ok]  %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() { say "$*"; [ $APPLY = 1 ] && "$@" || true; }
soft() { if [ $APPLY = 1 ]; then die "$*"; else echo "[warn] (dry run continues) $*"; fi; }
need() { command -v "$1" >/dev/null || soft "missing command: $1"; }
guard_unit() { local b; for b in $OLD_UNITS; do [ "$1" = "$b" ] && die "refusing to touch live unit $b"; done; case " $NEW_UNITS " in *" $1 "*) ;; *) die "unit $1 is not one of: $NEW_UNITS";; esac; }
guard_path() { case "$1" in $OPT/*|/etc/systemd/system/stealth-indexer-base.service|/etc/systemd/system/stealth-relayer-base.service|/etc/nginx/snippets/stealth-base.conf|/etc/nginx/conf.d/stealth-base-zones.conf|$VHOST) ;; *) die "refusing to write $1 (outside the Base v3 paths)";; esac; }
backup() { # file: copy an existing file to the backup dir before it is replaced
  [ -f "$1" ] || return 0; say "backup $1 -> $BK$1"; [ $APPLY = 1 ] && { mkdir -p "$BK$(dirname "$1")" && cp -p "$1" "$BK$1"; } || true; }
put() { # src dst mode owner : install with guard and backup
  guard_path "$2"; backup "$2"; run install -D -m "$3" -o "$4" -g "$4" "$1" "$2"; }
sync_file() { # src dst mode owner
  if [ -f "$2" ] && cmp -s "$1" "$2"; then ok "up to date $2"; else
    [ -f "$2" ] && say "update $2 (diff follows)" && { diff -u "$2" "$1" | head -20 || true; }
    put "$1" "$2" "$3" "$4"; CODE_CH=1; fi; }
keyline() { grep -m1 '^RELAYER_KEY=' "$1" 2>/dev/null || true; }     # only ever piped into cmp / grep -q, never printed
[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die "--apply needs root"
for c in node python3 nginx systemctl install diff cmp curl; do need $c; done
[ -d "$D" ] || die "no deploy dir $D"
for f in base.env.example stealth-indexer-base.service stealth-relayer-base.service stealth-base.conf; do [ -f "$D/$f" ] || die "missing $D/$f"; done
echo "mode: $([ $APPLY = 1 ] && echo APPLY || echo 'DRY RUN (nothing is changed)'); source: $SRC; backups: $BK"

# 1. preconditions (read-only)
node -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' || soft "node >= 18 required"
id stealth >/dev/null 2>&1 && ok "user stealth" || soft "user stealth missing (the RH stack created it; the Base v3 units run as stealth)"
for u in stealth-indexer.service stealth-relayer.service; do systemctl is-active --quiet $u && ok "live Base unit $u active (left untouched)" || echo "[warn] live Base unit $u not active"; done
for p in $IDX_PORT $REL_PORT; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p$"; then
    systemctl is-active --quiet $([ $p = $IDX_PORT ] && echo stealth-indexer-base || echo stealth-relayer-base) && ok "port $p is ours" || soft "port $p is already in use by something else"
  else ok "port $p free"; fi
done
grep -q '"base"' "$SRC/chains.json" || die "no base entry in $SRC/chains.json"
[ -f "$SRC/relay-util.mjs" ] || die "no $SRC/relay-util.mjs (relayer.mjs imports it)"
[ -f "$OLDKEY" ] && ok "key source $OLDKEY exists (root only; read by the operator's one-liner)" || echo "[warn] $OLDKEY missing: base.env needs another RELAYER_KEY source"
NM=""; for n in /opt/stealth-rh/node_modules /opt/stealth/node_modules; do [ -e "$n" ] && { NM="$(readlink -f "$n")"; break; }; done
[ -e $OPT/node_modules ] || { [ -n "$NM" ] && ok "node_modules will link to $NM (viem, as for RH)" || soft "no node_modules to link (viem must be installed)"; }

# 2. directories and the symlink
[ -d $OPT ] && ok "dir $OPT" || run install -d -m 755 $OPT
[ -d $DATA ] && ok "dir $DATA" || run install -d -o stealth -g stealth -m 755 $DATA     # 755: nginx (www-data) reads $DATA/pages
[ -e $OPT/node_modules ] || { [ -n "$NM" ] && run ln -s "$NM" $OPT/node_modules; }
[ -d $OPT/sanctions ] && ok "dir $OPT/sanctions" || run install -d -m 755 $OPT/sanctions

# 3. code (a private copy: the live Base code in /opt/stealth and the RH copy are never overwritten)
CODE_CH=0
for f in relayer.mjs relay-util.mjs chains.json stealth_indexer.py; do sync_file "$SRC/$f" $OPT/$f 644 root; done
sync_file "$SRC/sanctions/screen.mjs" $OPT/sanctions/screen.mjs 644 root
sync_file "$SRC/sanctions/update.py"  $OPT/sanctions/update.py  755 root
if [ -f $OPT/sanctions/evm.json ]; then ok "evm.json present (kept)"; else guard_path $OPT/sanctions/evm.json; run install -m 644 -o stealth -g stealth "$SRC/sanctions/evm.json" $OPT/sanctions/evm.json; fi
sync_file "$D/base.env.example" $OPT/base.env.example 644 root

# 4. env file (checked, never printed, never created here)
ENV_OK=0
if [ -f $ENVF ]; then
  ok "$ENVF exists"; ENV_OK=1
  [ "$(stat -c %a $ENVF)" = 600 ] || { echo "[warn] $ENVF mode is not 600"; ENV_OK=0; }
  [ "$(stat -c %U $ENVF)" = stealth ] || { echo "[warn] $ENVF owner is not stealth (the units run as stealth and could not read it)"; ENV_OK=0; }
  grep -q '<' $ENVF && { echo "[warn] $ENVF still contains <placeholders>"; ENV_OK=0; }
  grep -Eq '^STEALTH_CHAIN=base$' $ENVF || { echo "[warn] STEALTH_CHAIN=base missing"; ENV_OK=0; }
  grep -Eq '^STEALTH_ENV_ONLY=1$' $ENVF || { echo "[warn] STEALTH_ENV_ONLY=1 missing"; ENV_OK=0; }
  grep -Eiq "^STEALTHPAY=0x[0-9a-fA-F]{40}\$" $ENVF || die "STEALTHPAY missing/not an address in $ENVF (audit 1158 F-2: the indexer refuses to start without it)"   # die even in a dry run
  grep -Eiq "^STEALTHPAY=$SP3\$" $ENVF || { echo "[warn] STEALTHPAY is not the v3 address $SP3"; ENV_OK=0; }
  grep -Eiq "^STEALTHPAY_LEGACY=.*$SP2" $ENVF || { echo "[warn] STEALTHPAY_LEGACY does not list v2 $SP2 (v2 payments would not be withdrawable)"; ENV_OK=0; }
  grep -Eq "^STEALTH_PORT=$IDX_PORT\$" $ENVF && grep -Eq "^STEALTH_RELAY_PORT=$REL_PORT\$" $ENVF && grep -Eq "^STEALTH_INDEXER=http://127.0.0.1:$IDX_PORT\$" $ENVF || { echo "[warn] ports in $ENVF are not $IDX_PORT/$REL_PORT"; ENV_OK=0; }
  grep -Eq '^STEALTH_START_BLOCK=31700000$' $ENVF || { echo "[warn] STEALTH_START_BLOCK is not 31700000 (v2-era history would be missing)"; ENV_OK=0; }
  grep -Eq '^RELAYER_KEY=0x[0-9a-fA-F]{64}$' $ENVF || { echo "[warn] RELAYER_KEY missing/invalid (value not shown)"; ENV_OK=0; }
  if [ -f $OLDKEY ] && [ -n "$(keyline $OLDKEY)" ]; then
    cmp -s <(keyline $OLDKEY) <(keyline $ENVF) && echo "[info] RELAYER_KEY equals the live Base relayer's key: both relayers share one account and nonce (see README_ops.txt, Risks)" || echo "[info] RELAYER_KEY differs from the live Base relayer's key (fund its address with ETH on Base)"
  fi
  [ $ENV_OK = 1 ] || soft "$ENVF is not ready (see warnings above)"
else
  soft "$ENVF missing: create it with the root-only one-liner in server/deploy/README_ops.txt (section Base v3), then re-run"
fi

# 5. systemd units (new names only)
CH=0
for f in $NEW_UNITS; do
  guard_unit $f; guard_path /etc/systemd/system/$f
  if [ -f /etc/systemd/system/$f ] && cmp -s "$D/$f" /etc/systemd/system/$f; then ok "unit $f"; else backup /etc/systemd/system/$f; run install -m 644 "$D/$f" /etc/systemd/system/$f; CH=1; fi
done
[ $CH = 1 ] && run systemctl daemon-reload

# 6. nginx: own zones, snippet, include; reload only after a passing nginx -t, restore on failure
ZONES=/etc/nginx/conf.d/stealth-base-zones.conf; SNIP=/etc/nginx/snippets/stealth-base.conf
NGX_CH=0
if nginx -T 2>/dev/null | grep -q 'zone=st_bip_read'; then ok "nginx zones st_bip_* already defined"
  nginx -T 2>/dev/null | grep 'zone=st_bip_' | grep -q 'binary_remote_addr' && echo "[todo] the st_bip_* zones still key on \$binary_remote_addr: switch them to \$st_ipkey (map: $D/stealth-ipkey-map.conf; README_ops.txt, audit 1165 L-2)"
else
  say "write $ZONES (limit_req/limit_conn zones st_bip_*; the st_tail cache path comes from the RH zones file)"
  if [ $APPLY = 1 ]; then
    grep -rq 'keys_zone=st_tail' /etc/nginx 2>/dev/null && TAIL="" || TAIL='proxy_cache_path /var/cache/nginx/stealth_tail levels=1 keys_zone=st_tail:2m max_size=64m inactive=1m use_temp_path=off;'
    install -d /var/cache/nginx; guard_path $ZONES; backup $ZONES
    nginx -T 2>/dev/null | grep -q 'map $remote_addr $st_ipkey' && MAP="" || MAP="$(cat "$D/stealth-ipkey-map.conf")"       # audit 1165 L-2: one IPv6 /64 = one client; the map is defined once per host (the RH installer writes the same one)
    printf '%s\n' "$MAP" 'limit_req_zone $st_ipkey zone=st_bip_read:10m rate=10r/s;' 'limit_req_zone $st_ipkey zone=st_bip_post:10m rate=10r/m;' 'limit_conn_zone $st_ipkey zone=st_bip_conn:10m;' "$TAIL" > $ZONES
  fi
  NGX_CH=1
fi
if [ -f $SNIP ] && cmp -s "$D/stealth-base.conf" $SNIP; then ok "snippet $SNIP"; else put "$D/stealth-base.conf" $SNIP 644 root; NGX_CH=1; fi
INC='include /etc/nginx/snippets/stealth-base.conf;'
if grep -rqs 'snippets/stealth-base.conf' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null; then ok "snippet is included"; elif [ $INCLUDE = 1 ]; then
  [ -f "$VHOST" ] && [ ! -L "$VHOST" ] || soft "$VHOST is missing or a symlink: add the include by hand"
  grep -q "snippets/stealth-rh.conf" "$VHOST" 2>/dev/null || soft "no RH include line in $VHOST to anchor on: add the include by hand"
  say "insert '$INC' after the RH include in $VHOST"
  if [ $APPLY = 1 ]; then
    guard_path $VHOST; backup $VHOST; T="$(mktemp)"
    awk -v inc="    $INC" '{print} /include \/etc\/nginx\/snippets\/stealth-rh.conf;/ && !d {print inc; d=1}' "$VHOST" > "$T" && cat "$T" > "$VHOST"; rm -f "$T"; NGX_CH=1
  fi
else
  echo "[todo] add this line INSIDE the server{} of app.deepyield.ai, right after the RH include (or re-run with --add-include):"
  echo "         $INC"
fi
if [ $APPLY = 1 ]; then
  if nginx -t >/dev/null 2>&1; then ok "nginx -t"; else
    nginx -t 2>&1 | tail -5
    [ -f "$BK$VHOST" ] && cat "$BK$VHOST" > "$VHOST" && echo "[undo] restored $VHOST from $BK"
    for z in "$SNIP" "$ZONES"; do if [ -f "$BK$z" ]; then cat "$BK$z" > "$z"; else rm -f "$z"; fi; done
    die "nginx -t failed: restored the backup, NOT reloading"
  fi
else say "nginx -t (then reload only if it passes; restore the backup if not)"; fi

# 7. start the two new units only; nginx reload only if this run changed nginx files
if [ $START = 1 ]; then
  for u in $NEW_UNITS; do
    guard_unit $u
    if systemctl is-active --quiet $u; then
      if [ $CH = 1 ] || [ $CODE_CH = 1 ]; then say "restart $u (new code/unit)"; [ $APPLY = 1 ] && systemctl restart $u; else ok "$u already active"; fi
    else run systemctl enable --now $u; fi
  done
fi
if [ $NGX_CH = 1 ]; then say "systemctl reload nginx (after the passing nginx -t)"; [ $APPLY = 1 ] && nginx -t >/dev/null 2>&1 && systemctl reload nginx && ok "nginx reloaded"; fi

# 8. smoke tests (real run only)
if [ $APPLY = 1 ] && [ $START = 1 ]; then
  sleep 4; H=http://127.0.0.1
  curl -fsS $H:$IDX_PORT/stealth-api/head && echo || echo "[warn] indexer /head failed (still starting?)"
  curl -fsS $H:$REL_PORT/stealth-api/relay/stats | head -c 400; echo
  curl -fsS "$H:$REL_PORT/stealth-api/relay/screen?addr=0x0000000000000000000000000000000000000001" && echo
  curl -fsSk -H 'Host: app.deepyield.ai' https://127.0.0.1/stealth-api/base/head >/dev/null && ok "nginx path /stealth-api/base/head" || echo "[warn] /stealth-api/base/head not reachable through nginx (include added? reloaded?)"
else
  say "smoke: curl :$IDX_PORT/stealth-api/head (chain base, start 31700000), :$REL_PORT/stealth-api/relay/stats (stealthpay = v3), :$REL_PORT/stealth-api/relay/screen?addr=..., https://app.deepyield.ai/stealth-api/base/head, .../pages/manifest.json"
fi
echo "done ($([ $APPLY = 1 ] && echo applied || echo 'dry run, nothing changed'))"
