#!/usr/bin/env bash
# Install the Base stealth stack for StealthPay v3 (indexer :3893, relayer :3894, nginx path /stealth-api/base/) next to the live Base v2 stack.
# DEFAULT = DRY RUN: prints every action and runs only read-only checks. Pass --apply (as root) to execute.
# Idempotent: every step checks current state and skips when already done. Everything new lives in /opt/stealth-base and in units/snippets with "base" in the name.
# It NEVER stops, restarts, disables, reloads or rewrites the live Base units (stealth-indexer.service, stealth-relayer.service on 3873/3874, code in /opt/stealth), the RH units
# (stealth-*-rh.service, /opt/stealth-rh) or any other product's unit, and refuses a systemctl action or a write outside its own paths. It never edits /opt/mprhedged/exec/.env
# and never writes, copies or prints a secret: you create /opt/stealth-base/base.env yourself (README_ops.txt, "Base v3"); the script only checks it and compares the key line with the
# live relayer's file (yes/no, never the value). Every file it replaces is first copied to /var/backups/stealth-base/<time>/. nginx -t runs before every reload; a failing test (or any failed write) of the nginx files puts back exactly the nginx files THIS run changed and deletes only the ones it created.
# Usage:  ops/install_base.sh [--apply] [--src <repo>/server] [--no-start] [--add-include]
#   --add-include  (with --apply) inserts `include /etc/nginx/snippets/stealth-base.conf;` into the app.deepyield.ai vhost right after the RH include (backup first, written whole via a temp file + mv, nginx -t, undo on failure)
set -euo pipefail
APPLY=0; START=1; INCLUDE=0; SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../server" && pwd)"
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --no-start) START=0;; --add-include) INCLUDE=1;; --src) SRC="$2"; shift;; -h|--help) sed -n 2,12p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
OPT=/opt/stealth-base; DATA=$OPT/data; D="$SRC/deploy"; ENVF=$OPT/base.env
OLDKEY=/opt/stealth/relayer.env                      # the live Base relayer's key file: read by the operator's one-liner, only compared (never shown) here
NGX="${STEALTH_NGINX_DIR:-/etc/nginx}"; NGX_CACHE="${STEALTH_NGINX_CACHE:-/var/cache/nginx}"      # the two overrides exist for the offline test (server/test_ops_install.py); production uses the defaults
VHOST=$NGX/sites-enabled/app-deepyield; RH_SNIP=$NGX/snippets/stealth-rh.conf
NEW_UNITS="stealth-indexer-base.service stealth-relayer-base.service"
OLD_UNITS="stealth-indexer.service stealth-relayer.service stealth-indexer-rh.service stealth-relayer-rh.service stealth-watch.service stealth-watch.timer stealth-sanctions.service stealth-sanctions.timer"
SP3=0xC07f54984AbDa1EF76DaB6F602270B76a04E916d; SP2=0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76
IDX_PORT=3893; REL_PORT=3894
TS="$(date -u +%Y%m%d-%H%M%S)"; BK="${STEALTH_BACKUP_DIR:-/var/backups/stealth-base}/$TS"
say() { printf '%s %s\n' "$([ $APPLY = 1 ] && echo '[do] ' || echo '[dry]')" "$*"; }
ok()  { printf '[ok]  %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() { say "$*"; if [ $APPLY = 1 ]; then "$@"; fi; }      # audit 1180 L-2: a failing command under --apply stops the script (set -e)
soft() { if [ $APPLY = 1 ]; then die "$*"; else echo "[warn] (dry run continues) $*"; fi; }
need() { command -v "$1" >/dev/null || soft "missing command: $1"; }
guard_unit() { local b; for b in $OLD_UNITS; do [ "$1" = "$b" ] && die "refusing to touch live unit $b"; done; case " $NEW_UNITS " in *" $1 "*) ;; *) die "unit $1 is not one of: $NEW_UNITS";; esac; }
guard_path() { case "$1" in $OPT/*|/etc/systemd/system/stealth-indexer-base.service|/etc/systemd/system/stealth-relayer-base.service|$NGX/snippets/stealth-base.conf|$NGX/conf.d/stealth-base-zones.conf|$VHOST) ;; *) die "refusing to write $1 (outside the Base v3 paths)";; esac; }
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

# 6. nginx: own zones, snippet, include; reload only after a passing nginx -t; a failure puts back what THIS run changed
# audit 1181 M-2: UNDO lists exactly the files this run wrote ("restore:<path>" = it existed and its backup is in $BK, "remove:<path>" = this run created it). The rollback touches nothing else: a file the run did not
# write (zones already defined, snippet already up to date) is never restored over and never deleted. It runs from an EXIT trap, so ANY failure after the first write (a failing install, awk, mv, nginx -t) undoes the
# writes; and it is written so that no single failed step cuts it short (every step is an `if`, none relies on set -e).
UNDO=(); NGX_GUARD=0
track() { # path : call BEFORE writing a file in the nginx section. Takes the backup and refuses (real run) when it is not there, so the undo can always restore
  guard_path "$1"; backup "$1"; [ $APPLY = 1 ] || return 0
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
ZONES=$NGX/conf.d/stealth-base-zones.conf; SNIP=$NGX/snippets/stealth-base.conf
NGX_CH=0
# the whole running config once (audit 1181 L-8: grepping `nginx -T | grep -q` under pipefail reads "not found" when grep -q closes the pipe early and nginx dies of SIGPIPE; here grep reads a variable)
if NGXT="$(nginx -T 2>/dev/null)"; then :; else NGXT=""; soft "nginx -T failed: cannot tell which zones are defined"; fi
cfg_without() { awk -v f="$1:" '/^# configuration file /{skip=($4==f)} !skip' <<<"$NGXT"; }      # the dump without the section of file $1: a file about to be replaced must not count as "already defined"
if grep -q 'zone=st_bip_read' <<<"$NGXT"; then ok "nginx zones st_bip_* already defined"
  if grep 'zone=st_bip_' <<<"$NGXT" | grep -q 'binary_remote_addr'; then echo "[todo] the st_bip_* zones still key on \$binary_remote_addr: switch them to \$st_ipkey (map: $D/stealth-ipkey-map.conf; README_ops.txt, audit 1165 L-2)"; fi
else
  say "write $ZONES (limit_req/limit_conn zones st_bip_*; the st_tail cache path comes from the RH zones file)"
  if [ $APPLY = 1 ]; then
    OTHERS="$(cfg_without "$ZONES")"
    if grep -q 'keys_zone=st_tail' <<<"$OTHERS"; then TAIL=""; else TAIL='proxy_cache_path /var/cache/nginx/stealth_tail levels=1 keys_zone=st_tail:2m max_size=64m inactive=1m use_temp_path=off;'; fi
    if grep -q 'map $remote_addr $st_ipkey' <<<"$OTHERS"; then MAP=""; else MAP="$(cat "$D/stealth-ipkey-map.conf")"; fi       # audit 1165 L-2: one IPv6 /64 = one client; the map is defined once per host (the RH installer writes the same one)
    install -d "$NGX_CACHE"; track "$ZONES"
    ZT="$(mktemp "$ZONES.XXXXXX")"      # same directory, then mv: nginx never reads a half-written zones file (the name does not end in .conf, so conf.d/*.conf does not pick up a leftover)
    if printf '%s\n' "$MAP" 'limit_req_zone $st_ipkey zone=st_bip_read:10m rate=10r/s;' 'limit_req_zone $st_ipkey zone=st_bip_post:10m rate=10r/m;' 'limit_conn_zone $st_ipkey zone=st_bip_conn:10m;' "$TAIL" > "$ZT" && chmod 644 "$ZT" && mv -f "$ZT" "$ZONES"; then :; else rm -f "$ZT"; die "could not write $ZONES"; fi
  fi
  NGX_CH=1
fi
if [ -f $SNIP ] && cmp -s "$D/stealth-base.conf" $SNIP; then ok "snippet $SNIP"; else
  guard_path $SNIP; if [ $APPLY = 1 ]; then track $SNIP; else backup $SNIP; fi; run install -D -m 644 -o root -g root "$D/stealth-base.conf" $SNIP; NGX_CH=1; fi
INC="include $NGX/snippets/stealth-base.conf;"; ANCHOR="include $NGX/snippets/stealth-rh.conf;"      # ONE anchor string for the check and for the insert (fixed-string match both times)
if grep -rqs 'snippets/stealth-base.conf' $NGX/sites-enabled $NGX/conf.d 2>/dev/null; then ok "snippet is included"; elif [ $INCLUDE = 1 ]; then
  [ -f "$VHOST" ] && [ ! -L "$VHOST" ] || soft "$VHOST is missing or a symlink: add the include by hand"
  grep -qF -- "$ANCHOR" "$VHOST" 2>/dev/null || soft "no line '$ANCHOR' in $VHOST to anchor on: add the include by hand"
  say "insert '$INC' after the RH include in $VHOST"
  if [ $APPLY = 1 ]; then
    track $VHOST
    # a dot-file in the vhost's own directory (nginx's `include sites-enabled/*` does not match dot-files, so a leftover is never loaded), then mv: the vhost is replaced whole or not at all
    VT="$(mktemp "$(dirname "$VHOST")/.$(basename "$VHOST").XXXXXX")"      # cp -p first (below): the temp file carries the vhost's mode and owner, the awk output only replaces its content
    if cp -p "$VHOST" "$VT" && awk -v inc="    $INC" -v anchor="$ANCHOR" '{print} index($0, anchor) && !d {print inc; d=1} END {exit !d}' "$VHOST" > "$VT" && grep -qF -- "$INC" "$VT" && mv -f "$VT" "$VHOST"; then NGX_CH=1; else rm -f "$VT"; die "could not insert the include into $VHOST (anchor not found, or the write failed)"; fi
  fi
else
  echo "[todo] add this line INSIDE the server{} of app.deepyield.ai, right after the RH include (or re-run with --add-include):"
  echo "         $INC"
fi
if [ $APPLY = 1 ]; then
  if NGT="$(nginx -t 2>&1)"; then ok "nginx -t"; NGX_GUARD=0; else
    printf '%s\n' "$NGT" | tail -5 || true
    die "nginx -t failed: the files this run changed are put back (see [undo] lines), NOT reloading"      # the EXIT trap runs the rollback
  fi
else say "nginx -t (then reload only if it passes; the files this run changed are put back if not)"; fi

# 7. start the two new units only; nginx reload only if this run changed nginx files
if [ $START = 1 ]; then
  for u in $NEW_UNITS; do
    guard_unit $u
    if systemctl is-active --quiet $u; then
      if [ $CH = 1 ] || [ $CODE_CH = 1 ]; then say "restart $u (new code/unit)"; [ $APPLY = 1 ] && systemctl restart $u; else ok "$u already active"; fi
    else run systemctl enable --now $u; fi
  done
fi
if [ $NGX_CH = 1 ]; then say "systemctl reload nginx (after the passing nginx -t)"
  if [ $APPLY = 1 ]; then      # audit 1181 L-7: explicit; a failing test or reload is an error, never a silent skip. The config on disk already passed nginx -t at step 6, so nothing is rolled back here
    if nginx -t >/dev/null 2>&1; then if systemctl reload nginx; then ok "nginx reloaded"; else die "systemctl reload nginx failed (the config on disk passes nginx -t): check journalctl -u nginx"; fi; else die "nginx -t failed before the reload: NOT reloading"; fi
  fi
fi

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
