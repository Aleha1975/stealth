#!/usr/bin/env bash
# Install the Stealth watchdog (/opt/stealth-watch) and the per-stack OFAC refresh timers (stealth-sanctions@rh, stealth-sanctions@base) on the app server.
# DEFAULT = DRY RUN: prints every action and runs only read-only checks. Pass --apply (as root) to execute.
# Idempotent: every step checks current state and skips when already done. It NEVER touches the live Base units (stealth-indexer.service, stealth-relayer.service, code in /opt/stealth), the RH and Base v3 units
# (stealth-*-rh.service, stealth-*-base.service) or any other product's unit, and refuses a systemctl action or a write outside its own paths. The only thing it changes inside the stacks is the owner of
# /opt/stealth-rh/sanctions and /opt/stealth-base/sanctions (stealth, so the refresh unit can write evm.json). Every file it replaces is first copied to /var/backups/stealth-watch/<time>/.
# It never generates, prints or copies a secret and never reads another project's config: /opt/stealth-watch/watch.env is created from watch.env.example WITHOUT the Telegram lines (alerts go to the journal until you add
# TG_BOT_TOKEN and TG_CHAT_ID there by hand, chmod 600).
# Usage:  ops/install_watch.sh [--apply] [--src <repo>/server] [--no-start]
set -euo pipefail
APPLY=0; START=1; SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../server" && pwd)"
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --no-start) START=0;; --src) SRC="$2"; shift;; -h|--help) sed -n 2,9p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
OPT=/opt/stealth-watch; DATA=$OPT/data; D="$SRC/deploy"; ENVF=$OPT/watch.env
STACKS="rh base"                                        # per-stack sanctions instances: /opt/stealth-<stack>/sanctions
UNITS="stealth-watch.service stealth-watch.timer stealth-sanctions@.service stealth-sanctions@.timer"
ENABLE="stealth-watch.timer stealth-sanctions@rh.timer stealth-sanctions@base.timer"
LIVE_UNITS="stealth-indexer.service stealth-relayer.service stealth-indexer-rh.service stealth-relayer-rh.service stealth-indexer-base.service stealth-relayer-base.service stealth-sanctions.service stealth-sanctions.timer"
TS="$(date -u +%Y%m%d-%H%M%S)"; BK=/var/backups/stealth-watch/$TS
say() { printf '%s %s\n' "$([ $APPLY = 1 ] && echo '[do] ' || echo '[dry]')" "$*"; }
ok()  { printf '[ok]  %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() { say "$*"; [ $APPLY = 1 ] && "$@" || true; }
soft() { if [ $APPLY = 1 ]; then die "$*"; else echo "[warn] (dry run continues) $*"; fi; }
need() { command -v "$1" >/dev/null || soft "missing command: $1"; }
guard_unit() { local b; for b in $LIVE_UNITS; do [ "$1" = "$b" ] && die "refusing to touch live unit $b"; done; case " $UNITS $ENABLE " in *" $1 "*) ;; *) die "unit $1 is not one of: $UNITS $ENABLE";; esac; }
guard_path() { case "$1" in $OPT/*|/etc/systemd/system/stealth-watch.service|/etc/systemd/system/stealth-watch.timer|/etc/systemd/system/stealth-sanctions@.service|/etc/systemd/system/stealth-sanctions@.timer) ;; *) die "refusing to write $1 (outside the watchdog paths)";; esac; }
backup() { # file: copy an existing file to the backup dir before it is replaced
  [ -f "$1" ] || return 0; say "backup $1 -> $BK$1"; [ $APPLY = 1 ] && { mkdir -p "$BK$(dirname "$1")" && cp -p "$1" "$BK$1"; } || true; }
put() { # src dst mode owner : install with guard and backup
  guard_path "$2"; backup "$2"; run install -D -m "$3" -o "$4" -g "$4" "$1" "$2"; }
sync_file() { # src dst mode owner
  if [ -f "$2" ] && cmp -s "$1" "$2"; then ok "up to date $2"; else
    [ -f "$2" ] && say "update $2 (diff follows)" && { diff -u "$2" "$1" | head -20 || true; }
    put "$1" "$2" "$3" "$4"; fi; }
[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die "--apply needs root"
for c in python3 systemctl install diff cmp; do need $c; done
[ -d "$D" ] || die "no deploy dir $D"
for f in $UNITS watch.env.example; do [ -f "$D/$f" ] || die "missing $D/$f"; done
for f in stealth_watch.py chains.json sanctions/update.py; do [ -f "$SRC/$f" ] || die "missing $SRC/$f"; done
echo "mode: $([ $APPLY = 1 ] && echo APPLY || echo 'DRY RUN (nothing is changed)'); source: $SRC; backups: $BK"

# 1. preconditions (read-only)
id stealth >/dev/null 2>&1 && ok "user stealth" || soft "user stealth missing (the stacks created it; the watchdog and refresh units run as stealth)"
for u in $LIVE_UNITS; do systemctl is-active --quiet $u 2>/dev/null && ok "unit $u active (left untouched)"; done
for s in $STACKS; do [ -d /opt/stealth-$s ] && ok "stack /opt/stealth-$s present" || echo "[warn] /opt/stealth-$s missing: the watchdog unit has ReadOnlyPaths on it and the sanctions@$s instance is skipped"; done

# 2. directories
[ -d $OPT ] && ok "dir $OPT" || run install -d -m 755 $OPT
[ -d $DATA ] && ok "dir $DATA" || run install -d -o stealth -g stealth -m 750 $DATA

# 3. code (a private copy; the stacks' own copies are never overwritten)
sync_file "$SRC/stealth_watch.py" $OPT/stealth_watch.py 644 root
sync_file "$SRC/chains.json" $OPT/chains.json 644 root
sync_file "$D/watch.env.example" $OPT/watch.env.example 644 root

# 4. env file: created once, never overwritten, no Telegram lines, never printed
if [ -f $ENVF ]; then
  ok "$ENVF exists (kept)"
  [ "$(stat -c %a $ENVF)" = 600 ] || echo "[warn] $ENVF mode is not 600"
  grep -Eq '^TG_BOT_TOKEN=.+' $ENVF && ! grep -q '<' $ENVF && ok "Telegram token configured (value not shown)" || echo "[info] no Telegram token in $ENVF: alerts go to the journal (journalctl -u stealth-watch)"
else
  say "create $ENVF from watch.env.example without the TG_BOT_TOKEN / TG_CHAT_ID lines (chmod 600, owner stealth)"
  if [ $APPLY = 1 ]; then
    guard_path $ENVF; ( umask 077; grep -Ev '^TG_(BOT_TOKEN|CHAT_ID)=' "$D/watch.env.example" > $ENVF ); chown stealth:stealth $ENVF; chmod 600 $ENVF
  fi
  echo "[todo] add TG_BOT_TOKEN= and TG_CHAT_ID= to $ENVF by hand if you want Telegram alerts (this script never asks for or reads a token)"
fi

# 5. systemd units
CH=0
for f in $UNITS; do
  guard_unit $f; guard_path /etc/systemd/system/$f
  if [ -f /etc/systemd/system/$f ] && cmp -s "$D/$f" /etc/systemd/system/$f; then ok "unit $f"; else backup /etc/systemd/system/$f; run install -m 644 "$D/$f" /etc/systemd/system/$f; CH=1; fi
done
[ $CH = 1 ] && run systemctl daemon-reload

# 6. sanctions directories: the refresh unit runs as stealth and replaces evm.json in its directory
for s in $STACKS; do
  d=/opt/stealth-$s/sanctions
  if [ ! -d $d ]; then echo "[warn] $d missing: sanctions@$s not enabled"; continue; fi
  [ -f $d/update.py ] || { echo "[warn] $d/update.py missing: sanctions@$s not enabled"; continue; }
  [ "$(stat -c %U $d)" = stealth ] && ok "owner of $d" || run chown stealth:stealth $d
  if [ -f $d/evm.json ]; then [ "$(stat -c %U $d/evm.json)" = stealth ] && ok "owner of $d/evm.json" || run chown stealth:stealth $d/evm.json; fi
done

# 7. enable the timers and run the first refresh
if [ $START = 1 ]; then
  for u in $ENABLE; do
    guard_unit $u
    case "$u" in stealth-sanctions@*.timer) s="${u#stealth-sanctions@}"; s="${s%.timer}"; [ -f /opt/stealth-$s/sanctions/update.py ] || { echo "[skip] $u (no /opt/stealth-$s/sanctions/update.py)"; continue; };; esac
    systemctl is-active --quiet $u && ok "$u already active" || run systemctl enable --now $u
  done
  for s in $STACKS; do
    [ -f /opt/stealth-$s/sanctions/update.py ] || continue
    guard_unit stealth-sanctions@$s.timer; say "first refresh: systemctl start stealth-sanctions@$s.service (oneshot, downloads the OFAC list)"
    [ $APPLY = 1 ] && { systemctl start stealth-sanctions@$s.service && ok "sanctions@$s refreshed" || echo "[warn] sanctions@$s failed: journalctl -u stealth-sanctions@$s"; }
  done
  say "first watchdog run: systemctl start stealth-watch.service"
  [ $APPLY = 1 ] && { systemctl start stealth-watch.service && ok "watchdog ran" || echo "[warn] stealth-watch failed: journalctl -u stealth-watch"; }
fi

# 8. checks
if [ $APPLY = 1 ] && [ $START = 1 ]; then
  systemctl list-timers --no-pager 'stealth-watch.timer' 'stealth-sanctions@*.timer' || true
  for s in $STACKS; do [ -f /opt/stealth-$s/sanctions/evm.json ] && echo "[info] $s evm.json: $(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("count"),"addresses, fetched",d.get("fetched"))' /opt/stealth-$s/sanctions/evm.json)"; done
  [ -f $DATA/watch_state.json ] && ok "watch_state.json written" || echo "[warn] $DATA/watch_state.json not written yet (journalctl -u stealth-watch)"
else
  say "checks: systemctl list-timers 'stealth-watch.timer' 'stealth-sanctions@*.timer'; cat /opt/stealth-<rh|base>/sanctions/evm.json (count, fetched); $DATA/watch_state.json; journalctl -u stealth-watch -n 20"
fi
echo "done ($([ $APPLY = 1 ] && echo applied || echo 'dry run, nothing changed'))"
