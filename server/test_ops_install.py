#!/usr/bin/env python3
"""Offline check of the ops scripts (audit 1179 F2/F5/F7): bash -n on every ops script, install_rh.sh refuses --apply when /opt/stealth-rh exists and no longer installs the watchdog or the old sanctions units,
install_watch.sh uses the same paths as the unit files, the deploy gates use if/then/else and check web/vendor/SHA256SUMS. No network, nothing is installed."""
import glob, os, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); OPS = os.path.join(HERE, "..", "ops"); DEP = os.path.join(HERE, "deploy")
ok = fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1
    else: fail += 1; print("FAIL", name, flush=True)
rd = lambda p: open(p).read()
for f in sorted(glob.glob(os.path.join(OPS, "*.sh"))):
    check("bash -n " + os.path.basename(f), subprocess.run(["bash", "-n", f], capture_output=True).returncode == 0)
rh = rd(os.path.join(OPS, "install_rh.sh")); wt = rd(os.path.join(OPS, "install_watch.sh"))
units = re.search(r'^RH_UNITS="([^"]*)"', rh, re.M).group(1).split()
check("RH_UNITS = the two RH units only", units == ["stealth-indexer-rh.service", "stealth-relayer-rh.service"])
check("no watch / sanctions unit names left in install_rh.sh", not re.search(r"stealth-(watch|sanctions)\.(service|timer)|stealth-watch", rh))
check("install_rh.sh --apply refuses when /opt/stealth-rh exists", re.search(r'if \[ -d /opt/stealth-rh \]; then\s*\n\s*if \[ \$APPLY = 1 \]; then die "/opt/stealth-rh exists', rh) is not None)
check("the guard comes before any write step", rh.index("/opt/stealth-rh exists") < rh.index("# 2. user and directories"))
check("install_rh.sh header says legacy and names install_watch.sh", "LEGACY" in rh.split("set -euo")[0] and "install_watch.sh" in rh.split("set -euo")[0])
check("install_rh.sh dry run still exits 0", subprocess.run(["bash", os.path.join(OPS, "install_rh.sh")], capture_output=True, text=True).returncode in (0, 1) )
# install_watch.sh vs the unit files
svc = rd(os.path.join(DEP, "stealth-watch.service")); san = rd(os.path.join(DEP, "stealth-sanctions@.service")); env = rd(os.path.join(DEP, "watch.env.example"))
check("watch unit paths = install_watch.sh OPT/DATA/ENVF", "/opt/stealth-watch" in wt and "WorkingDirectory=/opt/stealth-watch\n" in svc and "OPT=/opt/stealth-watch; DATA=$OPT/data" in wt and "ENVF=$OPT/watch.env" in wt
      and "EnvironmentFile=-/opt/stealth-watch/watch.env" in svc and "ReadWritePaths=/opt/stealth-watch/data" in svc and "ExecStart=/usr/bin/python3 /opt/stealth-watch/stealth_watch.py" in svc)
check("watch.env.example state file under $DATA", "STEALTH_WATCH_STATE=/opt/stealth-watch/data/watch_state.json" in env)
check("watch unit ReadOnlyPaths = the stacks the installer checks", "ReadOnlyPaths=/opt/stealth-rh /opt/stealth-base" in svc and 'STACKS="rh base"' in wt)
check("sanctions template path = /opt/stealth-<stack>/sanctions as the installer", "/opt/stealth-%i/sanctions" in san and "d=/opt/stealth-$s/sanctions" in wt)
for u in ("stealth-watch.service", "stealth-watch.timer", "stealth-sanctions@.service", "stealth-sanctions@.timer"):
    check("install_watch.sh installs " + u + " (file exists)", u in wt.split('UNITS="')[1].split('"')[0] and os.path.exists(os.path.join(DEP, u)))
check("install_watch.sh enables the three timers", 'ENABLE="stealth-watch.timer stealth-sanctions@rh.timer stealth-sanctions@base.timer"' in wt)
check("install_watch.sh refuses the live units", all(x in wt.split('LIVE_UNITS="')[1].split('"')[0].split() for x in ("stealth-indexer.service", "stealth-relayer.service", "stealth-indexer-rh.service", "stealth-relayer-base.service")))
check("install_watch.sh is dry-run by default and never writes a Telegram token", "APPLY=0" in wt and "grep -Ev '^TG_(BOT_TOKEN|CHAT_ID)='" in wt and "mprhedged" not in wt.replace("another project", ""))
check("install_watch.sh dry run exits 0", subprocess.run(["bash", os.path.join(OPS, "install_watch.sh")], capture_output=True, text=True).returncode == 0)
# deploy gates
for f in ("deploy_prod.sh", "deploy_lab.sh"):
    t = rd(os.path.join(OPS, f))
    check(f + " checksum gate is if/then/else, no A && B || C", "if command -v sha256sum >/dev/null; then" in t and not re.search(r"sha256sum >/dev/null && sha256sum", t))
    check(f + " also checks web/vendor/SHA256SUMS", '"$ROOT/web/vendor" && sumcheck' in t)
sums = rd(os.path.join(HERE, "..", "web", "vendor", "SHA256SUMS")).split("\n")
check("vendor manifest paths are relative to web/vendor and exist", all(os.path.exists(os.path.join(HERE, "..", "web", "vendor", l.split(None, 1)[1].strip())) for l in sums if l.strip()) and any("noble.js" in l for l in sums) and any("bip39-english.txt" in l for l in sums))
print("%d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
