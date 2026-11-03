#!/usr/bin/env python3
"""Offline check of the ops scripts (audit 1179 F2/F5/F7): bash -n on every ops script, install_rh.sh refuses --apply when /opt/stealth-rh exists and no longer installs the watchdog or the old sanctions units,
install_watch.sh uses the same paths as the unit files, the deploy gates use if/then/else and check web/vendor/SHA256SUMS. No network, nothing is installed."""
import glob, os, re, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); OPS = os.path.join(HERE, "..", "ops"); DEP = os.path.join(HERE, "deploy")
ok = fail = 0
def check(name, cond, info=""):
    global ok, fail
    if cond: ok += 1
    else: fail += 1; print("FAIL", name, ("\n    " + str(info)[-900:]) if info else "", flush=True)
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
    check(f + " also checks web/vendor/SHA256SUMS", '"$SRC/vendor" && sumcheck' in t)
# audit 1180 L-2: a failing command under --apply must stop the script
for f in ("install_watch.sh", "install_rh.sh", "install_base.sh"):
    t = rd(os.path.join(OPS, f)); line = [l for l in t.split("\n") if l.startswith("run()")][0]
    check(f + " run() uses if/then (a failing command stops under set -e), no A && B || true", 'if [ $APPLY = 1 ]; then "$@"; fi;' in line and "|| true" not in line and "set -e" in t)
# audit 1180 L-4: copy first, check the copy, ship the copy; unlisted vendor files refuse the deploy
for f in ("deploy_prod.sh", "deploy_lab.sh"):
    t = rd(os.path.join(OPS, f))
    check(f + " copies web/ before the check and checks and ships the copy", t.index('rsync -a --exclude .DS_Store "$ROOT/web/" "$SRC/"') < t.index('cd "$SRC/vendor/webzjs"') < t.index('cd "$SRC/vendor" &&') and '"$SRC/" "$OUT/"' in t and '"$SRC/vendor/webzjs/"' in t and '"$ROOT/web/' not in t.split('"$SRC/"', 1)[1])
    check(f + " refuses unlisted files in web/vendor and web/vendor/webzjs", t.count("unlisted") >= 3 and "holds an unlisted file" in t)
# the unlisted() idiom itself, on a scratch tree
import tempfile, shutil
with tempfile.TemporaryDirectory() as d:
    idiom = [l for l in rd(os.path.join(OPS, "deploy_prod.sh")).split("\n") if "comm -23" in l][0].strip().rstrip("}").rstrip().rstrip(";")
    def run_unlisted(extra=""):
        return subprocess.run(["bash", "-c", "unlisted() { " + idiom + "; }\ncd " + d + " && unlisted " + extra], capture_output=True, text=True).stdout.strip()
    open(os.path.join(d, "a.js"), "w").write("x"); open(os.path.join(d, "SHA256SUMS"), "w").write("0  a.js\n"); os.makedirs(os.path.join(d, "webzjs"))
    check("unlisted(): nothing unlisted -> empty", run_unlisted() == "")
    open(os.path.join(d, "evil.js"), "w").write("x"); check("unlisted(): an extra file is reported", run_unlisted() == "evil.js")
    os.remove(os.path.join(d, "evil.js")); os.symlink("a.js", os.path.join(d, "ln.js")); check("unlisted(): a symlink is reported too", run_unlisted() == "ln.js")

# ---- audit 1181 L-6 / I-3: deploy refuses symlinks and a dirty web/, the manifest check is --strict
for f in ("deploy_prod.sh", "deploy_lab.sh"):
    t = rd(os.path.join(OPS, f))
    check(f + " refuses a symlink or special file in the copy (find -type l / not f not d) and a symlinked web/vendor/webzjs before copying", r'find "$SRC" \( -type l -o ! -type f ! -type d \)' in t and '[ -L "$ROOT/web/vendor/webzjs" ]' in t and t.index('[ -L "$ROOT/web/vendor/webzjs" ]') < t.index('rsync -a --exclude .DS_Store "$ROOT/web/"') < t.index('find "$SRC" \\('))
    check(f + " refuses a dirty web/ (git status --porcelain: staged and untracked too) unless FORCE_DIRTY=1; sumcheck uses --strict", 'status --porcelain --untracked-files=all -- web' in t and 'FORCE_DIRTY' in t and t.count("-c --quiet --strict") == 2 and 'diff --quiet ||' not in t)
# behaviour on a scratch repo: copy of the script into <root>/ops, a git repo with a clean web/
def scratch(extra=None):
    d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "ops")); os.makedirs(os.path.join(d, "web", "vendor", "webzjs"))
    for f in ("deploy_prod.sh", "deploy_lab.sh"): shutil.copy(os.path.join(OPS, f), os.path.join(d, "ops", f))
    open(os.path.join(d, "web", "a.js"), "w").write("x\n"); open(os.path.join(d, "web", "chains.js"), "w").write('export const privateFee = { fastBps: 20, maxBps: 30, appFeeRecipient: "loop_hole.near" };\n'); open(os.path.join(d, "web", "vendor", "webzjs", "w.js"), "w").write("w\n"); open(os.path.join(d, "web", "vendor", "n.js"), "w").write("n\n")
    sh = lambda p, *fs: subprocess.run(["shasum", "-a", "256", *fs], cwd=p, capture_output=True, text=True).stdout
    open(os.path.join(d, "web", "vendor", "webzjs", "SHA256SUMS"), "w").write(sh(os.path.join(d, "web", "vendor", "webzjs"), "w.js"))
    open(os.path.join(d, "web", "vendor", "SHA256SUMS"), "w").write(sh(os.path.join(d, "web", "vendor"), "n.js"))
    if extra: extra(d)
    g = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d, capture_output=True, text=True)
    g("init", "-q"); g("add", "-A"); g("commit", "-q", "-m", "x"); return d, g
def deploy(d, script="deploy_prod.sh", env=None):
    # a fake rsync that only copies the first (local) tree pair and pretends the remote ones worked: the gates run before any remote call
    bindir = tempfile.mkdtemp(); open(os.path.join(bindir, "ssh"), "w").write("#!/bin/sh\nexit 0\n"); os.chmod(os.path.join(bindir, "ssh"), 0o755)
    real = shutil.which("rsync")
    open(os.path.join(bindir, "rsync"), "w").write('#!/bin/sh\nfor a in "$@"; do case "$a" in *:*) echo "REMOTE-RSYNC $*" >> "%s/remote.log"; exit 0;; esac; done\nexec %s "$@"\n' % (bindir, real)); os.chmod(os.path.join(bindir, "rsync"), 0o755)
    r = subprocess.run(["bash", os.path.join(d, "ops", script)], capture_output=True, text=True, env=dict(os.environ, PATH=bindir + ":" + os.environ["PATH"], **(env or {})))
    return r, os.path.exists(os.path.join(bindir, "remote.log"))
if shutil.which("rsync") and shutil.which("git"):
    d, g = scratch(); r, shipped = deploy(d)
    check("1181 deploy: a clean tree passes the gates and ships", r.returncode == 0 and shipped, r.stdout + r.stderr)
    for kind, mk in (("an untracked file", lambda d: open(os.path.join(d, "web", "new.js"), "w").write("n")), ("a staged file", lambda d: (open(os.path.join(d, "web", "a.js"), "a").write("y"), subprocess.run(["git", "add", "web/a.js"], cwd=d))), ("a modified file", lambda d: open(os.path.join(d, "web", "a.js"), "a").write("y"))):
        d, g = scratch(); mk(d); r, shipped = deploy(d)
        check("1181 I-3 %s in web/ -> refused, nothing shipped" % kind, r.returncode != 0 and not shipped and "uncommitted" in r.stdout, r.stdout)
        r, shipped = deploy(d, env={"FORCE_DIRTY": "1"}); check("1181 I-3 ...and FORCE_DIRTY=1 deploys it (version gets a -<time> suffix)", r.returncode == 0 and shipped and re.search(r"deployed [0-9a-f]+-\d+ ", r.stdout) is not None, r.stdout + r.stderr)
    d, g = scratch(lambda d: open(os.path.join(d, "outside.txt"), "w").write("o")); open(os.path.join(d, ".gitignore"), "w").write("")
    d2, g2 = scratch(lambda d: os.symlink("a.js", os.path.join(d, "web", "ln.js"))); r, shipped = deploy(d2)
    check("1181 L-6 a symlinked file in web/ (even listed or not) -> refused before any check or ship", r.returncode != 0 and not shipped and "symlink" in r.stdout, r.stdout)
    d3, g3 = scratch(); shutil.rmtree(os.path.join(d3, "web", "vendor", "webzjs")); os.makedirs(os.path.join(d3, "elsewhere")); open(os.path.join(d3, "elsewhere", "w.js"), "w").write("w\n"); open(os.path.join(d3, "elsewhere", "SHA256SUMS"), "w").write(subprocess.run(["shasum", "-a", "256", "w.js"], cwd=os.path.join(d3, "elsewhere"), capture_output=True, text=True).stdout)
    os.symlink(os.path.join(d3, "elsewhere"), os.path.join(d3, "web", "vendor", "webzjs")); g3("add", "-A"); g3("commit", "-q", "-m", "link"); r, shipped = deploy(d3)
    check("1181 L-6 web/vendor/webzjs itself a symlink -> refused before the copy", r.returncode != 0 and not shipped and "webzjs is a symlink" in r.stdout, r.stdout)
    d4, g4 = scratch(); open(os.path.join(d4, "web", "vendor", "webzjs", "SHA256SUMS"), "a").write("this line is not a checksum\n"); g4("add", "-A"); g4("commit", "-q", "-m", "bad"); r, shipped = deploy(d4)
    check("1181 I-3 a malformed manifest line is an error (--strict), not a skipped line", r.returncode != 0 and not shipped, r.stdout + r.stderr)
    # audit 1182 L-4: git-ignored files under web/ are shipped by rsync but invisible to `git status --porcelain`
    def ign(d): open(os.path.join(d, ".gitignore"), "w").write("node_modules/\nweb/vendor/webzjs/package.json\n")
    for script in ("deploy_prod.sh", "deploy_lab.sh"):
        d7, g7 = scratch(ign); os.makedirs(os.path.join(d7, "web", "node_modules")); open(os.path.join(d7, "web", "node_modules", "x.js"), "w").write("evil\n"); r, shipped = deploy(d7, script=script)
        check("1182 L-4 %s: an ignored web/node_modules file -> refused, nothing shipped, the path is named" % script, r.returncode != 0 and not shipped and "git-ignored" in r.stdout and "web/node_modules/" in r.stdout, r.stdout + r.stderr)
        r, shipped = deploy(d7, script=script, env={"FORCE_DIRTY": "1"}); check("1182 L-4 ...FORCE_DIRTY does not override it", r.returncode != 0 and not shipped and "git-ignored" in r.stdout)
        d8, g8 = scratch(ign); open(os.path.join(d8, "web", "vendor", "webzjs", "package.json"), "w").write("{}\n"); r, shipped = deploy(d8, script=script)
        check("1182 L-4 %s: an ignored file of the expected wasm set (web/vendor/webzjs/package.json) passes THIS gate (the manifest gate judges it)" % script, "git-ignored" not in r.stdout, r.stdout)
    d9, g9 = scratch(ign); r, shipped = deploy(d9); check("1182 L-4 a clean tree with an ignore file still ships", r.returncode == 0 and shipped, r.stdout + r.stderr)
    # audit 1184 F1: prod ships the fee OFF unless PROD_FEE_ON=1, the state is always printed; lab keeps the repo value
    d10, g10 = scratch(); r, shipped = deploy(d10); check("1184 F1 deploy_prod.sh default: fee OFF, and the line says so", r.returncode == 0 and "service fee: OFF" in r.stdout and "service fee: ON" not in r.stdout, r.stdout + r.stderr)
    r, shipped = deploy(d10, env={"PROD_FEE_ON": "1"}); check("1184 F1 PROD_FEE_ON=1: fee ON, the line names the recipient", r.returncode == 0 and "service fee: ON, recipient loop_hole.near" in r.stdout, r.stdout + r.stderr)
    r, shipped = deploy(d10, env={"PROD_FEE_OFF": "1"}); check("1184 F1 the old PROD_FEE_OFF flag is gone (no effect, still OFF by default)", r.returncode == 0 and "service fee: OFF" in r.stdout and "PROD_FEE_OFF" not in rd(os.path.join(OPS, "deploy_prod.sh")))
    d11, g11 = scratch(lambda d: open(os.path.join(d, "web", "chains.js"), "w").write("export const x = 1;\n")); r, shipped = deploy(d11); check("1184 F1 no appFeeRecipient line in chains.js -> refused, nothing shipped", r.returncode != 0 and not shipped, r.stdout)
    d12, g12 = scratch(); r, shipped = deploy(d12, script="deploy_lab.sh"); check("1184 F1 deploy_lab.sh prints no fee line and is unchanged", r.returncode == 0 and "service fee" not in r.stdout)
    # audit 1183 L-5: hidden local edits and untracked files in a collapsed dir
    for script in ("deploy_prod.sh", "deploy_lab.sh"):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            d13, g13 = scratch(); subprocess.run(["git", "update-index", flag, "web/a.js"], cwd=d13); open(os.path.join(d13, "web", "a.js"), "a").write("hidden\n")
            r, shipped = deploy(d13, script=script); check("1183 L-5 %s: a file flagged %s -> refused, nothing shipped" % (script, flag), r.returncode != 0 and not shipped and "assume-unchanged or skip-worktree" in r.stdout and "web/a.js" in r.stdout, r.stdout + r.stderr)
            r, shipped = deploy(d13, script=script, env={"FORCE_DIRTY": "1"}); check("1183 L-5 ...FORCE_DIRTY does not override it", r.returncode != 0 and not shipped)
        d14, g14 = scratch(); os.makedirs(os.path.join(d14, "web", "sub")); open(os.path.join(d14, "web", "sub", "n.js"), "w").write("n"); r, shipped = deploy(d14, script=script)
        check("1183 L-5 %s: an untracked file in a new directory is named by its own path" % script, r.returncode != 0 and "web/sub/n.js" in r.stdout, r.stdout)
        d15, g15 = scratch(ign); open(os.path.join(d15, ".gitignore"), "a").write(".DS_Store\n"); open(os.path.join(d15, "web", ".DS_Store"), "w").write("x"); os.makedirs(os.path.join(d15, "web", "vendor", "z")); open(os.path.join(d15, "web", "vendor", "z", ".DS_Store"), "w").write("x")
        r, shipped = deploy(d15, script=script); check("1183 I-7 %s: an ignored .DS_Store (top level or nested) does not trip the ignored-file gate" % script, "git-ignored" not in r.stdout and r.returncode == 0, r.stdout + r.stderr)
    d5, g5 = scratch(); r, shipped = deploy(d5, script="deploy_lab.sh"); check("1181 deploy_lab.sh passes the same gates when clean", r.returncode == 0 and shipped, r.stdout + r.stderr)
    d6, g6 = scratch(lambda d: os.symlink("a.js", os.path.join(d, "web", "ln.js"))); r, shipped = deploy(d6, script="deploy_lab.sh"); check("1181 L-6 deploy_lab.sh refuses a symlink too", r.returncode != 0 and not shipped)

# ---- audit 1181 M-2 / L-7 / L-8: the nginx section of install_base.sh, run for real against a scratch /etc/nginx with a fake `nginx`
ib = rd(os.path.join(OPS, "install_base.sh")); ir = rd(os.path.join(OPS, "install_rh.sh"))
check("1181 M-2 install_base.sh: rollback keyed on what THIS run wrote (UNDO), run from an EXIT trap, no `rm -f` of a path that was not recorded", "UNDO+=" in ib and "trap 'rc=$?" in ib and 'rm -f "$z"' not in ib and "for z in" not in ib)
check("1181 L-7 reload is an explicit if/else die in both installers; no `&& nginx -t ... && systemctl reload nginx` chain", "systemctl reload nginx && ok" not in ib + ir and "systemctl reload nginx failed" in ib and "systemctl reload nginx failed" in ir)
check("1181 L-8 `nginx -T` is captured once and grepped as a variable (no `nginx -T | grep -q`)", "nginx -T 2>/dev/null | grep" not in ib + ir and 'NGXT="$(nginx -T' in ib and 'NGXT="$(nginx -T' in ir)
check("1181 L-7 the check and the awk insert use the same anchor string", ib.count('"$ANCHOR"') >= 2 and "snippets/stealth-rh.conf;/" not in ib)
def harness_for(script_text, start_marker, end_marker, stop_before):
    return script_text[:script_text.index(stop_before)] + script_text[script_text.index(start_marker):script_text.index(end_marker)] + '\necho SECTION-DONE\n'
if shutil.which("nginx") is None or True:
    H = harness_for(ib, "# 6. nginx", "# 7. start", '[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die')
    def nginx_env(vhost_extra="", snippet="outdated", zones="absent", dump_zone=False, dump_extra="", t_fail=True, vhost_has_base=False, anchor=True):
        d = tempfile.mkdtemp(); ngx = os.path.join(d, "nginx"); bk = os.path.join(d, "bk"); cache = os.path.join(d, "cache"); bindir = os.path.join(d, "bin")
        for x in ("sites-enabled", "snippets", "conf.d"): os.makedirs(os.path.join(ngx, x))
        os.makedirs(bindir); vh = os.path.join(ngx, "sites-enabled", "app-deepyield"); sn = os.path.join(ngx, "snippets", "stealth-base.conf"); zn = os.path.join(ngx, "conf.d", "stealth-base-zones.conf"); other = os.path.join(ngx, "conf.d", "other.conf"); rhs = os.path.join(ngx, "snippets", "stealth-rh.conf")
        orig = {}
        def w(path, text): open(path, "w").write(text); orig[path] = text
        w(vh, "server {\n    listen 443;\n" + ("    include %s/snippets/stealth-rh.conf;\n" % ngx if anchor else "") + ("    include %s/snippets/stealth-base.conf;\n" % ngx if vhost_has_base else "") + vhost_extra + "}\n"); os.chmod(vh, 0o640)
        w(rhs, "# rh snippet\n"); w(other, "# unrelated\n")
        if snippet == "outdated": w(sn, "# old base snippet\n")
        elif snippet == "current": shutil.copy(os.path.join(HERE, "deploy", "stealth-base.conf"), sn); orig[sn] = rd(sn)
        if zones == "old": w(zn, "# old zones file, no st_bip zones in it\n")
        elif zones == "current": w(zn, "limit_req_zone $st_ipkey zone=st_bip_read:10m rate=10r/s;\n")
        dump = os.path.join(d, "dump.txt"); open(dump, "w").write(("limit_req_zone $st_ipkey zone=st_bip_read:10m rate=10r/s;\n" if dump_zone else "# nothing\n") + dump_extra)
        open(os.path.join(bindir, "nginx"), "w").write('#!/bin/sh\ncase "$1" in -t) if [ -n "$FAKE_T_FAIL" ]; then echo "nginx: [emerg] fake failure" >&2; echo "nginx: configuration file test failed" >&2; exit 1; fi; echo "syntax is ok" >&2; exit 0;; -T) cat "$FAKE_DUMP"; exit 0;; esac\nexit 0\n')
        os.chmod(os.path.join(bindir, "nginx"), 0o755)
        # a non-root, non-GNU `install`: the same call without the -o/-g pairs, and -D done by hand
        open(os.path.join(bindir, "install"), "w").write('#!/usr/bin/env python3\nimport sys, os\na = sys.argv[1:]; out = []; i = 0; D = False\nwhile i < len(a):\n    if a[i] in ("-o", "-g"): i += 2; continue\n    if a[i] == "-D": D = True; i += 1; continue\n    out.append(a[i]); i += 1\nif D: os.makedirs(os.path.dirname(out[-1]), exist_ok=True)\nos.execv("/usr/bin/install", ["install"] + out)\n')
        os.chmod(os.path.join(bindir, "install"), 0o755)
        env = dict(os.environ, PATH=bindir + ":" + os.environ["PATH"], STEALTH_NGINX_DIR=ngx, STEALTH_BACKUP_DIR=bk, STEALTH_NGINX_CACHE=cache, FAKE_DUMP=dump, **({"FAKE_T_FAIL": "1"} if t_fail else {}))
        return dict(d=d, ngx=ngx, env=env, vh=vh, sn=sn, zn=zn, other=other, orig=orig)
    def run_section(e, extra_args=("--add-include",)):
        os.makedirs(os.path.join(e["d"], "ops"), exist_ok=True); os.makedirs(os.path.join(e["d"], "server"), exist_ok=True)      # the script's default SRC is ../server
        hp = os.path.join(e["d"], "ops", "harness.sh"); open(hp, "w").write(H)
        return subprocess.run(["bash", hp, "--apply", *extra_args, "--src", HERE], capture_output=True, text=True, env=e["env"])
    same = lambda e, path: os.path.exists(path) and rd(path) == e["orig"][path]
    # 1: nginx -t fails; zones already defined in the running config (zones file not touched), snippet outdated (touched), vhost gets the include (touched)
    e = nginx_env(zones="current", dump_zone=True); r = run_section(e)
    check("1181 M-2 -t fails: the run FAILS and says why (set -e does not cut the rollback short)", r.returncode != 0 and "nginx -t failed" in r.stderr and "SECTION-DONE" not in r.stdout, r.stdout + r.stderr)
    check("1181 M-2 ...the vhost and the snippet this run changed are restored byte for byte, and the [undo] lines say so", same(e, e["vh"]) and same(e, e["sn"]) and r.stdout.count("[undo] restored") == 2, r.stdout)
    check("1181 M-2 ...a file the run did NOT touch (zones already defined, the unrelated conf.d file, the RH snippet) is neither restored nor deleted", same(e, e["zn"]) and same(e, e["other"]) and same(e, os.path.join(e["ngx"], "snippets", "stealth-rh.conf")) and e["zn"] not in r.stdout)
    check("1181 M-2 ...no temp file is left behind, in sites-enabled (dot-files) or conf.d", sorted(os.listdir(os.path.join(e["ngx"], "sites-enabled"))) == ["app-deepyield"] and sorted(os.listdir(os.path.join(e["ngx"], "conf.d"))) == ["other.conf", "stealth-base-zones.conf"])
    # 2: zones file created by this run is removed; an up-to-date snippet and the vhost (already including the base snippet) are not touched
    e = nginx_env(zones="absent", snippet="current", vhost_has_base=True); r = run_section(e)
    check("1181 M-2 -t fails: a zones file this run CREATED is deleted again (and only that one)", r.returncode != 0 and not os.path.exists(e["zn"]) and "[undo] removed " + e["zn"] in r.stdout and r.stdout.count("[undo]") == 1, r.stdout + r.stderr)
    check("1181 M-2 ...the up-to-date snippet and the vhost the run did not change are untouched", same(e, e["sn"]) and same(e, e["vh"]) and same(e, e["other"]))
    # 3: an existing zones file (no zones in the running config) is rewritten, then restored, never deleted
    e = nginx_env(zones="old", snippet="current", vhost_has_base=True); r = run_section(e)
    check("1181 M-2 -t fails: an existing zones file the run rewrote is RESTORED, not deleted", r.returncode != 0 and same(e, e["zn"]) and "[undo] restored " + e["zn"] in r.stdout, r.stdout + r.stderr)
    # 4: nginx -t passes: everything lands, once, with the vhost's mode, no leftovers, no undo
    e = nginx_env(zones="absent", snippet="outdated", t_fail=False); r = run_section(e); vt = rd(e["vh"])
    check("1181 M-2 -t passes: exit 0, section completes, no [undo]", r.returncode == 0 and "SECTION-DONE" in r.stdout and "[undo]" not in r.stdout, r.stdout + r.stderr)
    check("1181 L-7 ...the include is inserted exactly once, right after the RH include, and the vhost keeps its mode", vt.count("stealth-base.conf;") == 1 and vt.index("stealth-rh.conf;") < vt.index("stealth-base.conf;") and oct(os.stat(e["vh"]).st_mode & 0o777) == "0o640" and sorted(os.listdir(os.path.join(e["ngx"], "sites-enabled"))) == ["app-deepyield"])
    check("1181 M-2 ...the zones file and the snippet were written", "zone=st_bip_read" in rd(e["zn"]) and rd(e["sn"]) == rd(os.path.join(HERE, "deploy", "stealth-base.conf")))
    # 5: the anchor is missing: the run stops (after having written the snippet) and the rollback removes what it created
    e = nginx_env(zones="current", dump_zone=True, snippet="absent", anchor=False, t_fail=False); r = run_section(e)
    check("1181 L-7 --add-include without the RH anchor line: the run stops, it does not report an insert that never happened", r.returncode != 0 and "anchor" in r.stderr and same(e, e["vh"]), r.stdout + r.stderr)
    check("1181 M-2 ...and the snippet written before the stop is removed again by the EXIT-trap rollback (any failure after the first write undoes the writes)", not os.path.exists(e["sn"]) and "[undo] removed " + e["sn"] in r.stdout, r.stdout)
    # 6: self-match: the zones file about to be replaced is the only place with the map and st_tail -> the new file must still carry them
    sec = "# configuration file %s/conf.d/stealth-base-zones.conf:\nmap $remote_addr $st_ipkey { default $remote_addr; }\nproxy_cache_path /var/cache/nginx/stealth_tail keys_zone=st_tail:2m;\n" 
    e = nginx_env(zones="old", t_fail=False); open(e["env"]["FAKE_DUMP"], "a").write(sec % e["ngx"]); r = run_section(e); z = rd(e["zn"])
    check("1181 L-8 the zones file being replaced does not count as 'already defined': the new file still has the map and the st_tail cache path", r.returncode == 0 and "map $remote_addr $st_ipkey" in z and "keys_zone=st_tail" in z, z)
    e = nginx_env(zones="old", t_fail=False); open(e["env"]["FAKE_DUMP"], "a").write("# configuration file %s/conf.d/elsewhere.conf:\nmap $remote_addr $st_ipkey { default $remote_addr; }\nproxy_cache_path /x keys_zone=st_tail:2m;\n" % e["ngx"]); r = run_section(e); z = rd(e["zn"])
    check("1181 L-8 ...but a map and a cache path defined in ANOTHER file are not duplicated", r.returncode == 0 and "map $remote_addr" not in z and "keys_zone=st_tail" not in z and "zone=st_bip_read" in z, z)
    # 7: a big dump does not turn into a false miss (grep reads a variable, not a pipe that nginx can break)
    e = nginx_env(zones="current", dump_zone=True, snippet="current", vhost_has_base=True, t_fail=False, dump_extra="x\n" * 2_000_000); r = run_section(e)
    check("1181 L-8 a very large `nginx -T` dump with the zone near the top is still seen as defined (no SIGPIPE false miss): the zones file is left alone", r.returncode == 0 and "already defined" in r.stdout and same(e, e["zn"]), r.stdout[-300:] + r.stderr[-300:])
    # install_rh.sh section 5 has the same scheme (its own file names)
    HR = harness_for(ir, "# 5. nginx", "# 6. start RH units only", '[ $APPLY = 1 ] && [ "$(id -u)" != 0 ] && die')
    e = nginx_env(zones="absent", dump_zone=False); rhz = os.path.join(e["ngx"], "conf.d", "stealth-rh-zones.conf"); rhs = os.path.join(e["ngx"], "snippets", "stealth-rh.conf")
    os.makedirs(os.path.join(e["d"], "ops"), exist_ok=True); os.makedirs(os.path.join(e["d"], "server"), exist_ok=True); hp = os.path.join(e["d"], "ops", "harness_rh.sh"); open(hp, "w").write(HR)
    r = subprocess.run(["bash", hp, "--apply", "--src", HERE], capture_output=True, text=True, env=dict(e["env"], PATH=e["env"]["PATH"]))
    check("1181 M-2 install_rh.sh: -t fails -> the outdated RH snippet is restored, the zones file the run created is removed, the unrelated file untouched, exit != 0", r.returncode != 0 and same(e, rhs) and not os.path.exists(rhz) and same(e, e["other"]) and r.stdout.count("[undo]") == 2, r.stdout + r.stderr)
sums = rd(os.path.join(HERE, "..", "web", "vendor", "SHA256SUMS")).split("\n")
check("vendor manifest paths are relative to web/vendor and exist", all(os.path.exists(os.path.join(HERE, "..", "web", "vendor", l.split(None, 1)[1].strip())) for l in sums if l.strip()) and any("noble.js" in l for l in sums) and any("bip39-english.txt" in l for l in sums))

# the ignored-file allowlist must accept files INSIDE web/vendor/webzjs/snippets/ (git lists them one by one with --untracked-files=all; a deploy was refused once because only the directory was allowed)
import re as _re
for _name in ("deploy_prod.sh", "deploy_lab.sh"):
    _src = open(os.path.join(HERE, "..", "ops", _name)).read()
    _m = _re.search(r"-e '(\^!! web/vendor/webzjs/\([^']*\)\$)'", _src)
    _ok = bool(_m)
    if _ok:
        _rx = _re.compile(_m.group(1))
        _ok = bool(_rx.match("!! web/vendor/webzjs/snippets/wasm_thread-8ee53d0673203880/src/wasm32/js/module_worker_start.js")) and bool(_rx.match("!! web/vendor/webzjs/webzjs_wallet_bg.wasm")) and not _rx.match("!! web/node_modules/x.js") and not _rx.match("!! web/vendor/webzjs/evil.js")
    check("1184 deploy gate allowlist (%s): files inside snippets/ and the wasm build files pass, anything else is refused" % _name, _ok)

print("%d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
