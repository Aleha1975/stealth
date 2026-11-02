#!/usr/bin/env python3
"""Offline test of the audit 1158 fixes in stealth_indexer.py (fake RPC, no node, no network): pinned head+logs (F-1), strict STEALTHPAY (F-2), /known needs a settled
Transfer (F-3), reconcile deletes only on two agreeing reads + retry of failed receipts + retraction signal (F-4), bounded canonical cache (F-5), strict input and exact
routes (F-6/F-11), total deadline and permit release (F-7). Run: python3 -B server/test_indexer_audit.py"""
import json, os, socket, sqlite3, sys, tempfile, threading, time, urllib.request, urllib.error, importlib

HERE = os.path.dirname(os.path.abspath(__file__))
V3 = "0xc07f54984abda1ef76dab6f602270b76a04e916d"
OTHER = "0x00000000000000000000000000000000000000aa"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
PAYER = "0x00000000000000000000000000000000000000b1"
TT = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond: ok += 1
    else: fail += 1; print("FAIL", name)


def load(**env):
    tmp = tempfile.mkdtemp()
    os.environ.update({"STEALTH_CHAIN": "base", "STEALTHPAY": V3, "STEALTH_DB": os.path.join(tmp, "a.db"), "STEALTH_START_BLOCK": "1"})
    os.environ.pop("STEALTHPAY_LEGACY", None)
    for k, v in env.items(): os.environ[k] = v
    sys.path.insert(0, HERE); sys.modules.pop("stealth_indexer", None)
    m = importlib.import_module("stealth_indexer"); m.init_db(); return m


S = lambda n: "0x%040x" % (0xa000 + n)
TX = lambda n: "0x%064x" % n
w = lambda x: "%064x" % x


def mk_log(block, idx, stealth, caller, amount, n=None):
    meta = bytes.fromhex("11a9059cbb" + USDC[2:] + w(amount))
    eph = bytes.fromhex("02" + "ab" * 32)
    pad = lambda b: b + b"\0" * (-len(b) % 32)
    d = bytes.fromhex(w(64) + w(64 + 32 + 64)) + bytes.fromhex(w(33)) + pad(eph) + bytes.fromhex(w(len(meta))) + pad(meta)
    return {"blockNumber": hex(block), "logIndex": hex(idx), "transactionHash": TX(n if n is not None else block * 100 + idx), "data": "0x" + d.hex(),
            "topics": ["0x" + "5" * 64, "0x" + w(1), "0x" + w(int(stealth, 16)), "0x" + w(int(caller, 16))]}


def rcpt(block, frm, transfers):
    return {"from": frm, "blockNumber": hex(block), "status": "0x1",
            "logs": [{"address": USDC, "logIndex": hex(i), "topics": [TT, "0x" + w(int(a, 16)), "0x" + w(int(b, 16))], "data": "0x" + w(v)} for i, (a, b, v) in enumerate(transfers)]}


class Chain:
    """Fake endpoints: name -> {head, logs, receipts, fail}. Lagging node: honest about a shorter chain, answers a clean empty result beyond its head."""
    def __init__(self, m, eps):
        self.eps = eps; self.calls = []; m.RPCS = list(eps)
        def rpc1(u, method, params, t):
            e = self.eps[u]; self.calls.append((u, method))
            if e.get("fail"): raise RuntimeError("down")
            if e.get("once_fail") and method == "eth_getLogs":
                e["once_fail"] = False; raise RuntimeError("down once")
            if method == "eth_blockNumber": return hex(e["head"])
            if method == "eth_getBlockByNumber":
                if params[0] in ("safe", "latest"): return {"number": hex(e["head"])}
                n = int(params[0], 16); return {"number": hex(n)} if n <= e.get("blocks_to", e["head"]) else None
            if method == "eth_getLogs":
                a, b = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
                return [l for l in e["logs"] if a <= int(l["blockNumber"], 16) <= min(b, e["head"])]
            if method == "eth_getTransactionReceipt": return e.get("receipts", {}).get(params[0])
            raise RuntimeError("unexpected " + method)
        m.rpc1 = rpc1


def serve(m):
    srv = m.BoundedServer(("127.0.0.1", 0), m.H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    def J(p):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (srv.server_address[1], p), timeout=10) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
    return srv, J


def put(m, block, idx, stealth, caller, amount, paid, n=None, payer=None):
    c = m.db(); c.execute("INSERT INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer,paid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          (block, TX(n if n is not None else block * 100 + idx), idx, 1, stealth, caller, "0x02" + "ab" * 32, "0x11a9059cbb" + USDC[2:] + w(amount), "0x11", payer, paid)); c.commit(); c.close()


def meta_set(m, **kv):
    c = m.db()
    for k, v in kv.items(): c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, str(v)))
    c.commit(); c.close()


def count(m): c = m.db(); n = c.execute("SELECT COUNT(*) FROM ann").fetchone()[0]; c.close(); return n


# ---- F-2: strict STEALTHPAY
for bad_sp in ("", "0x1234", "0x" + "g" * 40, " ", V3[:-1]):
    sys.modules.pop("stealth_indexer", None); os.environ["STEALTHPAY"] = bad_sp
    try: importlib.import_module("stealth_indexer"); r = False
    except SystemExit: r = True
    check("F-2 STEALTHPAY %r refuses to start" % bad_sp, r)
os.environ["STEALTHPAY"] = V3.upper().replace("0X", "0x")
sys.modules.pop("stealth_indexer", None); mm = importlib.import_module("stealth_indexer")
check("F-2 mixed-case valid address accepted (lowercased)", mm.STEALTHPAY == V3)

# ---- F-1 / 1163 M-1: head trust. A lags (head 100, clean empty beyond), B is ahead (200) and holds the announcement at block 150
m = load()
A = {"head": 100, "logs": []}; B = {"head": 200, "logs": [mk_log(150, 0, S(1), V3, 5_000_000)], "receipts": {TX(15000): rcpt(150, PAYER, [(PAYER, S(1), 5_000_000)])}}
ch = Chain(m, {"A": A, "B": B})
u, h, sf = m.pick_head(0)
check("M-1 two endpoints: accepted head = the SECOND-highest (100), pinned to a node that has it", (u, h) == ("A", 100) and m._pk["quorum"])
u, h, sf = m.pick_head(120)
check("M-1 second endpoint lags (100 < head_done 120), the top one is ahead: no advance, no rollback", h == 120)
A["head"] = 90; B["head"] = 95
u, h, sf = m.pick_head(120)
check("F-1 two endpoints below head_done = rollback accepted (to the second-highest)", h == 90)
B["fail"] = True
try: m.pick_head(120); r = False
except RuntimeError: r = True
check("F-1/I-2 one lagging answer alone (2 configured) is NOT a rollback at once", r)
m.FALLBACK_S = 0.2; time.sleep(0.3)
u, h, sf = m.pick_head(120)
check("I-2 survivor still lagging after FALLBACK_S -> accepted (no endless stall)", h == 90)
m.FALLBACK_S = 600; B["fail"] = False; A["head"] = 100; B["head"] = 200
# whole loop: A=100 lags, B=200 (A within HEAD_SKEW): head_done stays <= 100; when A reaches 200 block 150 is delivered
m.POLL = 0.02; m.RECONCILE_EVERY = 0.3
threading.Thread(target=m.index_loop, daemon=True).start()
time.sleep(1.0); c = m.db()
hd = int(c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0])
check("M-1 loop: head_done never above the second-highest head while A lags", hd <= 100 and count(m) == 0)
A["head"] = 200; A["logs"] = B["logs"]; t0 = time.time()
while time.time() - t0 < 10 and count(m) < 1: time.sleep(0.05)
hd = int(c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0])
check("F-1 loop: announcement at 150 found once both endpoints have the block", count(m) == 1 and hd == 200)
c.close()

# ---- 1163 M-1: a lying-high head. B claims 5000 and has no logs; A is honest at 300 and gets announcements later
m = load(); A = {"head": 300, "logs": []}; B = {"head": 5000, "logs": [], "blocks_to": 300}
ch = Chain(m, {"A": A, "B": B})
u, h, sf = m.pick_head(0)
check("M-1 a head far above the second-highest is not accepted (300, not 5000)", h == 300)
m = load(); B = {"head": 5000, "logs": [], "blocks_to": 300}; ch = Chain(m, {"B": B}); m.RPCS = ["B"]
u, h, sf = m.pick_head(0)
check("M-1 single endpoint: not quorum, head as claimed (5000) but ...", h == 5000 and not m._pk["quorum"])
check("M-1 single endpoint: advance cut to the highest block the endpoint returns (300)", m._confirm_upto("B", 1, 5000) == 300)
check("M-1 single endpoint: the whole chunk is returned when the block at its end exists", m._confirm_upto("B", 1, 200) == 200)
try: m._confirm_upto("B", 301, 400); r = False
except RuntimeError: r = True
check("M-1 single endpoint: nothing to advance over -> error, head_done stays", r)
# whole loop with a single liar: head_done stops at 300; later real announcement at 400 is not skipped
m.POLL = 0.02; m.RECONCILE_EVERY = 0.3; B["logs"] = []
threading.Thread(target=m.index_loop, daemon=True).start(); time.sleep(0.8)
c = m.db(); hd = int(c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0]); c.close()
check("M-1 loop: single liar cannot move head_done over blocks it does not return (<= 300)", hd == 300)
B["blocks_to"] = 5000; B["logs"] = [mk_log(400, 0, S(1), V3, 5_000_000)]; B["receipts"] = {TX(40000): rcpt(400, PAYER, [(PAYER, S(1), 5_000_000)])}
t0 = time.time()
while time.time() - t0 < 10 and count(m) < 1: time.sleep(0.05)
check("M-1 loop: the announcement at block 400 is indexed once the blocks exist (not skipped)", count(m) == 1)

# ---- 1163 I-2: a single configured endpoint: a low read must repeat
m = load(); A = {"head": 100, "logs": []}; ch = Chain(m, {"A": A})
try: m.pick_head(150); r = False
except RuntimeError: r = True
check("I-2 single endpoint: first low read refused", r)
u, h, sf = m.pick_head(150)
check("I-2 single endpoint: second consecutive low read accepted as rollback", h == 100)
m = load(); A = {"head": 100, "logs": []}; ch = Chain(m, {"A": A})
try: m.pick_head(150)
except RuntimeError: pass
A["head"] = 160; m.pick_head(150); A["head"] = 100
try: m.pick_head(150); r = False
except RuntimeError: r = True
check("I-2 a normal read in between resets the low-read counter", r)

# ---- 1163 M-1: --rewind
m = load(); meta_set(m, head=1000); put(m, 900, 0, S(1), V3, 5_000_000, 5_000_000)
m.START = 1; m.rewind(300)
c = m.db(); check("M-1 rewind moves head back N blocks, rows stay", c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0] == "700" and count(m) == 1)
m.rewind(10_000_000); check("M-1 rewind never goes below START-1", c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0] == "0"); c.close()
import subprocess
env = dict(os.environ); r0 = subprocess.run([sys.executable, "-B", os.path.join(HERE, "stealth_indexer.py"), "--rewind", "x"], env=env, capture_output=True, text=True)
check("M-1 rewind CLI refuses a bad N", r0.returncode != 0 and "usage" in (r0.stdout + r0.stderr))
meta_set(m, head=500)
r0 = subprocess.run([sys.executable, "-B", os.path.join(HERE, "stealth_indexer.py"), "--rewind", "5"], env=env, capture_output=True, text=True)
check("M-1 rewind CLI works", r0.returncode == 0 and "rewind: head 500 -> 495" in r0.stdout)

# ---- F-3 / F-4: receipts, paid, known gate, retraction signal
m = load()
ch = Chain(m, {"A": {"head": 500, "logs": [], "receipts": {}}})
r_ok = {"tx": TX(1), "stealth": S(1), "caller": V3, "block": 10}
ch.eps["A"]["receipts"][TX(1)] = rcpt(10, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000)])
ch.eps["A"]["receipts"][TX(2)] = rcpt(11, PAYER, [(PAYER, S(2), 10)])                                    # announced 5 USDC, really paid 10 units
ch.eps["A"]["receipts"][TX(3)] = rcpt(99, PAYER, [(PAYER, S(3), 5_000_000)])                              # receipt from another block than the log (reorg / wrong node)
base = {"scheme": 1, "eph": "0x02" + "ab" * 32, "meta": "0x11a9059cbb" + USDC[2:] + w(5_000_000), "view_tag": "0x11", "log_index": 10}
for n, st in ((1, S(1)), (2, S(2)), (3, S(3)), (4, S(4))):
    pc = m.db(); m.put_row(pc, dict(base, block=10 + n - 1 if n < 3 else 12, tx=TX(n), stealth=st, caller=V3), {}, "A"); pc.commit(); pc.close()
c = m.db(); rows = {r[0]: r[1:] for r in c.execute("SELECT stealth,payer,paid FROM ann")}
check("F-3/1163 L-1 paid = the matching Transfer to the stealth address; announced 5 USDC but 10 units arrived -> 0", rows[S(1)] == (PAYER, 5_000_000) and rows[S(2)][1] == 0)
check("F-4 wrong-block / missing receipt -> payer NULL and paid NULL (to be retried)", rows[S(3)] == (None, None) and rows[S(4)] == (None, None))
# audit 1161 L-1 / 1163 L-1: feeRecipient == stealth address: the fee leg (10) and the net leg (90) both reach it; the announcement says 90 -> paid = the 90 leg only (not the sum 100)
ch.eps["A"]["receipts"][TX(5)] = rcpt(13, PAYER, [(PAYER, V3, 100), (V3, S(5), 10), (V3, S(5), 90)])
pc = m.db(); m.put_row(pc, dict(base, block=13, tx=TX(5), stealth=S(5), caller=V3, meta="0x11a9059cbb" + USDC[2:] + w(90)), {}, "A"); pc.commit(); pc.close()
c = m.db(); p5 = c.execute("SELECT paid FROM ann WHERE stealth=?", (S(5),)).fetchone()[0]; c.close()
check("1163 L-1 paid = the transfer that matches the announced net (90), not the sum of all Transfers (100)", p5 == 90)
def paid_of(n, rc, ann_idx=10, amount=5_000_000, caller=V3):
    ch.eps["A"]["receipts"][TX(n)] = rc
    pc = m.db(); m.put_row(pc, dict(base, block=rc["blockNumber"] and int(rc["blockNumber"], 16), tx=TX(n), stealth=S(n), caller=caller, log_index=ann_idx, meta="0x11a9059cbb" + USDC[2:] + w(amount)), {}, "A"); pc.commit(); pc.close()
    c = m.db(); v = c.execute("SELECT paid FROM ann WHERE stealth=?", (S(n),)).fetchone()[0]; c.close(); return v
EXTRA = "0x00000000000000000000000000000000000000ee"
check("1163 L-1 direct payToken (payer -> stealth before the announce log) counts", paid_of(21, rcpt(30, PAYER, [(PAYER, S(21), 5_000_000)])) == 5_000_000)
check("1163 L-1 an extra same-tx transfer to the stealth address (dust, other amount) does not inflate paid", paid_of(22, rcpt(30, PAYER, [(EXTRA, S(22), 7_000_000), (PAYER, V3, 5_000_000), (V3, S(22), 5_000_000)])) == 5_000_000)
check("1163 L-1 only an extra transfer of another amount, no real leg -> 0", paid_of(23, rcpt(30, PAYER, [(EXTRA, S(23), 9_000_000)])) == 0)
check("1163 L-1 a same-amount transfer AFTER the announce log from a stranger does not count", paid_of(24, rcpt(30, PAYER, [(EXTRA, S(24), 5_000_000)]), ann_idx=0) == 0)
check("1163 L-1 a transfer FROM StealthPay counts at any position (authorization path, legacy order)", paid_of(25, rcpt(30, PAYER, [(V3, S(25), 5_000_000)]), ann_idx=0) == 5_000_000)
check("1163 L-1 announced amount differs from the transfer -> 0", paid_of(26, rcpt(30, PAYER, [(PAYER, S(26), 4_000_000)])) == 0)
mx = m.PAY_CALLERS; m.PAY_CALLERS = frozenset([V3, "0x00000000000000000000000000000000000000cc"])
check("1163 L-1 legacy v2 authorization (v2 -> stealth) still counts", paid_of(27, rcpt(30, PAYER, [(PAYER, "0x00000000000000000000000000000000000000cc", 5_000_000), ("0x00000000000000000000000000000000000000cc", S(27), 5_000_000)]), caller="0x00000000000000000000000000000000000000cc") == 5_000_000)
m.PAY_CALLERS = mx
meta_set(m, safe_block=1000)
srv, J = serve(m)
check("F-3 known: settled Transfer >= MIN", J("/known?addr=" + S(1)) == (200, {"known": True}))
check("F-3 known: announced 5 USDC but only 10 units settled -> refused", J("/known?addr=" + S(2))[1]["known"] is False)
check("F-4 known: row without verified paid -> refused until fixed", J("/known?addr=" + S(3))[1]["known"] is False)
meta_set(m, safe_block=5)
check("F-3 known: row above the safe block -> refused", J("/known?addr=" + S(1))[1]["known"] is False)
meta_set(m, safe_block=1000)
# retry: the right receipts arrive later
ch.eps["A"]["receipts"][TX(3)] = rcpt(12, PAYER, [(PAYER, S(3), 5_000_000)]); ch.eps["A"]["receipts"][TX(4)] = rcpt(12, PAYER, [(PAYER, V3, 5_000_000), (V3, S(4), 5_000_000)])
n = m.fix_rows(m.db(), "A", 1000)
c = m.db(); rows = {r[0]: r[1:] for r in c.execute("SELECT stealth,payer,paid FROM ann")}
check("F-4 fix_rows filled payer and paid later", n >= 2 and rows[S(3)] == (PAYER, 5_000_000) and rows[S(4)] == (PAYER, 5_000_000))
check("F-4 after the retry the address is known", J("/known?addr=" + S(4))[1]["known"] is True)
check("F-4 fix_rows has nothing left to do", m.fix_rows(m.db(), "A", 1000) == 0)
# migration of an old database (no paid column) and a NULL paid of a StealthPay row is refilled
old = os.path.join(tempfile.mkdtemp(), "old.db"); oc = sqlite3.connect(old)
oc.execute("CREATE TABLE ann (id INTEGER PRIMARY KEY AUTOINCREMENT, block INTEGER, tx TEXT, log_index INTEGER, scheme INTEGER, stealth TEXT, caller TEXT, eph TEXT, meta TEXT, view_tag TEXT, payer TEXT, UNIQUE(tx, log_index))")
oc.execute("INSERT INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer) VALUES(10,?,0,1,?,?,?,?,?,?)", (TX(1), S(1), V3, "0x02" + "ab" * 32, "0x11a9059cbb" + USDC[2:] + w(5_000_000), "0x11", PAYER)); oc.commit(); oc.close()
m.DB = old; m.init_db(); m.init_db()
oc = sqlite3.connect(old); check("F-3 migration adds paid once, keeps rows", oc.execute("SELECT paid, payer FROM ann").fetchall() == [(None, PAYER)]); oc.close()
meta_set(m, safe_block=1000)
m.fix_rows(m.db(), "A", 1000); oc = sqlite3.connect(old); check("F-3 backfill of paid on a migrated row", oc.execute("SELECT paid FROM ann").fetchone()[0] == 5_000_000); oc.close()
m.DB = os.environ["STEALTH_DB"]

# ---- F-4: reconcile deletes only when two reads agree
m = load(); m.MODE = "latest"; m.START = 1
put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000)
row150 = mk_log(150, 0, S(1), V3, 5_000_000)
ch = Chain(m, {"A": {"head": 300, "logs": []}, "B": {"head": 300, "logs": [row150]}})
m.reconcile(m.db(), 200, 250, "A")                       # A answers empty (short), B has it
check("F-4 reconcile: short answer of the pinned node does not delete", count(m) == 1)
ch.eps["B"]["logs"] = []
m.reconcile(m.db(), 200, 250, "A")
check("F-4 reconcile: two endpoints agree the log is gone -> deleted", count(m) == 0)
c = m.db(); check("F-4 reconcile: epoch bumped on removal", c.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()[0] == "1"); c.close()
put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000)
ch.eps["B"]["head"] = 100                                # B lags: its empty answer means nothing; A is read again
ch.eps["A"]["once_fail"] = False
calls = {"n": 0}; orig = m.rpc1
def flaky(u, method, params, t):
    if method == "eth_getLogs" and u == "A":
        calls["n"] += 1
        if calls["n"] == 2: raise RuntimeError("second read failed")
    return orig(u, method, params, t)
m.rpc1 = flaky
m.reconcile(m.db(), 200, 250, "A")
check("F-4 reconcile: no second read obtained -> nothing deleted", count(m) == 1)
m.rpc1 = orig
m.reconcile(m.db(), 200, 250, "A")
check("F-4 reconcile: lagging second node ignored, same node read twice agrees -> deleted", count(m) == 0)
m.MODE = "safe"; put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000)
m.reconcile(m.db(), 200, 250, "A", insert_only=True)
check("F-4 insert_only reconcile never deletes (base)", count(m) == 1)

# ---- F-1/F-4: final flag and epoch in the API
m = load(); put(m, 10, 0, S(1), V3, 5_000_000, 5_000_000); put(m, 900, 0, S(2), V3, 5_000_000, 5_000_000)
meta_set(m, final_block=500, safe_block=800, epoch=3, head=900, chain_head=900, ts=1)
srv, J = serve(m)
st, d = J("/announcements?since=0&limit=10")
check("F-4 rows carry final = block <= final_block", [r["final"] for r in d["rows"]] == [True, False] and d["final_block"] == 500 and d["epoch"] == 3)
st, d = J("/head")
check("F-4 /head exposes final_block, safe_block, epoch", (d["final_block"], d["safe_block"], d["epoch"]) == (500, 800, 3))
check("F-4 old fields of /announcements kept", all(k in d0 for d0 in J("/announcements?since=0")[1]["rows"] for k in ("id", "block", "tx", "scheme", "stealth", "caller", "eph", "meta", "payer")))

# ---- audit 1159 M-1: a verification signal per row (our StealthPay caller + parsed receipt) in /announcements and in the history pages
m = load(); LEG = "0x00000000000000000000000000000000000000cc"; m.PAY_CALLERS = frozenset([V3, LEG])
put(m, 10, 0, S(1), V3, 5_000_000, 5_000_000); put(m, 11, 0, S(2), OTHER, 1_000_000_000_000, 0); put(m, 12, 0, S(3), V3, 5_000_000, None); put(m, 13, 0, S(4), LEG, 5_000_000, 5_000_000)
srv, J = serve(m)
st, d = J("/announcements?since=0&limit=10")
check("M-1 /announcements verified: our caller + parsed receipt = 1; foreign caller, receipt pending = 0; legacy v2 = 1", [r["verified"] for r in d["rows"]] == [1, 0, 0, 1])
pd = tempfile.mkdtemp(); m.PAGES_DIR = pd; m.PAGE_SIZE = 4; m._write_page(m.db(), 0)
pg = json.load(open(os.path.join(pd, m._page_name(0))))
check("M-1 page rows: 7 old fields kept, verified appended last", [len(r) for r in pg] == [8] * 4 and [r[7] for r in pg] == [1, 0, 0, 1] and pg[0][6] is None and pg[0][3] == S(1))

# ---- F-5 / 1163 I-1: cache only canonical keys, bounded by bytes AND by entry count, only since <= max id
m = load(STEALTH_ANN_CACHE_BYTES="4000"); meta_set(m, final_block=1)
for i in range(1, 8): put(m, i, 0, S(i), V3, 5_000_000, 5_000_000)
srv, J = serve(m)
for sq in (1, 2, 3, 1025, "7"): J("/announcements?since=%s&limit=2000" % sq)
J("/announcements?since=0&limit=7")
check("F-5 arbitrary since/limit are never cached", len(m._ann_cache) == 0)
J("/announcements?since=0&limit=2000"); J("/announcements?since=0&limit=1000")
check("F-5 canonical keys are cached", len(m._ann_cache) >= 1)
check("F-5 cache stays within the byte budget", m._ann_size[0] <= m.ANN_CACHE_BYTES and m._ann_size[0] == sum(len(v[1]) for v in m._ann_cache.values()))
m._ann_cache.clear(); m._ann_size[0] = 0
for sq in (1024, 2048, 3072, 1 << 20, 1 << 30): J("/announcements?since=%d&limit=2000" % sq)
check("1163 I-1 canonical since beyond the max id (empty tail answers) is not cached", len(m._ann_cache) == 0)
m.ANN_CACHE_BYTES = 1 << 30; m.ANN_CACHE_ENTRIES = 3; m.ANN_TTL = 1000
for i in range(8): m._ann_put((i * 1024, 1000), time.time(), b"x")
check("1163 I-1 entry count capped (3) even for tiny bodies", len(m._ann_cache) <= 3)
m._ann_put((5, 5), time.time(), b"y" * (m.ANN_CACHE_BYTES + 1))
check("1163 I-1 a body larger than the whole budget is not cached", (5, 5) not in m._ann_cache)

# ---- F-6/F-11: strict input, exact routes, caches
m = load(); calls = []
ch = Chain(m, {"A": {"head": 5, "logs": []}})
dom = "0x" + "12" * 32
orig = m.rpc1
def counting(u, method, params, t):
    calls.append(method)
    if method == "eth_call" and params[0]["data"] == "0x3644e515": return dom
    if method == "eth_getTransactionReceipt": return {"status": "0x1", "blockNumber": "0x5"}
    return orig(u, method, params, t)
m.rpc1 = counting
srv, J = serve(m); m._mc.update({"ok": True, "ts": time.time()})
bad = ["/known?addr=0x" + "zz" * 20, "/known?addr=0x" + "A" * 39 + "%C3%A9", "/known?addr=0x%s%%20" % ("a" * 39), "/known", "/receipt?tx=0x" + "g" * 64, "/receipt?tx=0x12",
       "/announcements?since=1_0", "/announcements?since=99999999999999999999999", "/announcements?since=-1", "/announcements?since=9223372036854775808", "/announcements?limit=x",
       "/balances?addrs=0x" + "zz" * 20, "/balances?addrs=", "/balances?addrs=" + ",".join(["0x" + "a" * 40] * 101)]
check("F-6 bad input -> 400 (never 500)", all(J(p)[0] == 400 for p in bad))
check("F-6 multicall state not reset by client input errors", m._mc["ok"] is True)
check("F-6 nothing reached the RPC for bad input", "eth_getCode" not in calls and "eth_call" not in calls)
J("/usdc-domain"); J("/usdc-domain")
check("F-6 /usdc-domain cached", calls.count("eth_call") == 1)
tx = "0x" + "a" * 64; J("/receipt?tx=" + tx); J("/receipt?tx=" + tx)
check("F-6 /receipt cached briefly", calls.count("eth_getTransactionReceipt") == 1)
check("F-11 routes: prefixed and bare paths work", all(J(p)[0] == 200 for p in ("/head", "/stealth-api/head", "/stealth-api/rh/head", "/stealth-api/base/known?addr=" + S(1))))
check("F-11 routes: no endswith matching", all(J(p)[0] == 404 for p in ("/xhead", "/evil/head", "/head/x", "/stealth-api/rh/relay/head", "/stealth-api/a/b/head", "/knownx")))

# ---- F-7: permit released when the thread cannot start; total request deadline
m = load(); srv = m.BoundedServer(("127.0.0.1", 0), m.H)
before = srv._sem._value; a, b = socket.socketpair(); orig_start = threading.Thread.start
def boom(self): raise RuntimeError("can't start new thread")
threading.Thread.start = boom
try: srv.process_request(a, ("127.0.0.1", 1)); raised = False
except RuntimeError: raised = True
finally: threading.Thread.start = orig_start
check("F-7 Thread.start failure re-raised and the permit released", raised and srv._sem._value == before)
b.close()
m.REQ_DEADLINE = 0.7
srv, J = serve(m); s = socket.create_connection(("127.0.0.1", srv.server_address[1])); s.settimeout(5)
t0 = time.time(); s.sendall(b"GET /he"); time.sleep(0.3); s.sendall(b"a")                    # dribbling client: one byte per operation, never a full request
try: got = s.recv(10)
except socket.timeout: got = None
check("F-7 a dribbling client is cut at the total deadline (not held for the per-operation timeout)", got in (b"", ) and time.time() - t0 < 3)
s.close(); time.sleep(0.2)
check("F-7 permit back after the cut request", srv._sem._value == before)

# ---- 1163 L-2: reorg delete and epoch bump in ONE transaction
m = load(); m.MODE = "latest"; m.START = 1
put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000)
ch = Chain(m, {"A": {"head": 300, "logs": []}, "B": {"head": 300, "logs": []}})
real = m._bump_epoch
def die(c, commit=True): raise RuntimeError("killed between delete and epoch bump")
m._bump_epoch = die
rc_ = m.db()
try: m.reconcile(rc_, 200, 250, "A")
except RuntimeError: pass
rc_.close()
check("L-2 crash after the delete, before the epoch bump: nothing was committed (row still there, epoch unchanged)", count(m) == 1 and not sqlite3.connect(m.DB).execute("SELECT v FROM meta WHERE k='epoch'").fetchone())
m._bump_epoch = real; m.reconcile(m.db(), 200, 250, "A")
c = m.db(); check("L-2 normal path: row removed and epoch 1 together", count(m) == 0 and c.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()[0] == "1"); c.close()

# ---- 1163 L-3: the watchdog Timer cannot start -> the permit is released and the socket closed
m = load(); srv = m.BoundedServer(("127.0.0.1", 0), m.H); before = srv._sem._value
a_, b_ = socket.socketpair(); srv._sem.acquire()
orig_ts = threading.Timer.start
def tboom(self): raise RuntimeError("can't start new thread")
threading.Timer.start = tboom
try: srv.process_request_thread(a_, ("127.0.0.1", 1))
finally: threading.Timer.start = orig_ts
b_.settimeout(2)
check("L-3 Timer.start failure: permit released", srv._sem._value == before)
try: closed = b_.recv(1) == b""
except Exception: closed = False
check("L-3 Timer.start failure: socket shut down (peer sees EOF)", closed); b_.close()

# ---- 1163 L-4: no per-address RPC amplification
m = load(); calls = []
ch = Chain(m, {"A": {"head": 5, "logs": []}}); o4 = m.rpc1
m.rpc1 = lambda u, meth, p, t: (calls.append(meth), o4(u, meth, p, t))[1]
m._mc.update({"ok": False, "ts": time.time()})
srv, J = serve(m)
st, d = J("/balances?addrs=" + ",".join("0x%040x" % (0xb000 + i) for i in range(m.MAX_SINGLE + 1)))
check("L-4 /balances without multicall refuses more than MAX_SINGLE addresses before any RPC call", st == 500 and "eth_call" not in calls and "eth_getBalance" not in calls)
m.REQ_MAX_CALLS = 3; m._tl.calls = 0
n_ok = 0
try:
    for _ in range(5): m.rpc("eth_blockNumber", []); n_ok += 1
except RuntimeError as e: msg = str(e)
check("L-4 per-request RPC call budget stops a request after REQ_MAX_CALLS attempts", n_ok == 3 and "budget" in msg); m._tl.calls = None
check("L-4 the indexer thread (no counter) is not limited", all(m.rpc("eth_blockNumber", []) for _ in range(10)))

# ---- 1163 I-4: DB open failure answers 500; KNOWN_SAFE=0 only for a local fork; one final-block formula
m = load(); srv, J = serve(m); o_rdb = m.rdb
m.rdb = lambda: (_ for _ in ()).throw(sqlite3.OperationalError("unable to open database file"))
st, d = J("/head"); m.rdb = o_rdb
check("I-4 rdb() failure inside try: 500 JSON answer, not a dropped request", st == 500 and d.get("error"))
def refuses(**env):
    keep = {k: os.environ.get(k) for k in ("STEALTH_KNOWN_SAFE", "STEALTH_RPC", "STEALTH_FORK")}
    for k in keep: os.environ.pop(k, None)
    os.environ.update(env); sys.modules.pop("stealth_indexer", None)
    try: importlib.import_module("stealth_indexer"); r = False
    except SystemExit: r = True
    for k, v in keep.items():
        if v is None: os.environ.pop(k, None)
        else: os.environ[k] = v
    return r
check("I-4 KNOWN_SAFE=0 with a public RPC refused", refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="https://base-rpc.publicnode.com"))
check("I-4 KNOWN_SAFE=0 with no RPC set (chains.json public defaults) refused", refuses(STEALTH_KNOWN_SAFE="0"))
check("I-4 KNOWN_SAFE=0 with a lookalike host refused", refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="http://127.0.0.1.evil.example:8545"))
check("I-4 KNOWN_SAFE=0 on a loopback fork accepted", not refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="http://127.0.0.1:8545"))
check("I-4 KNOWN_SAFE=0 with STEALTH_FORK=1 accepted", not refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="https://example.org", STEALTH_FORK="1"))
check("I-4 default (KNOWN_SAFE on) unaffected", not refuses(STEALTH_RPC="https://base-rpc.publicnode.com"))
m = load(); m.MODE = "latest"; m.CONF = 0; m.PAGES_MARGIN = 200; m.POLL = 0.02; m.RECONCILE_EVERY = 100
Chain(m, {"A": {"head": 500, "logs": []}}); seen_fin = []
m.pages_step = lambda c, fb: seen_fin.append(fb)
threading.Thread(target=m.index_loop, daemon=True).start(); time.sleep(0.6)
c = m.db(); fbm = c.execute("SELECT v FROM meta WHERE k='final_block'").fetchone(); c.close()
check("I-4 pages_step gets the same final block as the meta (500 - 200 = 300)", seen_fin and set(seen_fin) == {300} and fbm and fbm[0] == "300")

# ---- 1163 I-3: nginx wasm location (text check; nginx is not run here)
ng = open(os.path.join(HERE, "..", "ops", "nginx-stealth-zec.conf")).read()
code = "\n".join(l.split("#")[0] for l in ng.splitlines())
wl = code[code.index("location ~ \\.wasm$"):]
check("I-3 no include mime.types / outer types{} (no duplicate-extension warning)", "include mime.types" not in code and code.count("types {") == 1)
check("I-3 the .wasm location serves application/wasm via empty types{} + default_type", "types { }" in wl and "default_type application/wasm" in wl)

print("%d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
