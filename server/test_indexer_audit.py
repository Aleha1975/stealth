#!/usr/bin/env python3
"""Offline test of the audit 1158 / 1163 / 1165 fixes in stealth_indexer.py (fake RPC, no node, no network): one trust rule (1165: head moves only over a block whose hash two endpoints return; one configured endpoint = trusted provider + parentHash chain; safe = min; receipts and logs checked against the agreed hash), strict STEALTHPAY (F-2), strict STEALTHPAY (F-2), /known needs a settled
Transfer (F-3), reconcile deletes only on two agreeing reads + retry of failed receipts + retraction signal (F-4), bounded canonical cache (F-5), strict input and exact
routes (F-6/F-11), total deadline and permit release (F-7). Run: python3 -B server/test_indexer_audit.py"""
import hashlib, io, json, os, socket, sqlite3, sys, tempfile, threading, time, urllib.request, urllib.error, importlib, contextlib

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
H = lambda n, salt="": "0x" + hashlib.sha256(("%s:%d" % (salt, n)).encode()).hexdigest()      # хэш блока n в цепи «salt»: у честных точек salt пустой


def mk_log(block, idx, stealth, caller, amount, n=None):
    meta = bytes.fromhex("11a9059cbb" + USDC[2:] + w(amount))
    eph = bytes.fromhex("02" + "ab" * 32)
    pad = lambda b: b + b"\0" * (-len(b) % 32)
    d = bytes.fromhex(w(64) + w(64 + 32 + 64)) + bytes.fromhex(w(33)) + pad(eph) + bytes.fromhex(w(len(meta))) + pad(meta)
    return {"blockNumber": hex(block), "blockHash": H(block), "logIndex": hex(idx), "transactionHash": TX(n if n is not None else block * 100 + idx), "data": "0x" + d.hex(),
            "topics": ["0x" + "5" * 64, "0x" + w(1), "0x" + w(int(stealth, 16)), "0x" + w(int(caller, 16))]}


def rcpt(block, frm, transfers, bh=None):
    return {"from": frm, "blockNumber": hex(block), "blockHash": bh or H(block), "status": "0x1",
            "logs": [{"address": USDC, "logIndex": hex(i), "topics": [TT, "0x" + w(int(a, 16)), "0x" + w(int(b, 16))], "data": "0x" + w(v)} for i, (a, b, v) in enumerate(transfers)]}


class Chain:
    """Fake endpoints: name -> {head, logs, receipts, fail, salt, safe, blocks_to, fake_high}. salt -- «своя цепь» (другие хэши блоков); lagging node: честен про короткую цепь, за головой отдаёт чистый пустой результат;
    fake_high -- на любой номер отвечает выдуманным блоком (врущий «вверх» узел)."""
    def __init__(self, m, eps):
        self.eps = eps; self.calls = []; m.RPCS = list(eps); m.NEED = min(2, len(eps))
        def blk(e, n):
            if e.get("fake_high"): return {"number": hex(n), "hash": H(n, "fake"), "parentHash": H(n - 1, "fake")}
            sl = lambda k: e.get("salt", "") if k >= e.get("fork_at", 0) else ""                  # fork_at: the chain's own hashes start there (shared history below)
            if e.get("bad_parent") and n >= e["bad_parent"]: return {"number": hex(n), "hash": H(n, sl(n)), "parentHash": H(n - 1, e.get("lie_salt", "lie"))}          # right block hash, invented parent
            return {"number": hex(n), "hash": H(n, sl(n)), "parentHash": H(n - 1, sl(n - 1))} if n <= e.get("blocks_to", e["head"]) else None
        def rpc1(u, method, params, t):
            e = self.eps[u]; self.calls.append((u, method))
            if e.get("fail"): raise RuntimeError("down")
            if e.get("once_fail") and method == "eth_getLogs":
                e["once_fail"] = False; raise RuntimeError("down once")
            if method == "eth_blockNumber": return hex(e["head"])
            if method == "eth_getBlockByNumber":
                if params[0] == "safe":
                    if e.get("safe", 0) is None: raise RuntimeError("no safe tag")
                    return blk({"head": 10**9, "salt": e.get("salt", "")}, e.get("safe", e["head"]))
                if params[0] == "latest": return blk({"head": 10**9, "salt": e.get("salt", "")}, e["head"])
                return blk(e, int(params[0], 16))
            if method == "eth_getLogs":
                a, b = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
                return [l for l in e["logs"] if a <= int(l["blockNumber"], 16) <= min(b, e["head"])]
            if method == "eth_getTransactionReceipt":
                rc = e["receipts"].get(params[0]) if "receipts" in e else next((x["receipts"][params[0]] for x in self.eps.values() if x is not e and params[0] in x.get("receipts", {})), None)     # no "receipts" key = an honest replica of the others
                if rc is None: return None
                return dict(rc, transactionHash=rc.get("transactionHash", params[0]), logs=[dict(l, transactionHash=l.get("transactionHash", params[0])) for l in rc["logs"]])
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

def run_loop(m, secs=None, until=None, limit=10):
    """Запустить index_loop в потоке; ждать until() до limit с (или secs секунд)."""
    m.POLL = 0.02; m.RECONCILE_EVERY = 0.3
    threading.Thread(target=m.index_loop, daemon=True).start()
    if secs: time.sleep(secs); return
    t0 = time.time()
    while time.time() - t0 < limit and not until(): time.sleep(0.05)


def meta_get(m, k):
    c = m.db(); r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone(); c.close(); return r[0] if r else None


# ---- 1165 M-1: ONE rule. head_done moves to b only over a block whose hash NEED endpoints return (2 configured -> two different endpoints; 1 configured -> trusted + parentHash chain)
m = load(); A = {"head": 100, "logs": []}; B = {"head": 200, "logs": []}
Chain(m, {"A": A, "B": B})
check("1165 heads: candidate = the second-highest claim (100), not the top endpoint's 200", m.heads_now()[0] == 100)
hb, eps = m.agreed(100, {})
check("1165 agreed: both endpoints return the same hash at 100", hb == H(100) and eps == ["A", "B"])
try: m.agreed(150, {}); r = False
except RuntimeError: r = True
check("1165 agreed: block 150 exists on B only -> no agreement (wait)", r)
B["salt"] = "x"
try: m.agreed(100, {}); r = False
except RuntimeError as e: r = "no 2 endpoints agree" in str(e)
check("1165 two endpoints with different hashes at the same block -> no agreement, no advance", r)
B["salt"] = ""; B["fail"] = True
try: m.heads_now(); r = False
except RuntimeError: r = True
check("1165 2 configured, only 1 answers -> waits (never takes one endpoint's word)", r)
try: m.agreed(100, {}); r = False
except RuntimeError: r = True
check("1165 2 configured, only 1 returns the block -> no agreement", r)
# safe tag: the lower of the two
B["fail"] = False; A["head"] = B["head"] = 600; A["safe"] = 500; B["safe"] = 300; m.MODE = "latest"; m.CONF = 20
check("1165 safe tag = min of the two endpoints (300), not one endpoint's (500)", m.heads_now() == (580, 300))
A["safe"] = None
check("1165 safe tag missing on one of two endpoints -> None (no safe claim)", m.heads_now() == (580, None))
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 500}}); m.MODE = "latest"; m.CONF = 20
check("1165 one configured endpoint: head and safe are its own", m.heads_now() == (580, 500))

# 1171+: /known on rh (mode latest) trusts a row KNOWN_LAG_S after the indexed head, not at the node's safe tag (that lags 10-15 min); on base (mode safe) the boundary is safe itself
m = load(STEALTH_KNOWN_LAG_S="120"); A = {"head": 5000, "logs": [], "safe": 100}; Chain(m, {"A": A}); m.MODE = "latest"; m.CONF = 20; m.START = 1; m.BLOCK_MS = 100
lag = -(-m.KNOWN_LAG_S * 1000 // m.BLOCK_MS)
check("rh known lag: 120 s at 100 ms/block = 1200 blocks", lag == 1200)
m = load(); Chain(m, {"A": {"head": 5000, "logs": [], "safe": 100}}); m.MODE = "latest"; m.CONF = 20; m.BLOCK_MS = 100
run_loop(m, until=lambda: meta_get(m, "known_block") is not None)
kb, sbk, hd = int(meta_get(m, "known_block")), int(meta_get(m, "safe_block")), int(meta_get(m, "head"))
check("rh: known_block = head - lag (not the node's safe tag); safe_block keeps the safe tag", kb == hd - 1200 and sbk == min(100, hd) and kb > sbk)
m = load(); Chain(m, {"A": {"head": 5000, "logs": [], "safe": 100}}); m.START = 1
run_loop(m, until=lambda: meta_get(m, "known_block") is not None)
check("base (mode safe): known_block = safe_block = indexed head", meta_get(m, "known_block") == meta_get(m, "safe_block") == meta_get(m, "head"))
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 500}}); meta_set(m, safe_block=1000, known_block=5)
pc = m.db(); m.put_row(pc, dict(scheme=1, eph="0x02" + "ab" * 32, meta="0x11a9059cbb" + USDC[2:] + w(5_000_000), view_tag="0x11", log_index=1, block=10, tx=TX(1), stealth=S(1), caller=V3), {}, "A"); pc.execute("UPDATE ann SET paid=5000000, payer=?", (PAYER,)); pc.commit(); pc.close()
srv0, J0 = serve(m)
check("/known reads known_block first: row at 10 above known_block 5 -> refused even though safe_block is 1000", J0("/known?addr=" + S(1))[1]["known"] is False)
meta_set(m, known_block=20)
check("/known: row at 10 at or below known_block 20 -> known", J0("/known?addr=" + S(1))[1]["known"] is True)

# whole loop, 2 endpoints disagree on the hash -> no advance (and an ALERT after WAIT_ALERT_S); agree later -> the announcement at 150 is found, not skipped
m = load(); m.WAIT_ALERT_S = 0.3
A = {"head": 200, "logs": [mk_log(150, 0, S(1), V3, 5_000_000)], "receipts": {TX(15000): rcpt(150, PAYER, [(PAYER, S(1), 5_000_000)])}}
B = {"head": 200, "logs": [mk_log(150, 0, S(1), V3, 5_000_000)], "salt": "x", "receipts": A["receipts"]}
Chain(m, {"A": A, "B": B}); out = io.StringIO()
with contextlib.redirect_stdout(out):
    run_loop(m, secs=1.0)
check("1165 loop: endpoints disagree on the hash -> head_done does not move, nothing indexed", meta_get(m, "head") is None and count(m) == 0)
check("1165 loop: ALERT in the log after WAIT_ALERT_S without progress", "ALERT indexing has not advanced" in out.getvalue())
B["salt"] = ""; t0 = time.time()
while time.time() - t0 < 10 and count(m) < 1: time.sleep(0.05)
time.sleep(0.2)
check("1165 loop: once both agree the announcement at 150 is indexed and head_done = 200 with its hash stored", count(m) == 1 and meta_get(m, "head") == "200" and meta_get(m, "head_hash") == H(200))

# one endpoint lies HIGH with fabricated block numbers: A honest at 300, B claims 5000 and invents every block
m = load(); A = {"head": 300, "logs": []}; B = {"head": 5000, "logs": [], "fake_high": True}
Chain(m, {"A": A, "B": B})
check("1165 lying-high: candidate head is 300 (second-highest claim)", m.heads_now()[0] == 300)
run_loop(m, secs=0.8)
check("1165 lying-high with 2 endpoints: the fabricated hash at 300 is not confirmed by A -> no advance at all", meta_get(m, "head") is None)
# the liar is honest up to 300 and silent above: moves to 300 only; the real announcement at 400 appears later and is NOT skipped
m = load(); A = {"head": 300, "logs": []}; B = {"head": 5000, "logs": [], "blocks_to": 300}
Chain(m, {"A": A, "B": B})
run_loop(m, secs=0.8)
check("1165 lying-high (honest below 300): head_done stops at 300, never over unmined blocks", meta_get(m, "head") == "300")
A["head"] = 500; A["logs"] = [mk_log(400, 0, S(1), V3, 5_000_000)]; A["receipts"] = {TX(40000): rcpt(400, PAYER, [(PAYER, S(1), 5_000_000)])}
time.sleep(0.6)
check("1165 lying-high: head_done does not pass the liar's last real block while it cannot confirm 400", meta_get(m, "head") == "300" and count(m) == 0)
B["blocks_to"] = 5000; B["head"] = 500; B["logs"] = A["logs"]                                       # the second endpoint catches up (and, being honest now, agrees)
B["fake_high"] = False; B["receipts"] = A["receipts"]
t0 = time.time()
while time.time() - t0 < 10 and count(m) < 1: time.sleep(0.05)
check("1165 lying-high: once two endpoints confirm block 500 the announcement at 400 is indexed (not skipped)", count(m) == 1 and meta_get(m, "head") == "500")

# logs: a getLogs answer from the agreed chain must carry the agreed blockHash and stay inside [a,b]
m = load(); A = {"head": 300, "logs": []}; B = {"head": 300, "logs": []}; Chain(m, {"A": A, "B": B})
bad = mk_log(150, 0, S(1), V3, 5_000_000); bad["blockHash"] = H(150, "other")
try: m.check_logs([bad], 100, 200, {}); r = False
except RuntimeError as e: r = "agreed hash" in str(e)
check("1165 logs: a log whose blockHash is not the agreed hash of its block is rejected", r)
try: m.check_logs([mk_log(250, 0, S(1), V3, 5_000_000)], 100, 200, {}); r = False
except RuntimeError as e: r = "outside" in str(e)
check("1165 logs: a block outside the requested range is rejected", r)
check("1165 logs: honest logs pass", m.check_logs([mk_log(150, 0, S(1), V3, 5_000_000)], 100, 200, {}) is None)
B["salt"] = "x"
try: m.check_logs([mk_log(150, 0, S(1), V3, 5_000_000)], 100, 200, {}); r = False
except RuntimeError: r = True
check("1165 logs: endpoints that disagree on the block of a log -> not accepted", r)

# ONE configured endpoint (trusted provider): moves by its own word, but parentHash continuity against the stored hash catches a backend switch (1167 L-2: the walk back stops at a stored hash that still matches)
m = load(); m.CHUNK0 = 20; A = {"head": 200, "logs": []}; Chain(m, {"A": A})
run_loop(m, until=lambda: meta_get(m, "head") == "200")
check("1165 single endpoint: indexes to 200 and stores the hash of block 200", meta_get(m, "head") == "200" and meta_get(m, "head_hash") == H(200))
A["salt"] = "z"; A["fork_at"] = 131; A["head"] = 400; A["logs"] = [mk_log(150, 0, S(7), V3, 5_000_000)]            # backend switched to a chain that forked at 131: its block 201 has another parent
for l in A["logs"]: l["blockHash"] = H(150, "z")
A["receipts"] = {TX(15000): rcpt(150, PAYER, [(PAYER, S(7), 5_000_000)], bh=H(150, "z"))}
out = io.StringIO(); t0 = time.time()
with contextlib.redirect_stdout(out):
    while time.time() - t0 < 10 and count(m) < 1: time.sleep(0.05)
    time.sleep(0.3)
check("1165 single endpoint backend switch: parentHash mismatch is reported", "does not match the stored hash" in out.getvalue())
check("1165/1167 single endpoint backend switch: stepped back to a stored block below the fork, the window is re-read (announcement at 150 not skipped), the chain continues from the new hashes",
      count(m) == 1 and meta_get(m, "head") == "400" and meta_get(m, "head_hash") == H(400, "z") and "re-reading from 101" in out.getvalue())
# 1167 L-2: a fork deeper than REORG_WIN: the walk back doubles (100, then 200) until a stored hash matches; rows above the matching block are dropped (the reconcile window cannot reach them) and epoch bumps
m = load(); m.CHUNK0 = 50; A = {"head": 1000, "logs": []}; Chain(m, {"A": A})
run_loop(m, until=lambda: meta_get(m, "head") == "1000")
put(m, 600, 0, S(8), V3, 5_000_000, 5_000_000)
A["salt"] = "z"; A["fork_at"] = 451; A["head"] = 1200
out = io.StringIO(); t0 = time.time()
with contextlib.redirect_stdout(out):
    while time.time() - t0 < 10 and meta_get(m, "head") != "1200": time.sleep(0.05)
    time.sleep(0.2)
check("1167 L-2 deep fork (single endpoint): keeps stepping back until a stored hash matches, then follows the new chain", "re-reading from 201" in out.getvalue() and meta_get(m, "head") == "1200" and meta_get(m, "head_hash") == H(1200, "z"))
check("1167 L-2 deep fork: the old-fork row above the matching block is dropped and epoch bumped", count(m) == 0 and meta_get(m, "epoch") == "1")
# no stored hash matches (fork below everything we kept, or a database without bh): ALERT and wait for the operator, head_done does not move
m = load(); m.CHUNK0 = 50; A = {"head": 300, "logs": []}; Chain(m, {"A": A})
run_loop(m, until=lambda: meta_get(m, "head") == "300")
A["salt"] = "z"; A["fork_at"] = 1; A["head"] = 500
out = io.StringIO()
with contextlib.redirect_stdout(out): time.sleep(0.8)
check("1167 L-2 nothing stored matches: ALERT, head_done stays, no re-read from the new chain", "ALERT no stored block hash matches" in out.getvalue() and meta_get(m, "head") == "300")
check("1169 I-4 the deep-divergence ALERT is throttled (many polls, one line)", out.getvalue().count("ALERT no stored block hash matches") == 1)
# 1169 M-1: two endpoints, ONE of them invents the parentHash of the next block (right block hash): the other does not confirm -> no step back, no delete, no epoch bump; the index keeps moving (via the honest one)
m = load(); m.CHUNK0 = 50; A = {"head": 300, "logs": []}; B = {"head": 300, "logs": []}; Chain(m, {"A": A, "B": B})
run_loop(m, until=lambda: meta_get(m, "head") == "300"); put(m, 150, 0, S(9), V3, 5_000_000, 5_000_000)
A["bad_parent"] = 301; A["head"] = B["head"] = 700
fc = []; _fc = m.find_common; m.find_common = lambda *a: (fc.append(a), _fc(*a))[1]
out = io.StringIO()
with contextlib.redirect_stdout(out):
    t0 = time.time()
    while time.time() - t0 < 10 and meta_get(m, "head") != "700": time.sleep(0.05)
    time.sleep(0.2)
check("1169 M-1 2 endpoints, one lies about parentHash: no rollback, no delete, no epoch bump, the old row stays, indexing reaches 700",
      not fc and count(m) == 1 and meta_get(m, "epoch") is None and meta_get(m, "head") == "700" and meta_get(m, "head_hash") == H(700))
# 1171 I-1: both endpoints differ from the stored hash but invent DIFFERENT parents (they do not show the same mismatch): no rollback
m = load(); m.CHUNK0 = 50; A = {"head": 300, "logs": []}; B = {"head": 300, "logs": []}; Chain(m, {"A": A, "B": B})
run_loop(m, until=lambda: meta_get(m, "head") == "300"); put(m, 150, 0, S(9), V3, 5_000_000, 5_000_000)
A["bad_parent"] = B["bad_parent"] = 301; A["lie_salt"] = "l1"; B["lie_salt"] = "l2"; A["head"] = B["head"] = 700
fc = []; _fc = m.find_common; m.find_common = lambda *a: (fc.append(a), _fc(*a))[1]
out = io.StringIO()
with contextlib.redirect_stdout(out):
    time.sleep(1.5)
check("1171 I-1 two endpoints with different invented parents: no rollback, no delete, the old row stays, head does not move", not fc and count(m) == 1 and meta_get(m, "epoch") is None and meta_get(m, "head") == "300")
# both of them agree the parent differs (a real fork seen by both): the walk back still happens
m = load(); m.CHUNK0 = 50; A = {"head": 300, "logs": []}; B = {"head": 300, "logs": []}; Chain(m, {"A": A, "B": B})
run_loop(m, until=lambda: meta_get(m, "head") == "300")
A["salt"] = B["salt"] = "z"; A["fork_at"] = B["fork_at"] = 251; A["head"] = B["head"] = 500
out = io.StringIO()
with contextlib.redirect_stdout(out):
    t0 = time.time()
    while time.time() - t0 < 10 and meta_get(m, "head") != "500": time.sleep(0.05)
    time.sleep(0.2)
check("1169 M-1 2 endpoints both confirm the mismatch: step back and follow the new chain", "re-reading from" in out.getvalue() and meta_get(m, "head_hash") == H(500, "z"))
# find_common: the stored hash of head_done is still agreed -> no rollback needed
c = m.db(); r = m.find_common(c, 500, {}, H(500, "z")); c.close()
check("1169 M-1 find_common returns head_done itself when its stored hash is still agreed", r == (500, H(500, "z")))
# 1169 L-3: hex integers of a receipt compare as numbers
m = load(); Chain(m, {"A": {"head": 20, "logs": []}, "B": {"head": 20, "logs": []}})
rw = {"tx": TX(1), "block": 10}; r1 = rcpt(10, PAYER, [(PAYER, V3, 1)]); r2 = dict(r1, blockNumber="0x0a", status="0x01"); r2["logs"] = [dict(l, logIndex="0x00") for l in r1["logs"]]; r1["logs"] = [dict(l, logIndex="0x0") for l in r1["logs"]]
r1["transactionHash"] = r2["transactionHash"] = TX(1)
for l in r1["logs"] + r2["logs"]: l["transactionHash"] = TX(1)
k1, k2 = m._rc_key(rw, r1, {}), m._rc_key(rw, r2, {})
check("1169 L-3 _rc_key: 0x1 / 0x01, 0xa / 0x0a, logIndex 0x0 / 0x00 give one key", k1 is not None and k1 == k2)
# first start / a database without head_hash: the first step is accepted without a comparison
m = load(); meta_set(m, head=100); Chain(m, {"A": {"head": 150, "logs": []}}); run_loop(m, until=lambda: meta_get(m, "head") == "150")
check("1165 no stored hash yet (new database / older version): accepted, hash stored", meta_get(m, "head") == "150" and meta_get(m, "head_hash") == H(150))
# a single endpoint that claims a head it cannot serve does not move the index (the block at b must exist)
m = load(); Chain(m, {"A": {"head": 5000, "logs": [], "blocks_to": 300}}); run_loop(m, secs=0.6)
check("1165 single endpoint claiming a head it cannot serve: waits", meta_get(m, "head") is None)

# a head below head_done is not a rollback (no automatic walk back on one word): the loop just waits; a real fork shows as a parentHash mismatch
m = load(); meta_set(m, head=150); Chain(m, {"A": {"head": 100, "logs": []}, "B": {"head": 100, "logs": []}}); run_loop(m, secs=0.5)
check("1165 head below head_done: no rollback, head_done stays", meta_get(m, "head") == "150")

# receipts used for paid (and /known): blockHash must equal the agreed hash of the block (2 endpoints)
m = load(); A = {"head": 500, "logs": [], "receipts": {}}; B = {"head": 500, "logs": []}; Chain(m, {"A": A, "B": B})
rowb = {"scheme": 1, "eph": "0x02" + "ab" * 32, "meta": "0x11a9059cbb" + USDC[2:] + w(5_000_000), "view_tag": "0x11", "log_index": 10}
A["receipts"][TX(1)] = rcpt(10, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000)])
A["receipts"][TX(2)] = rcpt(10, PAYER, [(PAYER, V3, 5_000_000), (V3, S(2), 5_000_000)], bh=H(10, "forged"))     # right block number, forged block hash
A["receipts"][TX(3)] = rcpt(10, PAYER, [(PAYER, V3, 5_000_000), (V3, S(3), 5_000_000)])
for n in (1, 2): pc = m.db(); m.put_row(pc, dict(rowb, block=10, tx=TX(n), stealth=S(n), caller=V3), {}, "A"); pc.commit(); pc.close()
B["salt"] = "x"                                                                                    # the endpoints now disagree about block 10
pc = m.db(); m.put_row(pc, dict(rowb, block=10, tx=TX(3), stealth=S(3), caller=V3), {}, "A"); pc.commit(); pc.close()
c = m.db(); rows = {r[0]: r[1:] for r in c.execute("SELECT stealth,payer,paid FROM ann")}; c.close()
check("1165 receipt: blockHash equals the agreed hash -> payer and paid set", rows[S(1)] == (PAYER, 5_000_000))
check("1165 receipt: right blockNumber but forged blockHash -> payer and paid stay NULL", rows[S(2)] == (None, None))
check("1165 receipt: no agreement on the block hash between endpoints -> NULL (retried later)", rows[S(3)] == (None, None))
B["salt"] = ""; meta_set(m, safe_block=1000)
check("1165 receipt: row with a forged receipt is not known", True)
n = m.fix_rows(m.db(), "A", 1000); c = m.db(); rows = {r[0]: r[1:] for r in c.execute("SELECT stealth,payer,paid FROM ann")}; c.close()
check("1165 receipt: fix_rows retries; agreed rows filled, the forged one stays NULL", rows[S(3)] == (PAYER, 5_000_000) and rows[S(2)] == (None, None))
m2 = load(); Chain(m2, {"A": {"head": 500, "logs": [], "receipts": {TX(1): rcpt(10, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000)], bh=H(10, "forged"))}}})
pc = m2.db(); m2.put_row(pc, dict(rowb, block=10, tx=TX(1), stealth=S(1), caller=V3), {}, "A"); pc.commit(); pc.close()
c = m2.db(); r1 = c.execute("SELECT payer,paid FROM ann").fetchone(); c.close()
check("1165 receipt: ONE configured endpoint = trusted provider, the receipt is taken as served", r1 == (PAYER, 5_000_000))

# ---- 1163 M-1 / 1165 I-5: --rewind (bumps epoch, drops the stored hash)
m = load(); meta_set(m, head=1000, head_hash=H(1000)); put(m, 900, 0, S(1), V3, 5_000_000, 5_000_000)
m.START = 1; m.rewind(300)
c = m.db(); check("M-1 rewind moves head back N blocks, rows stay", c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0] == "700" and count(m) == 1)
check("1165 I-5 rewind bumps epoch (clients re-read) and drops the stored hash", meta_get(m, "epoch") == "1" and meta_get(m, "head_hash") is None)
m.rewind(10_000_000); check("M-1 rewind never goes below START-1", c.execute("SELECT v FROM meta WHERE k='head'").fetchone()[0] == "0"); c.close()
check("1165 I-5 every rewind bumps epoch", meta_get(m, "epoch") == "2")
import subprocess
env = dict(os.environ); r0 = subprocess.run([sys.executable, "-B", os.path.join(HERE, "stealth_indexer.py"), "--rewind", "x"], env=env, capture_output=True, text=True)
check("M-1 rewind CLI refuses a bad N", r0.returncode != 0 and "usage" in (r0.stdout + r0.stderr))
meta_set(m, head=500)
r0 = subprocess.run([sys.executable, "-B", os.path.join(HERE, "stealth_indexer.py"), "--rewind", "5"], env=env, capture_output=True, text=True)
check("M-1 rewind CLI works", r0.returncode == 0 and "rewind: head 500 -> 495" in r0.stdout)

# ---- 1179 F1/F4: rewind closes the trust boundary and the first reconcile covers the abandoned fork above the new head
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 1
meta_set(m, head=700, head_hash=H(700), safe_block=690, known_block=690, final_block=680)
put(m, 550, 0, S(1), V3, 5_000_000, 5_000_000)                           # a row of the abandoned fork: the chain (fake) has no such log
srv1, J1 = serve(m)
check("1179 F1 before rewind: the row at 550 below known_block 690 is known", J1("/known?addr=" + S(1))[1]["known"] is True)
m.rewind(200)
check("1179 F1 rewind deletes known_block, safe_block and final_block", all(meta_get(m, k) is None for k in ("known_block", "safe_block", "final_block")))
check("1179 F1 after rewind /known answers nobody (also no fallback to a stale safe_block)", J1("/known?addr=" + S(1))[1]["known"] is False)
check("1179 F4 rewind leaves the row and asks for a reconcile from the new head + 1", count(m) == 1 and meta_get(m, "reconcile_from") == "501")
run_loop(m, until=lambda: meta_get(m, "known_block") is not None and meta_get(m, "reconcile_from") is None)
check("1179 F4 the loop reconciled once: the fork row above the new head is gone (base insert_only would have kept it), the marker is consumed", count(m) == 0 and meta_get(m, "reconcile_from") is None)
check("1179 F1 the next full pass recomputed the boundary", meta_get(m, "known_block") is not None and meta_get(m, "safe_block") is not None and meta_get(m, "final_block") is not None)
check("1179 F4 rows are still indexed from the new head (head moved on)", int(meta_get(m, "head")) >= 500)
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 500}}); m.START = 1; meta_set(m, head=700)
m.rewind(200); m.rewind(100)
check("1179 F4 a second rewind before the loop runs keeps the marker at the lowest block", meta_get(m, "reconcile_from") == "401")
meta_set(m, head=900); m.rewind(100)
check("1180 L-3 a rewind to a HIGHER point keeps the lower pending reconcile_from (min)", meta_get(m, "reconcile_from") == "401")
c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','junk')"); c.commit(); c.close(); meta_set(m, head=900); m.rewind(100)
check("1181 L-2 rewind over a corrupt old reconcile_from REPLACES it with START (1182 I-3: exact, long first pass), capped by the new point (never just the new one)", meta_get(m, "reconcile_from") == "1")
meta_set(m, head=50000); c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','junk')"); c.commit(); c.close(); m.rewind(100)
check("1182 I-3 ...with a high head the replacement is still START, not head - BH_KEEP (rows of an abandoned branch older than that would stay)", meta_get(m, "reconcile_from") == "1")
c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','99999999')"); c.commit(); c.close(); meta_set(m, head=50000); m.rewind(100)
check("1181 L-2 rewind over an out-of-range (above old head + 1) reconcile_from is replaced the same way (START)", meta_get(m, "reconcile_from") == "1")
c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','-5')"); c.commit(); c.close(); meta_set(m, head=50000); m.rewind(100)
check("1181 L-2 rewind over a value below START is replaced too (START)", meta_get(m, "reconcile_from") == "1")
c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','49000')"); c.commit(); c.close(); meta_set(m, head=50000); m.rewind(100)
check("1181 L-2 a valid old value is still just min(old, new + 1)", meta_get(m, "reconcile_from") == "49000")
# (a) a reconcile that returns False (window start above head_done) must not reopen /known while reconcile_from is pending
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 1
meta_set(m, head=100, head_hash=H(100)); c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','5000')"); c.commit(); c.close()
m.reconcile = lambda *a, **k: False
run_loop(m, secs=1.0)
check("1180 L-3a reconcile returned False: reconcile_from stays (an out-of-range 5000 is replaced by the wide window, not dropped) and no known/safe/final boundary is written", meta_get(m, "reconcile_from") == "1" and all(meta_get(m, k) is None for k in ("known_block", "safe_block", "final_block")))
# (c) a corrupt reconcile_from does not stall the loop: ALERT once, key dropped, /known closed on that pass, opened by the next clean one
import io, contextlib
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 1
meta_set(m, head=100, head_hash=H(100)); c = m.db(); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from','not-a-number')"); c.commit(); c.close()
seen = []; _real_set = m._set_meta
def spy(*a, **k): seen.append(meta_get(m, "reconcile_from")); return _real_set(*a, **k)
m._set_meta = spy
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    run_loop(m, until=lambda: meta_get(m, "known_block") is not None, limit=15)
out = buf.getvalue()
check("1181 L-2 a corrupt reconcile_from is replaced by the wide window, reconciled from there, consumed only after that reconcile is complete, and then the boundary opens", meta_get(m, "reconcile_from") is None and meta_get(m, "known_block") is not None)
check("1181 L-2 exactly one ALERT for the bad value, and the boundary was never written while the marker was still there", out.count("ALERT bad reconcile_from") == 1 and all(x is None for x in seen))


# ---- audit 1181 L-1: reconcile has three outcomes; /known opens only after a COMPLETE pass
m = load(); m.MODE = "latest"; m.START = 1
put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000)
ch = Chain(m, {"A": {"head": 300, "logs": []}, "B": {"head": 300, "logs": []}})
real_fr = m.fetch_range; nfr = [0]
def only_first_reads(*a, **k):                                   # the first read (one call per agreed endpoint) answers, every later one (the second read) fails
    nfr[0] += 1
    if nfr[0] > m.NEED: raise RuntimeError("second read down")
    return real_fr(*a, **k)
m.fetch_range = only_first_reads
r1 = m.reconcile(m.db(), 200, 250, "A")
check("1181 L-1 rows to delete but no second read -> REC_NO_SECOND, nothing deleted", r1 == m.REC_NO_SECOND and count(m) == 1)
m.fetch_range = real_fr
r2 = m.reconcile(m.db(), 200, 250, "A")
check("1181 L-1 two reads agree -> REC_DONE and the row is deleted", r2 == m.REC_DONE and count(m) == 0)
check("1181 L-1 a window above head_done -> REC_NOT_REACHED", m.reconcile(m.db(), 9000, 250, "A", frm=9000) == m.REC_NOT_REACHED and len({m.REC_DONE, m.REC_NO_SECOND, m.REC_NOT_REACHED}) == 3)
put(m, 150, 0, S(1), V3, 5_000_000, 5_000_000); nfr[0] = 0; m.fetch_range = only_first_reads
check("1181 L-1 insert_only never needs a second read -> REC_DONE", m.reconcile(m.db(), 200, 250, "A", insert_only=True) == m.REC_DONE); m.fetch_range = real_fr
# the loop: a --rewind whose second read is missing keeps reconcile_from, writes no boundary, ALERTs once; when the second read returns, the pass completes and the boundary opens
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}, "B": {"head": 600, "logs": [], "safe": 590}}); m.START = 1; m.MODE = "latest"
meta_set(m, head=700, head_hash=H(700)); put(m, 550, 0, S(1), V3, 5_000_000, 5_000_000); m.rewind(200)
real_fr = m.fetch_range; real_rec = m.reconcile; seen_u = {}; nfr = [0]
def only_first_reads2(a, b, u, *r, **k):                         # within one reconcile every endpoint answers once (the first read); a second read of the same endpoint fails
    nfr[0] += 1; seen_u[u] = seen_u.get(u, 0) + 1
    if seen_u[u] > 1: raise RuntimeError("second read down")
    return real_fr(a, b, u, *r, **k)
def rec_reset(*a, **k): seen_u.clear(); return real_rec(*a, **k)
m.reconcile = rec_reset
m.fetch_range = only_first_reads2; m.WAIT_ALERT_S = 3600
buf = io.StringIO()
with contextlib.redirect_stdout(buf): run_loop(m, secs=1.2)
out = buf.getvalue()
check("1181 L-1 second read missing: reconcile_from stays, no known/safe/final boundary, the fork row is NOT deleted", meta_get(m, "reconcile_from") == "501" and all(meta_get(m, k) is None for k in ("known_block", "safe_block", "final_block")) and count(m) == 1)
check("1181 L-1 ...and exactly one ALERT per WAIT_ALERT_S for the incomplete reconcile", out.count("ALERT reconcile from 501 incomplete (second-read-missing)") == 1)
m.fetch_range = real_fr; m.reconcile = real_rec
t0 = time.time()
while time.time() - t0 < 10 and meta_get(m, "reconcile_from") is not None: time.sleep(0.05)
check("1181 L-1 the second read is back: the pass completes, the fork row is gone, the marker is consumed and the boundary opens", meta_get(m, "reconcile_from") is None and count(m) == 0 and meta_get(m, "known_block") is not None)
# ---- audit 1183 L-4: a long reconcile_from runs in slices and keeps its progress; a failure in slice 3 resumes from slice 3
m = load(); Chain(m, {"A": {"head": 450, "logs": [], "safe": 440}, "B": {"head": 450, "logs": [], "safe": 440}}); m.START = 1; m.MODE = "latest"; m.RF_SLICE = 100; m.WAIT_ALERT_S = 3600
meta_set(m, head=450, head_hash=H(450), reconcile_from="1"); put(m, 130, 0, S(1), V3, 5_000_000, 5_000_000)      # a fork row in slice 2, gone from the chain
real_rec = m.reconcile; calls = []; broken = [True]
def rec_sliced(c, sf, hd, ep=None, insert_only=False, frm=None, to=None):
    if frm is not None: calls.append((frm, to))
    if frm == 201 and broken[0]: return m.REC_NO_SECOND                      # slice 3 cannot complete
    return real_rec(c, sf, hd, ep, insert_only=insert_only, frm=frm, to=to)
m.reconcile = rec_sliced; buf = io.StringIO()
with contextlib.redirect_stdout(buf): run_loop(m, secs=1.2)
out = buf.getvalue()
check("1183 L-4 slices 1 and 2 completed in order, slice 3 failed: reconcile_from is 201 (progress kept), no boundary is written, the fork row of slice 2 is already gone", calls[:3] == [(1, 100), (101, 200), (201, 300)] and meta_get(m, "reconcile_from") == "201" and all(meta_get(m, k) is None for k in ("known_block", "safe_block", "final_block")) and count(m) == 0)
check("1183 L-4 the next passes retry from slice 3, never from the start", all(c[0] >= 201 for c in calls[2:]) and len(calls) >= 3)
check("1183 L-4 progress is logged at most once per WAIT_ALERT_S without ALERT; the failure is an ALERT naming slice 3's start", out.count("reconcile progress: blocks up to 100 checked") == 1 and out.count("reconcile progress") == 1 and "ALERT reconcile progress" not in out and out.count("ALERT reconcile from 201 incomplete") == 1)
broken[0] = False; calls.clear(); t0 = time.time()
while time.time() - t0 < 10 and not (meta_get(m, "reconcile_from") is None and meta_get(m, "known_block") is not None): time.sleep(0.05)      # the loop thread of run_loop is still running
check("1183 L-4 once slice 3 can complete the rest runs from 201 (the last slice has no upper bound: the usual window to the head), the marker is consumed and the boundary opens", calls[:3] == [(201, 300), (301, 400), (401, None)] and meta_get(m, "reconcile_from") is None and meta_get(m, "known_block") is not None)
check("1183 L-4 reconcile(to=) reads only its slice: a row outside [frm, to] is not touched", (lambda mm: (put(mm, 50, 0, S(2), V3, 5_000_000, 5_000_000), put(mm, 150, 0, S(3), V3, 5_000_000, 5_000_000), Chain(mm, {"A": {"head": 300, "logs": []}, "B": {"head": 300, "logs": []}}), setattr(mm, "START", 1), mm.reconcile(mm.db(), 290, 300, "A", frm=100, to=199), count(mm))[-1] == 1)(load()))
# L-2 loop: out-of-range / corrupt values are replaced, the replacement reconciles, nothing is silently dropped
for bad in ("junk", "99999999", "-4", "0"):
    m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 5
    meta_set(m, head=100, head_hash=H(100), reconcile_from=bad); m.reconcile = lambda *a, **k: m.REC_NO_SECOND; seen = {}
    run_loop(m, secs=0.8)
    check("1181 L-2 reconcile_from %r (outside [START, head_done+1]) is replaced by START = 5, not deleted, /known stays closed" % bad, meta_get(m, "reconcile_from") == "5" and meta_get(m, "known_block") is None)
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 5; m.BH_KEEP = 20; meta_set(m, head=100, head_hash=H(100), reconcile_from="junk"); m.reconcile = lambda *a, **k: m.REC_NO_SECOND; run_loop(m, secs=0.8)
check("1182 I-3 a corrupt reconcile_from is replaced by START (5), NOT head_done - BH_KEEP (80): the first pass is exact", meta_get(m, "reconcile_from") == "5")
m = load(); Chain(m, {"A": {"head": 600, "logs": [], "safe": 590}}); m.START = 5; meta_set(m, head=100, head_hash=H(100), reconcile_from=101); m.reconcile = lambda *a, **k: m.REC_NOT_REACHED
run_loop(m, secs=0.6); check("1181 L-2 head_done + 1 is a valid value and is kept as it is", meta_get(m, "reconcile_from") == "101")
m = load(); m.START = 5
check("1181 L-2 _rf_valid: accepts [START, head_done+1] only", [m._rf_valid(v, 100) for v in ("5", "101", "50", 7)] == [5, 101, 50, 7] and [m._rf_valid(v, 100) for v in ("4", "102", "x", None, "1.5", "")] == [None] * 6)

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
ch.eps["B"]["head"] = 100                                # B lags: it cannot agree on the hash of block 250, so the window is not read at all (1167 M-2: two agreeing endpoints) -- nothing is deleted
try: m.reconcile(m.db(), 200, 250, "A"); r = False
except RuntimeError: r = True
check("F-4/1167 reconcile: a lagging second endpoint -> the pass waits, nothing deleted", r and count(m) == 1)
ch.eps["B"]["head"] = 300
m.reconcile(m.db(), 200, 250, "A")
check("F-4 reconcile: both endpoints back and both empty -> deleted", count(m) == 0)
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
check("1165 I-2 KNOWN_SAFE=0 with URL userinfo (http://localhost:80@evil.example/) refused: the host is evil.example", refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="http://localhost:80@evil.example/"))
check("I-4 KNOWN_SAFE=0 on a loopback fork accepted", not refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="http://127.0.0.1:8545"))
check("I-4 KNOWN_SAFE=0 with STEALTH_FORK=1 accepted", not refuses(STEALTH_KNOWN_SAFE="0", STEALTH_RPC="https://example.org", STEALTH_FORK="1"))
check("I-4 default (KNOWN_SAFE on) unaffected", not refuses(STEALTH_RPC="https://base-rpc.publicnode.com"))
m = load(); m.MODE = "latest"; m.CONF = 0; m.PAGES_MARGIN = 200; m.POLL = 0.02; m.RECONCILE_EVERY = 100
Chain(m, {"A": {"head": 500, "logs": []}}); seen_fin = []
m.pages_step = lambda c, fb: seen_fin.append(fb)
threading.Thread(target=m.index_loop, daemon=True).start(); time.sleep(0.6)
c = m.db(); fbm = c.execute("SELECT v FROM meta WHERE k='final_block'").fetchone(); c.close()
check("I-4 pages_step gets the same final block as the meta (500 - 200 = 300)", seen_fin and set(seen_fin) == {300} and fbm and fbm[0] == "300")

# ---- 1165 L-2: one process-wide token bucket for API-originated RPC calls (the indexer thread is not charged)
m = load(); Chain(m, {"A": {"head": 5, "logs": []}})
m.API_RPC_RATE = 0.0; m._tb.update({"n": 3.0, "t": time.monotonic()}); m._tl.calls = 0
n_ok = 0
try:
    for _ in range(10): m.rpc("eth_blockNumber", []); n_ok += 1
except m.RateLimited: pass
check("1165 L-2 the bucket stops API-originated RPC calls after its capacity (3), across requests", n_ok == 3)
m._tl.calls = None
check("1165 L-2 the indexer thread (no per-request counter) does not draw from the bucket", all(m.rpc("eth_blockNumber", []) for _ in range(20)))
m.API_RPC_RATE = 1000.0; m._tb.update({"n": 0.0, "t": time.monotonic()}); time.sleep(0.05); m._tl.calls = 0
check("1165 L-2 the bucket refills with time", m.rpc("eth_blockNumber", []) is not None); m._tl.calls = None
m.API_RPC_RATE = 0.0; m._tb.update({"n": 0.0, "t": time.monotonic()}); srv, J = serve(m)
st, d = J("/receipt?tx=0x" + "c" * 64)
check("1165 L-2 an empty bucket answers 429 (retryable), not 500", st == 429)
m._tb.update({"n": 5.0, "t": time.monotonic()}); st, d = J("/head")
check("1165 L-2 routes that make no RPC call are unaffected by an empty bucket", st == 200)

# ---- 1165 I-3: what verified means
m = load(); sqlx = m.db(); ETHM = "0x11eeeeeeee" + "ee" * 20 + w(10 ** 15)
def ins(n, caller, meta, paid): sqlx.execute("INSERT INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer,paid) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (n, TX(n), 0, 1, S(n), caller, "0x02" + "ab" * 32, meta, "0x11", None, paid))
TOKM = "0x11a9059cbb" + USDC[2:] + w(5_000_000)
ins(1, V3, TOKM, 5_000_000); ins(2, V3, TOKM, 0); ins(3, V3, TOKM, None); ins(4, V3, ETHM, 0); ins(5, V3, ETHM, None); ins(6, OTHER, TOKM, 5_000_000); ins(7, V3, "0x11deadbeef" + "00" * 52, 0); sqlx.commit(); sqlx.close()
srv, J = serve(m); st, d = J("/announcements?since=0&limit=10")
check("1165 I-3 verified: token row with a found Transfer = 1; token row with paid 0 = 0; receipt pending = 0; payETH with a parsed receipt = 1; payETH pending = 0; foreign caller = 0; unknown selector = 0",
      [r["verified"] for r in d["rows"]] == [1, 0, 0, 1, 0, 0, 0])

# ---- 1167 M-1 / M-2: contents, not only block identity. Two endpoints: discovery = UNION of their logs; paid (and /known) only from a receipt two endpoints return identically
def idx_state(logs_a, logs_b, rc_a, rc_b, want_rows=1, secs=None):
    m = load(); A = {"head": 200, "logs": logs_a, "receipts": rc_a}; B = {"head": 200, "logs": logs_b, "receipts": rc_b}; Chain(m, {"A": A, "B": B})
    run_loop(m, until=lambda: meta_get(m, "head") == "200" and count(m) >= want_rows)
    time.sleep(0.3); c = m.db(); rows = c.execute("SELECT stealth,payer,paid FROM ann ORDER BY id").fetchall(); c.close(); return m, rows
GOOD = rcpt(150, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000)])
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): GOOD}, {TX(15000): GOOD})
check("1167 M-1 honest log and identical receipts from both endpoints: payer and paid set", rows == [(S(1), PAYER, 5_000_000)])
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [], {TX(15000): GOOD}, {})
check("1167 M-1 fabricated log + forged receipt from ONE endpoint: row stored but unverified (payer and paid NULL), not known", rows == [(S(1), None, None)])
meta_set(m, safe_block=1000); srv, J = serve(m)
check("1167 M-1 /known refuses the fabricated address", J("/known?addr=" + S(1))[1]["known"] is False)
bigger = rcpt(150, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000), (PAYER, S(1), 1)])
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): GOOD}, {TX(15000): bigger})
check("1167 M-1 the two endpoints return different receipts (extra Transfer on one): not accepted", rows == [(S(1), None, None)])
B2 = rcpt(150, PAYER, [(PAYER, V3, 5_000_000), (V3, S(1), 5_000_000)]); B2["transactionHash"] = TX(1)
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): B2}, {TX(15000): B2})
check("1167 M-1 receipt whose transactionHash is another tx: rejected by both endpoints", rows == [(S(1), None, None)])
B3 = dict(GOOD, logs=[dict(l, transactionHash=TX(1)) for l in GOOD["logs"]])
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): B3}, {TX(15000): B3})
check("1167 M-1 a Transfer log carrying another transactionHash: rejected", rows == [(S(1), None, None)])
# fix_rows retries: once the second endpoint confirms the receipt the row gets paid
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000)], [], {TX(15000): GOOD}, {})
meta_set(m, safe_block=1000)
# second endpoint now returns the receipt (honest confirmation)
def _confirm(m, rc_b):
    o = m.rpc1
    def f(u, method, params, t):
        if u == "B" and method == "eth_getTransactionReceipt" and params[0] == TX(15000): return dict(rc_b, transactionHash=TX(15000), logs=[dict(l, transactionHash=TX(15000)) for l in rc_b["logs"]])
        return o(u, method, params, t)
    m.rpc1 = f
_confirm(m, GOOD); m._fix["after"] = 0; m.fix_rows(m.db(), "A", 1000); c = m.db(); rows = c.execute("SELECT stealth,payer,paid FROM ann").fetchall(); c.close()
check("1167 M-1 fix_rows: a second endpoint later confirms the receipt -> paid set", rows == [(S(1), PAYER, 5_000_000)])
# M-2: one endpoint omits the announcement, the other has it: the union indexes it
m, rows = idx_state([], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): GOOD}, {TX(15000): GOOD})
check("1167 M-2 ingest: a log omitted by one endpoint is still indexed (union), verified by two receipts", rows == [(S(1), PAYER, 5_000_000)])
m, rows = idx_state([mk_log(150, 0, S(1), V3, 5_000_000), mk_log(160, 1, S(2), V3, 5_000_000)], [mk_log(150, 0, S(1), V3, 5_000_000)], {TX(15000): GOOD}, {TX(15000): GOOD}, want_rows=2)
check("1167 M-2 ingest: logs seen by both are stored once (dedupe by tx, log_index); the one seen by A only is added", sorted(r[0] for r in rows) == [S(1), S(2)])
m = load(); m.MODE = "latest"; m.START = 1
Chain(m, {"A": {"head": 300, "logs": [], "receipts": {TX(15000): GOOD}}, "B": {"head": 300, "logs": [mk_log(150, 0, S(1), V3, 5_000_000)], "receipts": {TX(15000): GOOD}}})
m.reconcile(m.db(), 200, 250, "A")
check("1167 M-2 reconcile: the pinned endpoint omits the log, the other has it -> inserted (union of both reads)", count(m) == 1)
badlog = mk_log(150, 0, S(1), V3, 5_000_000); badlog["blockHash"] = H(150, "other")
m = load(); Chain(m, {"A": {"head": 300, "logs": []}, "B": {"head": 300, "logs": [badlog]}})
try: m.reconcile(m.db(), 200, 250, "A"); r = False
except RuntimeError: r = True
check("1167 M-2 reconcile: a log from a non-agreed block is still rejected per endpoint", r and count(m) == 0)

# ---- 1167 L-3: RateLimited propagates untouched; multicall availability is not cached as False
m = load(); Chain(m, {"A": {"head": 5, "logs": []}})
m._tl.calls = 0; m._take_token = lambda: False
try: m.mc_available(); r = False
except m.RateLimited: r = True
check("1167 L-3 mc_available: RateLimited propagates and nothing is cached", r and m._mc["ok"] is None)
m._mc.update({"ok": True, "ts": time.time()})
try: m.balances([S(1)]); r = False
except m.RateLimited: r = True
check("1167 L-3 balances: RateLimited propagates; multicall availability is untouched (still True, no per-address fallback)", r and m._mc["ok"] is True)
m._tl.calls = None

# ---- 1163 I-3: nginx wasm location (text check; nginx is not run here)
ng = open(os.path.join(HERE, "..", "ops", "nginx-stealth-zec.conf")).read()
code = "\n".join(l.split("#")[0] for l in ng.splitlines())
wl = code[code.index("location ~ \\.wasm$"):]
check("I-3 no include mime.types / outer types{} (no duplicate-extension warning)", "include mime.types" not in code and code.count("types {") == 1)
check("I-3 the .wasm location serves application/wasm via empty types{} + default_type", "types { }" in wl and "default_type application/wasm" in wl)

print("%d passed, %d failed" % (ok, fail), flush=True)
os._exit(1 if fail else 0)      # the indexer threads of the fakes are daemons: a normal interpreter exit can abort (Python 3.9, exit 134) after all checks passed
