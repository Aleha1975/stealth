#!/usr/bin/env python3
"""Offline test of STEALTHPAY_LEGACY in stealth_indexer.py (no node, no network): payments made through an old StealthPay of the same chain stay
known to /known and get their real payer; unknown callers stay refused; with no legacy list nothing changes. Run: python3 -B server/test_indexer_legacy.py"""
import json, os, sys, tempfile, threading, urllib.request, importlib

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = "0xc1b372731c1ee68ee89f212a05cb8ac9a7929f76"
V3 = "0xc07f54984abda1ef76dab6f602270b76a04e916d"
OTHER = "0x00000000000000000000000000000000000000aa"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
PAYER = "0x00000000000000000000000000000000000000b1"
RELAYER = "0x00000000000000000000000000000000000000b2"
ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond: ok += 1
    else: fail += 1; print("FAIL", name)


def load(legacy):
    tmp = tempfile.mkdtemp()
    os.environ.update({"STEALTH_CHAIN": "base", "STEALTHPAY": V3, "STEALTH_DB": os.path.join(tmp, "a.db"), "STEALTH_START_BLOCK": "1"})
    if legacy: os.environ["STEALTHPAY_LEGACY"] = legacy
    else: os.environ.pop("STEALTHPAY_LEGACY", None)
    sys.path.insert(0, HERE); sys.modules.pop("stealth_indexer", None)
    m = importlib.import_module("stealth_indexer"); m.init_db(); return m


def meta(amount, token=USDC): return "0x11a9059cbb" + token[2:] + "%064x" % amount


def row(m, i, stealth, caller, amount):
    c = m.db(); c.execute("INSERT INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer,paid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          (i, "0x%064x" % i, 0, 1, stealth, caller, "0x02" + "ab" * 32, meta(amount), "0x11", None, amount))       # paid = Transfer из квитанции (audit 1158 F-3): здесь совпадает с объявленным
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('safe_block','1000')"); c.commit(); c.close()


def receipt(frm_tx, transfers, tx):
    return {"from": frm_tx, "transactionHash": tx, "logs": [{"transactionHash": tx, "address": USDC, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + "0" * 24 + a[2:], "0x" + "0" * 24 + b[2:]], "data": "0x"} for a, b in transfers]}


def serve(m):
    srv = m.BoundedServer(("127.0.0.1", 0), m.H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, lambda p: json.load(urllib.request.urlopen("http://127.0.0.1:%d%s" % (srv.server_address[1], p)))


S = lambda n: "0x%040x" % (0xa000 + n)
# 1) with the legacy list: v2, v3 known; other caller and dust refused
m = load(V2)
check("PAY_CALLERS holds v3 and v2", m.PAY_CALLERS == frozenset([V3, V2]))
row(m, 1, S(1), V2, 5_000_000); row(m, 2, S(2), V3, 5_000_000); row(m, 3, S(3), OTHER, 5_000_000); row(m, 4, S(4), V2, 10)
srv, J = serve(m)
check("known: paid through old v2", J("/known?addr=" + S(1))["known"] is True)
check("known: paid through v3", J("/known?addr=" + S(2))["known"] is True)
check("known: unknown caller refused", J("/known?addr=" + S(3))["known"] is False)
check("known: v2 dust below MIN_KNOWN_USDC refused", J("/known?addr=" + S(4))["known"] is False)
check("announcements list the v2 row too", any(r["caller"] == V2 for r in J("/announcements?since=0&limit=10")["rows"]))
srv.shutdown()
# 2) payer: v2 payToken moves tokens payer -> stealth directly (tx.from is the payer's own tx); v3 payWithAuthorization via the contract (tx.from = relayer)
m.rpc = lambda method, params, t=0, **kw: receipt(RELAYER, [(PAYER, V3), (V3, S(2))], params[0]) if params[0].endswith("2".rjust(64, "0")) else receipt(PAYER, [(PAYER, S(1))], params[0])
cache = {}
check("payer of a v2 payment (direct transfer)", m.payer_of({"tx": "0x%064x" % 1, "stealth": S(1), "caller": V2}, cache) == PAYER)
check("payer of a v3 payment (through the contract)", m.payer_of({"tx": "0x%064x" % 2, "stealth": S(2), "caller": V3}, {}) == PAYER)
# 3) without the legacy list the v2 row is NOT known (this is why the Base indexer needs it)
m = load("")
check("no legacy: PAY_CALLERS is v3 only", m.PAY_CALLERS == frozenset([V3]))
row(m, 1, S(1), V2, 5_000_000); row(m, 2, S(2), V3, 5_000_000)
srv, J = serve(m)
check("no legacy: v2 row unknown, v3 known", J("/known?addr=" + S(1))["known"] is False and J("/known?addr=" + S(2))["known"] is True)
srv.shutdown()
# 4) audit 1158 F-2: no STEALTHPAY (or a malformed one) = the indexer refuses to start (it used to accept any caller)
for bad_sp in ("", "0x1234", "0x" + "g" * 40, V3 + "0"):
    os.environ.pop("STEALTHPAY_LEGACY", None); os.environ.update({"STEALTHPAY": bad_sp}); sys.modules.pop("stealth_indexer", None)
    try: importlib.import_module("stealth_indexer"); bad = False
    except SystemExit: bad = True
    check("STEALTHPAY %r refuses to start" % bad_sp[:12], bad)
# 5) a malformed legacy address stops the start
os.environ.update({"STEALTHPAY": V3, "STEALTHPAY_LEGACY": "0x1234"}); sys.modules.pop("stealth_indexer", None)
try: importlib.import_module("stealth_indexer"); bad = False
except SystemExit: bad = True
check("bad legacy address refuses to start", bad)
print("%d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
