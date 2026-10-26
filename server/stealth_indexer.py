#!/usr/bin/env python3
"""Stealth: индексатор объявлений ERC-5564 на Base и маленький API для клиента (без ключей, без денег).

Читает события Announcement общего Announcer (0x5564…5564) с блока START в sqlite и отдаёт клиенту пачками; клиент
проверяет каждую запись своим ключом просмотра у себя. Фильтры против спама: только схема 1, эфемерный ключ ровно
33 байта, metadata обрезается до 128 байт. Голова берётся по тегу "safe" (реорги Base не заденут).
API (127.0.0.1:3873, за nginx как /stealth-api/):
  GET /head                                  -> {head, chain_head, lag, count, ts, start}
  GET /announcements?since=<id>&limit=<n>     -> {rows:[{id,block,tx,scheme,stealth,caller,eph,meta,payer}], next}
  GET /known?addr=0x..                        -> {known: bool}   (объявлено ЧЕРЕЗ наш StealthPay, USDC >= MIN_KNOWN_USDC)
  GET /balances?addrs=0x..,0x..               -> {addr: {usdc, eth}} (до 50 адресов; чтобы телефон не ходил в публичный узел сам)
  GET /receipt?tx=0x..                        -> {status: 1|0|null}
  GET /usdc-domain                            -> {domain_separator}
"""
import json, os, sqlite3, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564".lower()
STEALTHPAY = os.environ.get("STEALTHPAY", "").lower()
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
START = int(os.environ.get("STEALTH_START_BLOCK", "31700000"))
DB = os.environ.get("STEALTH_DB", "/opt/stealth/announcements.db")
PORT = int(os.environ.get("STEALTH_PORT", "3873"))
MIN_KNOWN_USDC = int(os.environ.get("MIN_KNOWN_USDC", "100000"))     # $0.10: мельче через релеер не выводим
MAX_META = 128
CHUNK0 = 50_000
POLL = 20
RPCS = [u for u in [os.environ.get("BASE_LOGS_RPC"), os.environ.get("BASE_RPC"), "https://base-rpc.publicnode.com"] if u]
UA = {"Content-Type": "application/json", "User-Agent": "deepyield-stealth/1.0"}
_lock = threading.Lock()


def rpc(method, params, timeout=60):
    last = None
    for u in RPCS:
        try:
            req = urllib.request.Request(u, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), UA)
            with urllib.request.urlopen(req, timeout=timeout) as fh:
                d = json.load(fh)
            if "error" in d:
                last = d["error"]; continue
            return d["result"]
        except Exception as e:
            last = e
    raise RuntimeError("rpc failed: %s" % str(last)[:120])


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS ann (id INTEGER PRIMARY KEY AUTOINCREMENT, block INTEGER, tx TEXT, log_index INTEGER,
                 scheme INTEGER, stealth TEXT, caller TEXT, eph TEXT, meta TEXT, view_tag TEXT, payer TEXT, UNIQUE(tx, log_index))""")
    c.execute("CREATE INDEX IF NOT EXISTS ann_block ON ann(block)")
    c.execute("CREATE INDEX IF NOT EXISTS ann_stealth ON ann(stealth)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    c.commit(); c.close()


def decode(log):
    t = log["topics"]
    if len(t) != 4:
        return None
    scheme = int(t[1], 16)
    if scheme != 1:
        return None
    stealth = "0x" + t[2][-40:]; caller = "0x" + t[3][-40:]
    data = bytes.fromhex(log["data"][2:])
    o1 = int.from_bytes(data[0:32], "big"); o2 = int.from_bytes(data[32:64], "big")
    l1 = int.from_bytes(data[o1:o1 + 32], "big"); eph = data[o1 + 32:o1 + 32 + l1]
    l2 = int.from_bytes(data[o2:o2 + 32], "big"); meta = data[o2 + 32:o2 + 32 + l2]
    if len(eph) != 33 or eph[0] not in (2, 3):
        return None
    meta = meta[:MAX_META]
    tx = log["transactionHash"]
    if not (isinstance(tx, str) and len(tx) == 66):
        return None
    return {"block": int(log["blockNumber"], 16), "tx": tx.lower(), "log_index": int(log["logIndex"], 16), "scheme": scheme,
            "stealth": stealth.lower(), "caller": caller.lower(), "eph": "0x" + eph.hex(), "meta": "0x" + meta.hex(),
            "view_tag": ("0x%02x" % meta[0]) if meta else None}


def safe_head():
    b = rpc("eth_getBlockByNumber", ["safe", False])
    return int(b["number"], 16)


def index_loop():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='head'").fetchone()
    head_done = int(row[0]) if row else START - 1
    chunk = CHUNK0
    while True:
        try:
            head = safe_head()
            while head_done < head:
                a = head_done + 1; b = min(a + chunk - 1, head)
                try:
                    logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}])
                except Exception as e:
                    if chunk > 1000:
                        chunk //= 2; print("getLogs failed, chunk ->", chunk, str(e)[:80], flush=True); continue
                    raise
                payers = {}
                for lg in logs:
                    r = None
                    try:
                        r = decode(lg)
                    except Exception as e:
                        print("decode skip", lg.get("transactionHash"), str(e)[:80], flush=True)
                    if not r:
                        continue
                    if r["tx"] not in payers:
                        try:
                            txo = rpc("eth_getTransactionByHash", [r["tx"]]); payers[r["tx"]] = ((txo or {}).get("from") or "").lower() or None
                        except Exception:
                            payers[r["tx"]] = None
                    with _lock:
                        c.execute("INSERT OR IGNORE INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                  (r["block"], r["tx"], r["log_index"], r["scheme"], r["stealth"], r["caller"], r["eph"], r["meta"], r["view_tag"], payers[r["tx"]]))
                with _lock:
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(b),))
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('ts',?)", (str(int(time.time())),))
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('chain_head',?)", (str(head),))
                    c.commit()
                head_done = b
                if chunk < CHUNK0:
                    chunk = min(CHUNK0, chunk * 2)
                if logs:
                    print("indexed", len(logs), "announcements up to block", b, flush=True)
        except Exception as e:
            print("index error:", str(e)[:200], flush=True)
        time.sleep(POLL)


def balances(addrs):
    out = {}
    for a in addrs:
        usdc = rpc("eth_call", [{"to": USDC, "data": "0x70a08231" + a[2:].rjust(64, "0")}, "latest"])
        eth = rpc("eth_getBalance", [a, "latest"])
        out[a] = {"usdc": str(int(usdc, 16)) if usdc and usdc != "0x" else "0", "eth": str(int(eth, 16))}
    return out


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); c = db()
        try:
            if u.path.endswith("/head"):
                g = lambda k: c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
                h, ts, ch = g("head"), g("ts"), g("chain_head")
                n = c.execute("SELECT COUNT(*) FROM ann").fetchone()[0]
                head = int(h[0]) if h else None; chain = int(ch[0]) if ch else None
                return self._json(200, {"head": head, "chain_head": chain, "lag": (chain - head) if (head and chain) else None, "count": n, "ts": int(ts[0]) if ts else None, "start": START})
            if u.path.endswith("/announcements"):
                since = int(q.get("since", ["0"])[0]); limit = max(1, min(2000, int(q.get("limit", ["1000"])[0])))
                rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer FROM ann WHERE id>? ORDER BY id LIMIT ?", (since, limit)).fetchall()
                out = [{"id": r[0], "block": r[1], "tx": r[2], "scheme": r[3], "stealth": r[4], "caller": r[5], "eph": r[6], "meta": r[7], "payer": r[8]} for r in rows]
                return self._json(200, {"rows": out, "next": out[-1]["id"] if out else since})
            if u.path.endswith("/known"):
                addr = (q.get("addr", [""])[0] or "").lower()
                if not (addr.startswith("0x") and len(addr) == 42): return self._json(400, {"error": "addr"})
                rows = c.execute("SELECT caller, meta FROM ann WHERE stealth=?", (addr,)).fetchall()
                ok = False
                for caller, meta in rows:
                    if STEALTHPAY and caller != STEALTHPAY: continue
                    try:
                        m = bytes.fromhex(meta[2:]); amt = int.from_bytes(m[25:57], "big") if len(m) >= 57 else 0
                        tok = "0x" + m[5:25].hex() if len(m) >= 57 else ""
                    except Exception:
                        amt, tok = 0, ""
                    if tok == USDC and amt >= MIN_KNOWN_USDC: ok = True; break
                return self._json(200, {"known": ok})
            if u.path.endswith("/balances"):
                addrs = [a.lower() for a in (q.get("addrs", [""])[0] or "").split(",") if a]
                if not addrs or len(addrs) > 50 or any(not (a.startswith("0x") and len(a) == 42) for a in addrs): return self._json(400, {"error": "addrs"})
                return self._json(200, balances(addrs))
            if u.path.endswith("/receipt"):
                tx = (q.get("tx", [""])[0] or "").lower()
                if not (tx.startswith("0x") and len(tx) == 66): return self._json(400, {"error": "tx"})
                rc = rpc("eth_getTransactionReceipt", [tx])
                return self._json(200, {"status": (int(rc["status"], 16) if rc and rc.get("status") else None), "block": int(rc["blockNumber"], 16) if rc else None})
            if u.path.endswith("/usdc-domain"):
                return self._json(200, {"domain_separator": rpc("eth_call", [{"to": USDC, "data": "0x3644e515"}, "latest"])})
            return self._json(404, {"error": "not found"})
        except ValueError:
            return self._json(400, {"error": "bad parameter"})
        except Exception as e:
            print("api error:", str(e)[:200], flush=True)
            return self._json(500, {"error": "temporarily unavailable"})
        finally:
            c.close()


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    init_db()
    threading.Thread(target=index_loop, daemon=True).start()
    print("stealth indexer on", PORT, "db", DB, "from block", START, "stealthpay", STEALTHPAY or "(any caller)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
