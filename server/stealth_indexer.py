#!/usr/bin/env python3
"""Stealth: индексатор объявлений ERC-5564 на Base и маленький API для клиента.

Читает события Announcement общего контракта Announcer (0x5564…5564) с блока START, кладёт в sqlite и отдаёт
клиенту пачками: клиент фильтрует по метке просмотра у себя и сам находит свои платежи (ключи сервер не видит).
API (127.0.0.1:3873, за nginx как /stealth-api/):
  GET /stealth-api/head                       -> {"head": <последний проиндексированный блок>, "count": N, "ts": ...}
  GET /stealth-api/announcements?since=<id>&limit=<n>&view_tag=<hex1>  -> {"rows":[...], "next": <id>}
      view_tag -- необязательный отсев по первому байту metadata (255/256 отсеивается до математики на клиенте).
Денег не трогает. Узел: BASE_LOGS_RPC (dRPC) с запасом publicnode (адресный фильтр там проходит).
"""
import json, os, sqlite3, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564".lower()
TOPIC = "0x5f0eab8057630ba7676c49b4f21a0231414e79474595be8e4c4df8c4e6ebb6c9"   # placeholder, overwritten from chain if wrong
START = int(os.environ.get("STEALTH_START_BLOCK", "31700000"))
DB = os.environ.get("STEALTH_DB", "/opt/stealth/announcements.db")
PORT = int(os.environ.get("STEALTH_PORT", "3873"))
CHUNK = 50_000
POLL = 30
RPCS = [u for u in [os.environ.get("BASE_LOGS_RPC"), os.environ.get("BASE_RPC"), "https://base-rpc.publicnode.com"] if u]
UA = {"Content-Type": "application/json", "User-Agent": "deepyield-stealth/1.0"}


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
    raise RuntimeError("rpc failed: %s" % last)


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.execute("""CREATE TABLE IF NOT EXISTS ann (id INTEGER PRIMARY KEY AUTOINCREMENT, block INTEGER, tx TEXT, log_index INTEGER,
                 scheme INTEGER, stealth TEXT, caller TEXT, eph TEXT, meta TEXT, view_tag TEXT, payer TEXT, UNIQUE(tx, log_index))""")
    try: c.execute("ALTER TABLE ann ADD COLUMN payer TEXT")
    except Exception: pass
    c.execute("CREATE INDEX IF NOT EXISTS ann_block ON ann(block)")
    c.execute("CREATE INDEX IF NOT EXISTS ann_tag ON ann(view_tag)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    return c


def decode(log):
    # Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)
    t = log["topics"]
    scheme = int(t[1], 16); stealth = "0x" + t[2][-40:]; caller = "0x" + t[3][-40:]
    data = bytes.fromhex(log["data"][2:])
    o1 = int.from_bytes(data[0:32], "big"); o2 = int.from_bytes(data[32:64], "big")
    l1 = int.from_bytes(data[o1:o1 + 32], "big"); eph = data[o1 + 32:o1 + 32 + l1]
    l2 = int.from_bytes(data[o2:o2 + 32], "big"); meta = data[o2 + 32:o2 + 32 + l2]
    return {"block": int(log["blockNumber"], 16), "tx": log["transactionHash"], "log_index": int(log["logIndex"], 16),
            "scheme": scheme, "stealth": stealth, "caller": caller, "eph": "0x" + eph.hex(), "meta": "0x" + meta.hex(),
            "view_tag": ("0x%02x" % meta[0]) if meta else None}


def index_loop():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='head'").fetchone()
    head_done = int(row[0]) if row else START - 1
    while True:
        try:
            head = int(rpc("eth_blockNumber", []), 16) - 3          # три блока запаса от реорга
            while head_done < head:
                a = head_done + 1; b = min(a + CHUNK - 1, head)
                logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}])
                for lg in logs:
                    try:
                        r = decode(lg)
                    except Exception as e:
                        print("decode skip", lg.get("transactionHash"), e, flush=True); continue
                    payer = None
                    try:
                        txo = rpc("eth_getTransactionByHash", [r["tx"]]); payer = (txo or {}).get("from")
                    except Exception:
                        pass
                    c.execute("INSERT OR IGNORE INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (r["block"], r["tx"], r["log_index"], r["scheme"], r["stealth"], r["caller"], r["eph"], r["meta"], r["view_tag"], payer))
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(b),))
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('ts',?)", (str(int(time.time())),))
                c.commit()
                head_done = b
                if logs: print("indexed", len(logs), "announcements up to block", b, flush=True)
        except Exception as e:
            print("index error:", str(e)[:200], flush=True)
        time.sleep(POLL)


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
                h = c.execute("SELECT v FROM meta WHERE k='head'").fetchone(); ts = c.execute("SELECT v FROM meta WHERE k='ts'").fetchone()
                n = c.execute("SELECT COUNT(*) FROM ann").fetchone()[0]
                return self._json(200, {"head": int(h[0]) if h else None, "count": n, "ts": int(ts[0]) if ts else None, "start": START})
            if u.path.endswith("/announcements"):
                since = int(q.get("since", ["0"])[0]); limit = max(1, min(5000, int(q.get("limit", ["1000"])[0])))
                tag = (q.get("view_tag", [None])[0] or "").lower() or None
                if tag:
                    rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer FROM ann WHERE id>? AND view_tag=? ORDER BY id LIMIT ?", (since, tag, limit)).fetchall()
                else:
                    rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer FROM ann WHERE id>? ORDER BY id LIMIT ?", (since, limit)).fetchall()
                out = [{"id": r[0], "block": r[1], "tx": r[2], "scheme": r[3], "stealth": r[4], "caller": r[5], "eph": r[6], "meta": r[7], "payer": r[8]} for r in rows]
                return self._json(200, {"rows": out, "next": out[-1]["id"] if out else since})
            return self._json(404, {"error": "not found"})
        except Exception as e:
            return self._json(500, {"error": str(e)[:200]})
        finally:
            c.close()


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    threading.Thread(target=index_loop, daemon=True).start()
    print("stealth indexer on", PORT, "db", DB, "from block", START, flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
