#!/usr/bin/env python3
"""Stealth: индексатор объявлений ERC-5564 (Base или Robinhood Chain, STEALTH_CHAIN=base|rh) и маленький API для клиента (без ключей, без денег).

Читает события Announcement общего Announcer (0x5564…5564) с блока START в sqlite и отдаёт клиенту пачками; клиент
проверяет каждую запись своим ключом просмотра у себя. Фильтры против спама: только схема 1, эфемерный ключ ровно
33 байта, metadata обрезается до 128 байт. Голова: base -- тег "safe"; rh -- latest минус STEALTH_CONFIRMATIONS блоков
(быстро видно), а раз в RECONCILE_EVERY секунд окно (safe..голова] перечитывается и строки, изменённые реорганизацией,
удаляются/вставляются заново. Одна служба = одна цепь (порт/БД/цепь задаются окружением); конфиг цепей -- chains.json.
API (127.0.0.1:3873, за nginx как /stealth-api/):
  GET /head                                  -> {head, chain_head, lag, count, ts, start}
  GET /announcements?since=<id>&limit=<n>     -> {rows:[{id,block,tx,scheme,stealth,caller,eph,meta,payer}], next}
  Статические страницы истории (nginx, не Python): STEALTH_PAGES_DIR/manifest.json + p<k>.json(.gz), по PAGE_SIZE=1024 строк на страницу
  (id в [k*1024+1, (k+1)*1024]), строка = [id,block,tx,stealth,eph,meta,payer]. Страница пишется только когда полная И все её строки
  не новее "финального" блока (реорг-страж их уже не тронет); /announcements?since=tail_since_id отдаёт только хвост.
  GET /known?addr=0x..                        -> {known: bool}   (объявлено ЧЕРЕЗ наш StealthPay -- payToken или payWithAuthorization, токен цепи >= MIN_KNOWN_USDC)
  GET /balances?addrs=0x..,0x..               -> {addr: {usdc, eth}} (до 100 адресов, Multicall3 + кэш 15 с; usdc = токен цепи)
  GET /receipt?tx=0x..                        -> {status: 1|0|null}
  GET /usdc-domain                            -> {domain_separator, chain, token}
"""
import gzip, json, os, sqlite3, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

CHAIN = os.environ.get("STEALTH_CHAIN", "base").strip().lower()
_CH = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "chains.json")))
if CHAIN not in _CH:
    raise SystemExit("unknown STEALTH_CHAIN %r (have %s)" % (CHAIN, ",".join(_CH)))
CC = _CH[CHAIN]
ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564".lower()
STEALTHPAY = os.environ.get("STEALTHPAY", "").lower()
USDC = CC["token"].lower()                                      # токен цепи (USDC на Base, USDG на RH); имя оставлено для совместимости
MULTICALL3 = CC["multicall3"].lower()
_sb = os.environ.get("STEALTH_START_BLOCK") or CC.get("start_block")
START = int(_sb) if _sb else None                              # None (rh без env) -> при первом запуске head - BACKFILL
BACKFILL = int(os.environ.get("STEALTH_BACKFILL", "200000"))
MODE = os.environ.get("STEALTH_HEAD_MODE", CC["mode"])         # safe | latest
CONF = int(os.environ.get("STEALTH_CONFIRMATIONS", CC["confirmations"]))
RECONCILE_EVERY = int(os.environ.get("STEALTH_RECONCILE_EVERY", "60"))
PAGES_DIR = os.environ.get("STEALTH_PAGES_DIR", "")             # пусто -> страницы не пишем (клиент идёт по старому пути)
PAGE_SIZE = 1024
PAGES_MARGIN = int(os.environ.get("STEALTH_PAGES_MARGIN", "200"))   # rh: финал = safe - MARGIN (> окна реконсиляции safe-100)
DB = os.environ.get("STEALTH_DB", "/opt/stealth/announcements.db")
PORT = int(os.environ.get("STEALTH_PORT", "3873"))
MIN_KNOWN_USDC = int(os.environ.get("MIN_KNOWN_USDC", "100000"))     # $0.10: мельче через релеер не выводим
MAX_META = 128
CHUNK0 = int(os.environ.get("STEALTH_CHUNK", "50000"))
POLL = int(os.environ.get("STEALTH_POLL", "20" if MODE == "safe" else "2"))
CACHE_TTL = float(os.environ.get("STEALTH_BAL_TTL", "15"))
MAX_ADDRS = 100
MAX_THREADS = int(os.environ.get("STEALTH_MAX_THREADS", "64"))
SOCK_TIMEOUT = float(os.environ.get("STEALTH_SOCK_TIMEOUT", "10"))
_env_rpc = [u.strip() for u in os.environ.get("STEALTH_RPC", "").split(",") if u.strip()]
RPCS = _env_rpc or [u for u in [os.environ.get(k) for k in CC["rpc_env"]] + CC["rpcs"] if u]
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


_tl = threading.local()


def rdb():
    """Соединение для чтения API: одно на поток (раньше -- новое на каждый запрос с PRAGMA journal_mode=WAL). WAL уже выставлен init_db."""
    c = getattr(_tl, "c", None)
    if c is None:
        c = _tl.c = sqlite3.connect(DB, timeout=30, check_same_thread=False)
        c.execute("PRAGMA query_only=1")
    return c


_ann_cache = {}                 # (since, limit) -> (ts, body bytes): много клиентов листают одни и те же страницы
_ann_lock = threading.Lock()
ANN_TTL = float(os.environ.get("STEALTH_ANN_TTL", "1.5"))
_count = {"t": 0, "n": 0}       # COUNT(*) на большой таблице дорог: кэш 5 с


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
    b = rpc("eth_getBlockByNumber", ["safe", False], 20)
    return int(b["number"], 16)


def latest_head():
    return int(rpc("eth_blockNumber", [], 20), 16)


def target_head():
    """(голова для индексации, safe или None). rh: latest - CONF; base: safe."""
    if MODE == "safe":
        h = safe_head(); return h, h
    lat = latest_head()
    try: sf = safe_head()
    except Exception: sf = None
    return max(0, lat - CONF), sf


def put_row(c, r, payers):
    if r["tx"] not in payers:
        try:
            txo = rpc("eth_getTransactionByHash", [r["tx"]], 15); payers[r["tx"]] = ((txo or {}).get("from") or "").lower() or None
        except Exception:
            payers[r["tx"]] = None
    with _lock:
        c.execute("INSERT OR IGNORE INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (r["block"], r["tx"], r["log_index"], r["scheme"], r["stealth"], r["caller"], r["eph"], r["meta"], r["view_tag"], payers[r["tx"]]))


def fetch_range(a, b):
    """Все декодированные записи Announcer в [a,b]; getLogs режем пополам, если узел отказывает по размеру."""
    try:
        logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}])
    except Exception:
        if b - a < 1000: raise
        m = (a + b) // 2
        return fetch_range(a, m) + fetch_range(m + 1, b)
    out = []
    for lg in logs:
        try:
            r = decode(lg)
        except Exception as e:
            print("decode skip", lg.get("transactionHash"), str(e)[:80], flush=True); continue
        if r: out.append(r)
    return out


def reconcile(c, sf, head_done):
    """Реорг-страж (rh): перечитать (safe-100 .. head_done], убрать строки, которых в цепи больше нет (или они в другом блоке), добавить новые."""
    a = max(START, (sf or head_done - 10000) - 100)
    if a > head_done: return
    # верхняя граница обязательна: иначе строки новее head_done (их уже записал основной цикл за время getLogs) считались бы "пропавшими" и удалялись
    fresh = fetch_range(a, head_done)
    want = {(r["tx"], r["log_index"], r["block"]): r for r in fresh}
    with _lock:
        have = {(t, li, bl): i for i, t, li, bl in c.execute("SELECT id,tx,log_index,block FROM ann WHERE block>=? AND block<=?", (a, head_done))}
    gone = [i for k, i in have.items() if k not in want]
    if gone:
        with _lock:
            c.executemany("DELETE FROM ann WHERE id=?", [(i,) for i in gone]); c.commit()
        print("reconcile: removed", len(gone), "rows changed by reorg", flush=True)
    new = [r for k, r in want.items() if k not in have]
    payers = {}
    for r in new: put_row(c, r, payers)
    if new:
        with _lock: c.commit()
        print("reconcile: added", len(new), "rows", flush=True)


def _atomic(path, data):
    tmp = path + ".tmp%d" % os.getpid()
    with open(tmp, "wb") as f: f.write(data)
    os.replace(tmp, path)


def _page_name(k): return "p%06d.json" % k


def _write_page(c, k):
    """Записать страницу k (json + json.gz) из БД; вернуть число строк."""
    rows = c.execute("SELECT id,block,tx,stealth,eph,meta,payer FROM ann WHERE id>? AND id<=? ORDER BY id", (k * PAGE_SIZE, (k + 1) * PAGE_SIZE)).fetchall()
    raw = json.dumps([list(r) for r in rows], separators=(",", ":")).encode()
    base = os.path.join(PAGES_DIR, _page_name(k))
    _atomic(base, raw); _atomic(base + ".gz", gzip.compress(raw, 9, mtime=0))
    return len(rows)


def pages_step(c, final_block):
    """Дописать новые полные страницы и перезаписать те, где реорг удалил строку. final_block None -> новых страниц нет."""
    if not PAGES_DIR: return
    os.makedirs(PAGES_DIR, exist_ok=True)
    with _lock:
        g = lambda k: c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        st = json.loads(g("pages")[0]) if g("pages") else {"full": 0, "version": 1, "counts": []}
        full, ver, counts = st["full"], st["version"], st["counts"]
        changed = False
        # 1) уже записанные страницы: число строк должно совпадать (удаление реорга -> перезапись + новая версия)
        if full and c.execute("SELECT COUNT(*) FROM ann WHERE id<=?", (full * PAGE_SIZE,)).fetchone()[0] != sum(counts):
            now = dict(c.execute("SELECT (id-1)/?, COUNT(*) FROM ann WHERE id<=? GROUP BY 1", (PAGE_SIZE, full * PAGE_SIZE)).fetchall())
            bad = [k for k in range(full) if now.get(k, 0) != counts[k]]
            for k in bad: counts[k] = _write_page(c, k)
            if bad: ver += 1; changed = True; print("pages: rewrote", bad, "after reorg, version", ver, flush=True)
        # 2) новые полные финальные страницы
        mx = c.execute("SELECT COALESCE(MAX(id),0) FROM ann").fetchone()[0]
        lim = mx
        if final_block is None: lim = full * PAGE_SIZE
        else:
            u = c.execute("SELECT MIN(id) FROM ann WHERE block>?", (final_block,)).fetchone()[0]
            if u is not None: lim = min(lim, u - 1)
        while (full + 1) * PAGE_SIZE <= lim:
            counts.append(_write_page(c, full)); full += 1; changed = True
        mpath = os.path.join(PAGES_DIR, "manifest.json")
        if changed or not os.path.exists(mpath):
            c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('pages',?)", (json.dumps({"full": full, "version": ver, "counts": counts}),)); c.commit()
            _atomic(mpath, json.dumps({"chain": CHAIN, "full_pages": full, "page_size": PAGE_SIZE, "version": ver, "tail_since_id": full * PAGE_SIZE}, separators=(",", ":")).encode())


def index_loop():
    global START
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='head'").fetchone()
    if START is None:                                       # rh без STEALTH_START_BLOCK: старт = голова - BACKFILL (запомним в БД)
        r0 = c.execute("SELECT v FROM meta WHERE k='start'").fetchone()
        while r0 is None:
            try:
                st0 = max(0, target_head()[0] - BACKFILL)
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('start',?)", (str(st0),)); c.commit(); r0 = (str(st0),)
            except Exception as e:
                print("start block lookup failed:", str(e)[:100], flush=True); time.sleep(5)
        START = int(r0[0])
    head_done = int(row[0]) if row else START - 1
    chunk = CHUNK0
    last_rec = 0
    while True:
        try:
            head, sf = target_head()
            if head < head_done:                            # цепь откатилась глубже нашей головы: перечитаем с новой
                print("chain head went back", head_done, "->", head, flush=True); head_done = head; last_rec = 0
                with _lock: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(head),)); c.commit()
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
                    if r: put_row(c, r, payers)
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
            with _lock:                                     # метка свежести и когда догнали (иначе lag/ts стоят, пока нет новых блоков)
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('ts',?)", (str(int(time.time())),))
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('chain_head',?)", (str(head),)); c.commit()
            if MODE != "safe" and time.time() - last_rec >= RECONCILE_EVERY:
                reconcile(c, sf, head_done); last_rec = time.time()
            pages_step(c, head_done if MODE == "safe" else (sf - PAGES_MARGIN if sf else None))
        except Exception as e:
            print("index error:", str(e)[:200], flush=True)
        time.sleep(POLL)


_bal_cache = {}                 # addr -> (ts, {"usdc","eth"})
_bal_lock = threading.Lock()
_mc = {"ok": None, "ts": 0}     # есть ли код Multicall3 на этой цепи (eth_getCode), перепроверка раз в 10 мин или после сбоя


def _word(x): return x.to_bytes(32, "big")


def mc_encode(addrs):
    """aggregate3([(target,allowFailure,callData)...]): на каждый адрес balanceOf(токен) и Multicall3.getEthBalance."""
    calls = []
    for a in addrs:
        pad = bytes.fromhex(a[2:]).rjust(32, b"\0")
        calls.append((bytes.fromhex(USDC[2:]), bytes.fromhex("70a08231") + pad))
        calls.append((bytes.fromhex(MULTICALL3[2:]), bytes.fromhex("4d2301cc") + pad))
    heads, tails = [], []
    off = 32 * len(calls)
    for tgt, cd in calls:
        pcd = cd + b"\0" * (-len(cd) % 32)
        t = tgt.rjust(32, b"\0") + _word(1) + _word(96) + _word(len(cd)) + pcd
        heads.append(_word(off)); tails.append(t); off += len(t)
    arr = _word(len(calls)) + b"".join(heads) + b"".join(tails)
    return "0x82ad56cb" + (_word(32) + arr).hex()


def mc_decode(hexs, n):
    d = bytes.fromhex(hexs[2:])
    base = int.from_bytes(d[0:32], "big"); cnt = int.from_bytes(d[base:base + 32], "big")
    if cnt != n: raise ValueError("multicall length")
    arr = base + 32; out = []
    for i in range(cnt):
        o = arr + int.from_bytes(d[arr + 32 * i:arr + 32 * i + 32], "big")
        ok = int.from_bytes(d[o:o + 32], "big"); bo = o + int.from_bytes(d[o + 32:o + 64], "big")
        ln = int.from_bytes(d[bo:bo + 32], "big"); out.append((bool(ok), d[bo + 32:bo + 32 + ln]))
    return out


def mc_available():
    if _mc["ok"] is not None and time.time() - _mc["ts"] < 600: return _mc["ok"]
    try:
        _mc["ok"] = len(rpc("eth_getCode", [MULTICALL3, "latest"], 15)) > 4
    except Exception:
        _mc["ok"] = False
    _mc["ts"] = time.time(); return _mc["ok"]


def _fetch_multicall(addrs):
    res = mc_decode(rpc("eth_call", [{"to": MULTICALL3, "data": mc_encode(addrs)}, "latest"], 20), 2 * len(addrs))
    out = {}
    for i, a in enumerate(addrs):
        (ok1, r1), (ok2, r2) = res[2 * i], res[2 * i + 1]
        out[a] = {"usdc": str(int.from_bytes(r1, "big")) if ok1 and r1 else "0", "eth": str(int.from_bytes(r2, "big")) if ok2 and r2 else "0"}
    return out


def _fetch_single(addrs):
    out = {}
    for a in addrs:
        usdc = rpc("eth_call", [{"to": USDC, "data": "0x70a08231" + a[2:].rjust(64, "0")}, "latest"], 15)
        eth = rpc("eth_getBalance", [a, "latest"], 15)
        out[a] = {"usdc": str(int(usdc, 16)) if usdc and usdc != "0x" else "0", "eth": str(int(eth, 16))}
    return out


def balances(addrs):
    now = time.time(); out = {}; miss = []
    with _bal_lock:
        for a in addrs:
            e = _bal_cache.get(a)
            if e and now - e[0] < CACHE_TTL: out[a] = e[1]
            elif a not in miss: miss.append(a)
    if miss:
        fresh = None
        if mc_available():
            try: fresh = _fetch_multicall(miss)
            except Exception as e:
                print("multicall failed, fallback per-call:", str(e)[:100], flush=True); _mc["ok"] = None
        if fresh is None: fresh = _fetch_single(miss)
        with _bal_lock:
            if len(_bal_cache) > 20000: _bal_cache.clear()
            for a, v in fresh.items(): _bal_cache[a] = (now, v)
        out.update(fresh)
    return {a: out[a] for a in addrs}


class BoundedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer с потолком одновременных потоков: сверх MAX_THREADS сразу 503, а не рост потоков до исчерпания памяти."""
    daemon_threads = True
    request_queue_size = 128
    _sem = threading.BoundedSemaphore(MAX_THREADS)
    def process_request(self, request, client_address):
        if not self._sem.acquire(blocking=False):
            try:
                request.settimeout(2); request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 2\r\nConnection: close\r\n\r\n")
            except Exception: pass
            self.shutdown_request(request); return
        super().process_request(request, client_address)
    def handle_error(self, request, client_address):
        import sys
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)): return    # клиент ушёл посреди ответа: не шум в журнале
        super().handle_error(request, client_address)
    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: self._sem.release()


class H(BaseHTTPRequestHandler):
    timeout = SOCK_TIMEOUT          # сокет-таймаут: медленный клиент не держит поток вечно
    def log_message(self, *a): pass
    def _json(self, code, obj):
        self._raw(code, json.dumps(obj, separators=(",", ":")).encode())
    def _raw(self, code, body):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); c = rdb()
        try:
            if u.path.endswith("/head"):
                g = lambda k: c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
                h, ts, ch = g("head"), g("ts"), g("chain_head")
                if time.time() - _count["t"] > 5: _count["n"] = c.execute("SELECT COUNT(*) FROM ann").fetchone()[0]; _count["t"] = time.time()
                n = _count["n"]
                head = int(h[0]) if h else None; chain = int(ch[0]) if ch else None
                return self._json(200, {"head": head, "chain_head": chain, "lag": (chain - head) if (head and chain) else None, "count": n, "ts": int(ts[0]) if ts else None, "start": START, "chain": CHAIN, "chain_id": CC["id"], "mode": MODE, "confirmations": CONF if MODE != "safe" else None})
            if u.path.endswith("/announcements"):
                since = int(q.get("since", ["0"])[0]); limit = max(1, min(2000, int(q.get("limit", ["1000"])[0])))
                key = (since, limit); now = time.time()
                with _ann_lock: hit = _ann_cache.get(key)
                if hit and now - hit[0] < ANN_TTL: return self._raw(200, hit[1])
                rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer FROM ann WHERE id>? ORDER BY id LIMIT ?", (since, limit)).fetchall()
                out = [{"id": r[0], "block": r[1], "tx": r[2], "scheme": r[3], "stealth": r[4], "caller": r[5], "eph": r[6], "meta": r[7], "payer": r[8]} for r in rows]
                body = json.dumps({"rows": out, "next": out[-1]["id"] if out else since}, separators=(",", ":")).encode()
                with _ann_lock:
                    if len(_ann_cache) > 256: _ann_cache.clear()
                    _ann_cache[key] = (now, body)
                return self._raw(200, body)
            if u.path.endswith("/known"):
                addr = (q.get("addr", [""])[0] or "").lower()
                if not (addr.startswith("0x") and len(addr) == 42): return self._json(400, {"error": "addr"})
                rows = c.execute("SELECT caller, meta FROM ann WHERE stealth=?", (addr,)).fetchall()
                ok = False
                for caller, meta in rows:
                    if STEALTHPAY and caller != STEALTHPAY: continue
                    try:
                        m = bytes.fromhex(meta[2:]); amt = int.from_bytes(m[25:57], "big") if len(m) >= 57 else 0
                        tok = "0x" + m[5:25].hex() if len(m) >= 57 and m[1:5] == bytes.fromhex("a9059cbb") else ""   # viewTag|transfer-селектор|токен|сумма (payToken и payWithAuthorization)
                    except Exception:
                        amt, tok = 0, ""
                    if tok == USDC and amt >= MIN_KNOWN_USDC: ok = True; break
                return self._json(200, {"known": ok})
            if u.path.endswith("/balances"):
                addrs = [a.lower() for a in (q.get("addrs", [""])[0] or "").split(",") if a]
                if not addrs or len(addrs) > MAX_ADDRS or any(not (a.startswith("0x") and len(a) == 42) for a in addrs): return self._json(400, {"error": "addrs"})
                return self._json(200, balances(addrs))
            if u.path.endswith("/receipt"):
                tx = (q.get("tx", [""])[0] or "").lower()
                if not (tx.startswith("0x") and len(tx) == 66): return self._json(400, {"error": "tx"})
                rc = rpc("eth_getTransactionReceipt", [tx], 15)
                return self._json(200, {"status": (int(rc["status"], 16) if rc and rc.get("status") else None), "block": int(rc["blockNumber"], 16) if rc else None})
            if u.path.endswith("/usdc-domain"):
                return self._json(200, {"domain_separator": rpc("eth_call", [{"to": USDC, "data": "0x3644e515"}, "latest"], 15), "chain": CHAIN, "token": CC["token"]})
            return self._json(404, {"error": "not found"})
        except ValueError:
            return self._json(400, {"error": "bad parameter"})
        except Exception as e:
            print("api error:", str(e)[:200], flush=True)
            return self._json(500, {"error": "temporarily unavailable"})


if __name__ == "__main__":
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    init_db()
    threading.Thread(target=index_loop, daemon=True).start()
    print("stealth indexer", CHAIN, "mode", MODE, "conf", CONF, "on", PORT, "db", DB, "from block", START if START is not None else "(head-%d)" % BACKFILL, "stealthpay", STEALTHPAY or "(any caller)", flush=True)
    BoundedServer(("127.0.0.1", PORT), H).serve_forever()
