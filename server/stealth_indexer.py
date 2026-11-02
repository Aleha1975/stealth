#!/usr/bin/env python3
"""Stealth: индексатор объявлений ERC-5564 (Base или Robinhood Chain, STEALTH_CHAIN=base|rh) и маленький API для клиента (без ключей, без денег).

Читает события Announcement общего Announcer (0x5564…5564) с блока START в sqlite и отдаёт клиенту пачками; клиент
проверяет каждую запись своим ключом просмотра у себя. Фильтры против спама: только схема 1, эфемерный ключ ровно
33 байта, metadata обрезается до 128 байт. Голова: base -- тег "safe"; rh -- latest минус STEALTH_CONFIRMATIONS блоков
(быстро видно), а раз в RECONCILE_EVERY секунд окно (safe..голова] перечитывается и строки, изменённые реорганизацией,
удаляются/вставляются заново. Одна служба = одна цепь (порт/БД/цепь задаются окружением); конфиг цепей -- chains.json.
API (127.0.0.1:3873, за nginx как /stealth-api/):
  GET /head                                  -> {head, chain_head, lag, count, ts, start, final_block, safe_block, epoch}   (epoch растёт, когда реорг/откат цепи убрал строки: клиент, державший старые, перечитывает)
  GET /announcements?since=<id>&limit=<n>     -> {rows:[{id,block,tx,scheme,stealth,caller,eph,meta,payer,final}], next, final_block, epoch}   (final = block <= final_block: строку реорг уже не уберёт)
  Статические страницы истории (nginx, не Python): STEALTH_PAGES_DIR/manifest.json + p<k>.json(.gz), по PAGE_SIZE=1024 строк на страницу
  (id в [k*1024+1, (k+1)*1024]), строка = [id,block,tx,stealth,eph,meta,payer]. Страница пишется только когда полная И все её строки
  не новее "финального" блока (реорг-страж их уже не тронет); /announcements?since=tail_since_id отдаёт только хвост.
  GET /known?addr=0x..                        -> {known: bool}   (объявлено ЧЕРЕЗ наш StealthPay или через один из STEALTHPAY_LEGACY -- payToken или payWithAuthorization, токен цепи >= MIN_KNOWN_USDC И в квитанции есть Transfer токена на stealth-адрес >= MIN_KNOWN_USDC, строка не новее safe-блока)
  GET /balances?addrs=0x..,0x..               -> {addr: {usdc, eth}} (до 100 адресов, Multicall3 + кэш 15 с; usdc = токен цепи)
  GET /receipt?tx=0x..                        -> {status: 1|0|null}
  GET /usdc-domain                            -> {domain_separator, chain, token}
"""
import gzip, json, os, re, socket, sqlite3, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

CHAIN = os.environ.get("STEALTH_CHAIN", "base").strip().lower()
_CH = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "chains.json")))
if CHAIN not in _CH:
    raise SystemExit("unknown STEALTH_CHAIN %r (have %s)" % (CHAIN, ",".join(_CH)))
CC = _CH[CHAIN]
ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564".lower()
_ADDR = re.compile(r"^0x[0-9a-f]{40}$"); _TXH = re.compile(r"^0x[0-9a-f]{64}$"); _UINT = re.compile(r"^[0-9]{1,18}$")     # строго: только маленькие буквы после lower(), ни пробелов, ни "_"
STEALTHPAY = os.environ.get("STEALTHPAY", "").strip().lower()
if not _ADDR.match(STEALTHPAY):         # аудит 1158 F-2: без адреса фильтр caller молча выключался -> /known признавал бы любое объявление с нужной metadata
    raise SystemExit("STEALTHPAY: set a valid 0x address (got %r)" % STEALTHPAY[:12])
# Прежние StealthPay той же цепи (через запятую): их платежи остаются «нашими» -- /known их признаёт (релеер выводит с таких адресов), payer считается так же.
# Индексатор и так читает ВСЕ объявления общего Announcer с START, так что строки старого контракта в БД есть; здесь только признание их платежами через Stealth.
LEGACY = [a.strip().lower() for a in os.environ.get("STEALTHPAY_LEGACY", "").split(",") if a.strip()]
for _a in LEGACY:
    if not _ADDR.match(_a):
        raise SystemExit("STEALTHPAY_LEGACY: bad address %r" % _a)
PAY_CALLERS = frozenset([STEALTHPAY] + LEGACY)
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
KNOWN_SAFE = os.environ.get("STEALTH_KNOWN_SAFE", "1") != "0"     # 0 -- ТОЛЬКО лаборатория/форк (у anvil тег safe не движется): /known верит строкам до проиндексированной головы, а не до safe
MAX_META = 128
CHUNK0 = int(os.environ.get("STEALTH_CHUNK", "50000"))
POLL = int(os.environ.get("STEALTH_POLL", "20" if MODE == "safe" else "2"))
CACHE_TTL = float(os.environ.get("STEALTH_BAL_TTL", "15"))
MAX_ADDRS = 100
MAX_THREADS = int(os.environ.get("STEALTH_MAX_THREADS", "64"))
SOCK_TIMEOUT = float(os.environ.get("STEALTH_SOCK_TIMEOUT", "10"))
REQ_DEADLINE = float(os.environ.get("STEALTH_REQ_DEADLINE", "30"))   # весь запрос целиком (аудит 1158 F-7); самый долгий законный вызов -- мультикол 20 с
ANN_CACHE_BYTES = int(os.environ.get("STEALTH_ANN_CACHE_BYTES", str(16 << 20)))   # аудит 1158 F-5: ~12 полных ответов по 1.3 МБ; раньше 256 записей = 300+ МБ
_env_rpc = [u.strip() for u in os.environ.get("STEALTH_RPC", "").split(",") if u.strip()]
RPCS = _env_rpc or [u for u in [os.environ.get(k) for k in CC["rpc_env"]] + CC["rpcs"] if u]
UA = {"Content-Type": "application/json", "User-Agent": "deepyield-stealth/1.0"}
_lock = threading.Lock()


def rpc1(u, method, params, timeout):
    req = urllib.request.Request(u, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), UA)
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        d = json.load(fh)
    if "error" in d: raise RuntimeError(str(d["error"])[:120])
    return d["result"]


_rot = 0                        # с какой точки начинать: сдвигается после сбоя итерации, чтобы одна больная первая точка не держала индексатор


def rpc(method, params, timeout=60, only=None):
    """Первый ответивший узел; only=<url> -- ТОЛЬКО эта точка (закрепление: голова и логи одного узла, аудит 1158 F-1). В потоке API есть общий срок запроса _tl.dl."""
    last = None
    for u in ([only] if only else RPCS):
        t = timeout
        dl = getattr(_tl, "dl", None)
        if dl is not None:
            if dl - time.time() <= 0: raise RuntimeError("request deadline")
            t = min(timeout, dl - time.time())
        try:
            return rpc1(u, method, params, t)
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


_ann_cache = {}                 # (since, limit) -> (ts, body bytes): много клиентов листают одни и те же страницы. Только канонические ключи и потолок по БАЙТАМ (аудит 1158 F-5)
_ann_lock = threading.Lock()
_ann_size = [0]                 # байт в _ann_cache
_small = {}                     # кэш /receipt и /usdc-domain: key -> (ts, obj)
ANN_TTL = float(os.environ.get("STEALTH_ANN_TTL", "1.5"))
_count = {"t": 0, "n": 0}       # COUNT(*) на большой таблице дорог: кэш 5 с


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS ann (id INTEGER PRIMARY KEY AUTOINCREMENT, block INTEGER, tx TEXT, log_index INTEGER,
                 scheme INTEGER, stealth TEXT, caller TEXT, eph TEXT, meta TEXT, view_tag TEXT, payer TEXT, paid INTEGER, UNIQUE(tx, log_index))""")
    if "paid" not in [r[1] for r in c.execute("PRAGMA table_info(ann)")]:       # миграция старой БД: paid = Transfer токена на stealth из квитанции (NULL -> ещё не проверено; цикл fix_rows заполнит)
        c.execute("ALTER TABLE ann ADD COLUMN paid INTEGER")
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


def safe_head(u=None):
    b = rpc("eth_getBlockByNumber", ["safe", False], 20, only=u)
    return int(b["number"], 16)


def latest_head(u=None):
    return int(rpc("eth_blockNumber", [], 20, only=u), 16)


def target_head(u=None):
    """(голова для индексации, safe или None). rh: latest - CONF; base: safe. u -- закрепить за одной точкой."""
    if MODE == "safe":
        h = safe_head(u); return h, h
    lat = latest_head(u)
    try: sf = safe_head(u)
    except Exception: sf = None
    return max(0, lat - CONF), sf


def pick_head(head_done, best=False):
    """(точка, голова, safe) -- первая точка, ЧЬЯ голова не ниже head_done (аудит 1158 F-1: логи потом читаются у неё же, отстающий узел не двигает head_done дальше своей головы).
    best=True (раз в RECONCILE_EVERY): опросить все точки и взять с самой высокой головой -- иначе устойчиво отстающая, но «не ниже head_done» точка держала бы индекс позади остальных.
    Все ответившие ниже head_done -> откат цепи, но только если ответили >= 2 точек (или единственная): одна отставшая не «откатывает» индекс."""
    seen = []
    for u in RPCS[_rot:] + RPCS[:_rot]:
        try: h, sf = target_head(u)
        except Exception: continue
        if h >= head_done and not best: return u, h, sf
        seen.append((h, u, sf))
    if seen and (best or len(seen) >= min(2, len(RPCS))):
        h, u, sf = max(seen, key=lambda t: t[0])
        if h >= head_done or len(seen) >= min(2, len(RPCS)): return u, h, sf
    raise RuntimeError("no endpoint with head >= %d (answered %d of %d)" % (head_done, len(seen), len(RPCS)))


TRANSFER_T = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
PAID_CAP = 1 << 62              # sqlite INTEGER = int64: сумма Transfer зажата, чтобы не переполнить колонку (порог $0.10 = 1e5, запас огромный)


def _real_payer(rc, stealth):
    """Настоящий плательщик по квитанции. Токеновый платёж через StealthPay: payWithAuthorization (газless, tx.from = релеер) -> Transfer токена
    на контракт StealthPay, from = плательщик; payToken -> Transfer токена прямо на stealth-адрес (from = плательщик). payETH/нет логов -> tx.from."""
    tx_from = (rc.get("from") or "").lower() or None
    to_sp = to_st = None
    for lg in rc.get("logs") or []:
        t = lg.get("topics") or []
        if (lg.get("address") or "").lower() != USDC or len(t) != 3 or t[0].lower() != TRANSFER_T: continue
        frm, to = "0x" + t[1][-40:].lower(), "0x" + t[2][-40:].lower()
        if to in PAY_CALLERS and to_sp is None: to_sp = frm
        elif to == stealth and frm not in PAY_CALLERS and to_st is None: to_st = frm
    return to_sp or to_st or tx_from


def _paid_to(rc, stealth):
    """Аудит 1158 F-3: сколько токена цепи РЕАЛЬНО пришло на stealth-адрес в этой транзакции (сумма Transfer(to=stealth) из квитанции), а не что объявлено в metadata."""
    tot = 0
    for lg in rc.get("logs") or []:
        t = lg.get("topics") or []
        if (lg.get("address") or "").lower() != USDC or len(t) != 3 or t[0].lower() != TRANSFER_T or "0x" + t[2][-40:].lower() != stealth: continue
        try: tot += int(lg.get("data") or "0x0", 16)
        except ValueError: pass
    return min(tot, PAID_CAP)


def receipt_of(r, cache, ep=None):
    """Квитанция tx (один eth_getTransactionReceipt на tx в cache). Сначала закреплённая точка (та же, что дала лог), затем любая. None = не получили ИЛИ квитанция из другого блока
    (реорг/отстающий узел) -- строка останется с payer/paid NULL и будет дозаполнена fix_rows, а не «навсегда NULL» (аудит 1158 F-4)."""
    if r["tx"] in cache: return cache[r["tx"]]
    rc = None
    for o in ([ep, None] if ep else [None]):
        try: rc = rpc("eth_getTransactionReceipt", [r["tx"]], 15, only=o) or None
        except Exception: rc = None
        if rc and r.get("block") is not None and rc.get("blockNumber") and int(rc["blockNumber"], 16) != r["block"]: rc = None
        if rc: break
    cache[r["tx"]] = rc
    return rc


def _payer_from(r, rc):
    if not rc: return None
    if r["caller"] in PAY_CALLERS: return _real_payer(rc, r["stealth"])
    return (rc.get("from") or "").lower() or None


def payer_of(r, cache, ep=None):
    """cache: tx -> квитанция. Для анонсов не от StealthPay - tx.from через ту же квитанцию."""
    return _payer_from(r, receipt_of(r, cache, ep))


def put_row(c, r, payers, ep=None):
    rc = receipt_of(r, payers, ep)
    payer = _payer_from(r, rc); paid = _paid_to(rc, r["stealth"]) if rc else None
    with _lock:
        c.execute("INSERT OR IGNORE INTO ann(block,tx,log_index,scheme,stealth,caller,eph,meta,view_tag,payer,paid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (r["block"], r["tx"], r["log_index"], r["scheme"], r["stealth"], r["caller"], r["eph"], r["meta"], r["view_tag"], payer, paid))


def _meta_get(c, k):
    r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else None


def _save_pages(c, st):
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('pages',?)", (json.dumps(st),)); c.commit()
    _atomic(os.path.join(PAGES_DIR, "manifest.json"), json.dumps({"chain": CHAIN, "full_pages": st["full"], "page_size": PAGE_SIZE, "version": st["version"], "tail_since_id": st["full"] * PAGE_SIZE}, separators=(",", ":")).encode())


def _rewrite_pages(c, ids):
    """Строка уже записанной страницы изменилась (дозаполнен payer) -> перезаписать страницу и поднять версию манифеста (клиент перекачает по ?v=)."""
    if not PAGES_DIR or not ids: return
    with _lock:
        v = _meta_get(c, "pages")
        if not v: return
        st = json.loads(v); ks = sorted({(i - 1) // PAGE_SIZE for i in ids if (i - 1) // PAGE_SIZE < st["full"]})
        if not ks: return
        for k in ks: st["counts"][k] = _write_page(c, k)
        st["version"] += 1; _save_pages(c, st)


_fix = {"after": 0}
FIX_BATCH = 50                  # квитанций за цикл (потолок RPC на дозаполнение; кольцом по id, больные строки не занимают окно вечно)


def fix_rows(c, ep, upto):
    """Дозаполнить строки до блока upto: payer IS NULL (квитанция тогда не пришла) и paid IS NULL у объявлений через наш StealthPay (старые БД после миграции). Круговой курсор по id."""
    pc = tuple(PAY_CALLERS)
    with _lock:
        rows = c.execute("SELECT id,tx,stealth,caller,block,payer FROM ann WHERE id>? AND block<=? AND (payer IS NULL OR (paid IS NULL AND caller IN (%s))) ORDER BY id LIMIT ?" % ",".join("?" * len(pc)),
                         (_fix["after"], upto) + pc + (FIX_BATCH,)).fetchall()
    if not rows: _fix["after"] = 0; return 0
    _fix["after"] = rows[-1][0]
    cache = {}; changed = []; n = 0
    for id_, tx, stealth, caller, block, old in rows:
        r = {"tx": tx, "stealth": stealth, "caller": caller, "block": block}
        rc = receipt_of(r, cache, ep)
        if not rc: continue
        payer = _payer_from(r, rc); n += 1
        with _lock: c.execute("UPDATE ann SET payer=COALESCE(?,payer), paid=? WHERE id=?", (payer, _paid_to(rc, stealth), id_))
        if payer != old: changed.append(id_)
    with _lock: c.commit()
    _rewrite_pages(c, changed)
    if n: print("fix_rows: filled", n, "rows", flush=True)
    return n


def refill_payers():
    """Одноразово (--refill-payers / --backfill-paid): пересчитать payer и paid у строк нашего StealthPay (и у любых с payer NULL), затем перезаписать страницы и поднять версию манифеста."""
    c = db(); cache = {}; n = ch = 0
    q = "SELECT id,tx,stealth,caller,payer,block FROM ann WHERE caller IN (%s) OR payer IS NULL ORDER BY id" % ",".join("?" * len(PAY_CALLERS))
    for id_, tx, stealth, caller, old, block in c.execute(q, tuple(PAY_CALLERS)).fetchall():
        r = {"tx": tx, "stealth": stealth, "caller": caller, "block": block}
        rc = receipt_of(r, cache)
        if not rc: continue
        new = _payer_from(r, rc); n += 1
        c.execute("UPDATE ann SET payer=COALESCE(?,payer), paid=? WHERE id=?", (new, _paid_to(rc, stealth), id_))
        if new and new != old: ch += 1
        if len(cache) > 500: cache.clear()
    c.commit()
    if PAGES_DIR and c.execute("SELECT v FROM meta WHERE k='pages'").fetchone():
        st = json.loads(c.execute("SELECT v FROM meta WHERE k='pages'").fetchone()[0])
        for k in range(st["full"]): st["counts"][k] = _write_page(c, k)
        st["version"] += 1; _save_pages(c, st)
        print("pages rewritten:", st["full"], "version", st["version"], flush=True)
    print("refill-payers: checked", n, "changed", ch, flush=True)


def fetch_range(a, b, ep=None):
    """Все декодированные записи Announcer в [a,b]; getLogs режем пополам, если узел отказывает по размеру. ep -- закреплённая точка."""
    try:
        logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}], only=ep)
    except Exception:
        if b - a < 1000: raise
        m = (a + b) // 2
        return fetch_range(a, m, ep) + fetch_range(m + 1, b, ep)
    out = []
    for lg in logs:
        try:
            r = decode(lg)
        except Exception as e:
            print("decode skip", lg.get("transactionHash"), str(e)[:80], flush=True); continue
        if r: out.append(r)
    return out


def _bump_epoch(c):
    with _lock:
        c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('epoch',?)", (str(int(_meta_get(c, "epoch") or 0) + 1),)); c.commit()


def reconcile(c, sf, head_done, ep=None, insert_only=False):
    """Реорг-страж (rh): перечитать (safe-100 .. head_done], убрать строки, которых в цепи больше нет (или они в другом блоке), добавить новые.
    Аудит 1158 F-4: удаляем ТОЛЬКО то, чего нет в двух чтениях (закреплённая точка + другая, чья голова покрывает окно; нет другой -- та же ещё раз); короткий/отстающий ответ строки не стирает.
    insert_only (base, режим safe: реорга ниже safe нет) -- только добавляем пропущенное."""
    a = max(START, (sf or head_done - 10000) - 100)
    if a > head_done: return
    # верхняя граница обязательна: иначе строки новее head_done (их уже записал основной цикл за время getLogs) считались бы "пропавшими" и удалялись
    fresh = fetch_range(a, head_done, ep)
    want = {(r["tx"], r["log_index"], r["block"]): r for r in fresh}
    with _lock:
        have = {(t, li, bl): i for i, t, li, bl in c.execute("SELECT id,tx,log_index,block FROM ann WHERE block>=? AND block<=?", (a, head_done))}
    gone = {k: i for k, i in have.items() if k not in want}
    if gone and not insert_only:
        second = [u for u in RPCS if u != ep]
        for u in second + [ep]:
            if u is None: continue
            try:
                if u != ep and latest_head(u) < head_done: continue          # у этой точки голова не покрывает окно -- её «нет» ничего не значит
                want2 = {(r["tx"], r["log_index"], r["block"]) for r in fetch_range(a, head_done, u)}
            except Exception: continue
            gone = {k: i for k, i in gone.items() if k not in want2}; break
        else: gone = {}                                                       # второго чтения не получили -> не удаляем
        if gone:
            with _lock:
                c.executemany("DELETE FROM ann WHERE id=?", [(i,) for i in gone.values()]); c.commit()
            _bump_epoch(c)
            print("reconcile: removed", len(gone), "rows changed by reorg (two reads agree)", flush=True)
    new = [r for k, r in want.items() if k not in have]
    payers = {}
    for r in new: put_row(c, r, payers, ep)
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
            _save_pages(c, {"full": full, "version": ver, "counts": counts})


def _set_meta(c, **kv):
    with _lock:
        for k, v in kv.items():
            if v is not None: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, str(v)))
        c.commit()


def index_loop():
    global START, _rot
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
            ep, head, sf = pick_head(head_done, time.time() - last_rec >= RECONCILE_EVERY)   # голова и логи -- с ОДНОЙ точки (аудит 1158 F-1)
            if head < head_done:                            # цепь откатилась глубже нашей головы (подтвердили >= 2 точки): перечитаем с новой
                print("chain head went back", head_done, "->", head, flush=True); head_done = head; last_rec = 0
                with _lock: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(head),)); c.commit()
            while head_done < head:
                a = head_done + 1; b = min(a + chunk - 1, head)
                try:
                    logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}], only=ep)
                    if any(not (a <= int(lg["blockNumber"], 16) <= b) for lg in logs): raise RuntimeError("getLogs returned a block outside [%d,%d]" % (a, b))
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
                    if r: put_row(c, r, payers, ep)
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
            # safe_block -- до него /known верит строкам; final_block -- после него строку реорг уже не тронет (флаг final, страницы). Без safe (rh, узел не отдал) прежние значения остаются.
            safe_b = head_done if (MODE == "safe" or not KNOWN_SAFE) else (min(sf, head_done) if sf is not None else None)
            _set_meta(c, safe_block=safe_b, final_block=(head_done if MODE == "safe" else (max(0, safe_b - PAGES_MARGIN) if safe_b is not None else None)))
            if time.time() - last_rec >= RECONCILE_EVERY:
                reconcile(c, sf, head_done, ep, insert_only=(MODE == "safe")); last_rec = time.time()
            fix_rows(c, ep, head_done)
            pages_step(c, head_done if MODE == "safe" else (sf - PAGES_MARGIN if sf else None))
        except Exception as e:
            print("index error:", str(e)[:200], flush=True)
            _rot = (_rot + 1) % max(1, len(RPCS))          # следующая итерация начнёт с другой точки
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
            try: fresh = _fetch_multicall(miss)         # адреса уже проверены строгим hex в do_GET: ошибка здесь -- сбой узла, а не ввод клиента (аудит 1158 F-6)
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
        try: super().process_request(request, client_address)
        except BaseException:                       # Thread.start не удался (нет ресурсов): поток не запущен, значит и release из process_request_thread не придёт (аудит 1158 F-7)
            self._sem.release(); self.shutdown_request(request); raise
    def handle_error(self, request, client_address):
        import sys
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)): return    # клиент ушёл посреди ответа: не шум в журнале
        super().handle_error(request, client_address)
    def process_request_thread(self, request, client_address):
        def kill():                                 # общий срок на весь запрос: SOCK_TIMEOUT -- на одну операцию, а читающий по байту клиент держал бы поток вечно
            try: request.shutdown(socket.SHUT_RDWR)
            except Exception: pass
        tm = threading.Timer(REQ_DEADLINE, kill); tm.daemon = True; tm.start()
        try: super().process_request_thread(request, client_address)
        finally: tm.cancel(); self._sem.release()


ROUTE = re.compile(r"^(?:/stealth-api(?:/[a-z0-9_-]+)?)?/(head|announcements|known|balances|receipt|usdc-domain)$")   # точный путь: nginx отдаёт /stealth-api/<chain>/<имя> (proxy_pass без URI) или просто /<имя>


def _small_get(key, ttl, fn):
    now = time.time()
    with _ann_lock:
        hit = _small.get(key)
        if hit and now - hit[0] < ttl: return hit[1]
    v = fn()
    with _ann_lock:
        if len(_small) > 1000: _small.clear()
        _small[key] = (now, v)
    return v


def _ann_put(key, now, body):
    with _ann_lock:
        if _ann_size[0] + len(body) > ANN_CACHE_BYTES:
            for k in [k for k, v in _ann_cache.items() if now - v[0] >= ANN_TTL]: _ann_size[0] -= len(_ann_cache.pop(k)[1])
            if _ann_size[0] + len(body) > ANN_CACHE_BYTES: _ann_cache.clear(); _ann_size[0] = 0
        old = _ann_cache.get(key)
        if old: _ann_size[0] -= len(old[1])
        _ann_cache[key] = (now, body); _ann_size[0] += len(body)


class H(BaseHTTPRequestHandler):
    timeout = SOCK_TIMEOUT          # сокет-таймаут: медленный клиент не держит поток вечно
    def log_message(self, *a): pass
    def finish(self):
        try: super().finish()
        finally:                    # соединение чтения живёт на поток, а поток -- на один запрос: без закрытия они копились (аудит 1158 F-11)
            c = getattr(_tl, "c", None); _tl.c = None
            if c is not None:
                try: c.close()
                except Exception: pass
    def _json(self, code, obj):
        self._raw(code, json.dumps(obj, separators=(",", ":")).encode())
    def _raw(self, code, body):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        _tl.dl = time.time() + REQ_DEADLINE
        u = urlparse(self.path); q = parse_qs(u.query); c = rdb()
        mt = ROUTE.match(u.path); route = mt.group(1) if mt else None
        one = lambda k, d="": (q.get(k, [d])[0] or "").strip()
        try:
            if route == "head":
                g = lambda k: c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
                h, ts, ch = g("head"), g("ts"), g("chain_head")
                if time.time() - _count["t"] > 5: _count["n"] = c.execute("SELECT COUNT(*) FROM ann").fetchone()[0]; _count["t"] = time.time()
                n = _count["n"]
                head = int(h[0]) if h else None; chain = int(ch[0]) if ch else None
                fb, sb, ep = g("final_block"), g("safe_block"), g("epoch")
                return self._json(200, {"head": head, "chain_head": chain, "lag": (chain - head) if (head and chain) else None, "count": n, "ts": int(ts[0]) if ts else None, "start": START, "chain": CHAIN, "chain_id": CC["id"], "mode": MODE, "confirmations": CONF if MODE != "safe" else None,
                                       "final_block": int(fb[0]) if fb else None, "safe_block": int(sb[0]) if sb else None, "epoch": int(ep[0]) if ep else 0})
            if route == "announcements":
                sq, lq = one("since", "0"), one("limit", "1000")
                if not (_UINT.match(sq) and _UINT.match(lq)): return self._json(400, {"error": "bad parameter"})
                since = int(sq); limit = max(1, min(2000, int(lq)))
                key = (since, limit); now = time.time()
                canon = since % PAGE_SIZE == 0 and limit in (1000, 2000)      # 1000 -- умолчание, 2000 -- то, что шлёт клиент; произвольные смещения не кэшируем
                if canon:
                    with _ann_lock: hit = _ann_cache.get(key)
                    if hit and now - hit[0] < ANN_TTL: return self._raw(200, hit[1])
                rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer FROM ann WHERE id>? ORDER BY id LIMIT ?", (since, limit)).fetchall()
                fb = c.execute("SELECT v FROM meta WHERE k='final_block'").fetchone(); fb = int(fb[0]) if fb else -1
                ep = c.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()
                out = [{"id": r[0], "block": r[1], "tx": r[2], "scheme": r[3], "stealth": r[4], "caller": r[5], "eph": r[6], "meta": r[7], "payer": r[8], "final": r[1] <= fb} for r in rows]
                body = json.dumps({"rows": out, "next": out[-1]["id"] if out else since, "final_block": fb if fb >= 0 else None, "epoch": int(ep[0]) if ep else 0}, separators=(",", ":")).encode()
                if canon: _ann_put(key, now, body)
                return self._raw(200, body)
            if route == "known":
                addr = one("addr").lower()
                if not _ADDR.match(addr): return self._json(400, {"error": "addr"})
                sb = c.execute("SELECT v FROM meta WHERE k='safe_block'").fetchone(); sb = int(sb[0]) if sb else -1       # нет safe-блока -> никого не признаём (закрыто)
                rows = c.execute("SELECT caller, meta, paid FROM ann WHERE stealth=? AND block<=?", (addr, sb)).fetchall()
                ok = False
                for caller, meta, paid in rows:
                    if caller not in PAY_CALLERS: continue
                    if paid is None or paid < MIN_KNOWN_USDC: continue      # F-3: подтверждено Transfer'ом токена на stealth-адрес в квитанции, а не только заявлено в metadata
                    try:
                        m = bytes.fromhex(meta[2:]); amt = int.from_bytes(m[25:57], "big") if len(m) >= 57 else 0
                        tok = "0x" + m[5:25].hex() if len(m) >= 57 and m[1:5] == bytes.fromhex("a9059cbb") else ""   # viewTag|transfer-селектор|токен|сумма (payToken и payWithAuthorization)
                    except Exception:
                        amt, tok = 0, ""
                    if tok == USDC and amt >= MIN_KNOWN_USDC: ok = True; break
                return self._json(200, {"known": ok})
            if route == "balances":
                addrs = [a.strip().lower() for a in one("addrs").split(",") if a.strip()]
                if not addrs or len(addrs) > MAX_ADDRS or not all(_ADDR.match(a) for a in addrs): return self._json(400, {"error": "addrs"})
                return self._json(200, balances(addrs))
            if route == "receipt":
                tx = one("tx").lower()
                if not _TXH.match(tx): return self._json(400, {"error": "tx"})
                def rcpt():
                    rc = rpc("eth_getTransactionReceipt", [tx], 15)
                    return {"status": (int(rc["status"], 16) if rc and rc.get("status") else None), "block": int(rc["blockNumber"], 16) if rc else None}
                v = _small_get(("r", tx), 2, rcpt)                           # 2 с: клиент опрашивает статус, но мгновенный повтор не должен каждый раз идти на платный RPC
                return self._json(200, v)
            if route == "usdc-domain":
                v = _small_get(("d",), 3600, lambda: {"domain_separator": rpc("eth_call", [{"to": USDC, "data": "0x3644e515"}, "latest"], 15), "chain": CHAIN, "token": CC["token"]})   # константа контракта
                return self._json(200, v)
            return self._json(404, {"error": "not found"})
        except (ValueError, OverflowError):
            return self._json(400, {"error": "bad parameter"})
        except Exception as e:
            print("api error:", str(e)[:200], flush=True)
            return self._json(500, {"error": "temporarily unavailable"})


if __name__ == "__main__":
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    init_db()
    if "--refill-payers" in sys.argv or "--backfill-paid" in sys.argv:
        refill_payers(); raise SystemExit(0)
    threading.Thread(target=index_loop, daemon=True).start()
    print("stealth indexer", CHAIN, "mode", MODE, "conf", CONF, "on", PORT, "db", DB, "from block", START if START is not None else "(head-%d)" % BACKFILL, "stealthpay", STEALTHPAY, "legacy", ",".join(LEGACY) or "-", flush=True)
    BoundedServer(("127.0.0.1", PORT), H).serve_forever()
