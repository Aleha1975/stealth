#!/usr/bin/env python3
"""Stealth: индексатор объявлений ERC-5564 (Base или Robinhood Chain, STEALTH_CHAIN=base|rh) и маленький API для клиента (без ключей, без денег).

Читает события Announcement общего Announcer (0x5564…5564) с блока START в sqlite и отдаёт клиенту пачками; клиент
проверяет каждую запись своим ключом просмотра у себя. Фильтры против спама: только схема 1, эфемерный ключ ровно
33 байта, metadata обрезается до 128 байт. Голова: base -- тег "safe"; rh -- latest минус STEALTH_CONFIRMATIONS блоков
(быстро видно), а раз в RECONCILE_EVERY секунд окно (safe..голова] перечитывается и строки, изменённые реорганизацией,
удаляются/вставляются заново. Голова двигается только к блоку, чей хэш вернули две разные точки (одна настроенная -- доверенный провайдер, сверяется parentHash). Одна служба = одна цепь (порт/БД/цепь задаются окружением); конфиг цепей -- chains.json.
API (127.0.0.1:3873, за nginx как /stealth-api/):
  GET /head                                  -> {head, chain_head, lag, count, ts, start, final_block, safe_block, epoch}   (epoch растёт, когда реорг/откат цепи убрал строки: клиент, державший старые, перечитывает)
  GET /announcements?since=<id>&limit=<n>     -> {rows:[{id,block,tx,scheme,stealth,caller,eph,meta,payer,final,verified}], next, final_block, epoch}   (final = block <= final_block: строку реорг уже не уберёт)
  Статические страницы истории (nginx, не Python): STEALTH_PAGES_DIR/manifest.json + p<k>.json(.gz), по PAGE_SIZE=1024 строк на страницу
  (id в [k*1024+1, (k+1)*1024]), строка = [id,block,tx,stealth,eph,meta,payer,verified] (verified: 1 = объявил наш StealthPay и квитанция разобрана, а у токеновой строки в ней найден Transfer на объявленную сумму; у строки payETH сумму гарантирует контракт, логи её не показывают; старые страницы без 8-го поля клиент считает «не подтверждено», пока --backfill-paid не перепишет их и не поднимет версию). Страница пишется только когда полная И все её строки
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
# Аудит 1165 M-1: ОДНО правило доверия к RPC. head_done двигается к блоку b, только когда хэш блока b подтверждён: при >= 2 настроенных точках его вернули равным ДВЕ разные точки
# (хэш блока включает всю цепь под ним), при одной настроенной (RH) точка доверенный провайдер по конфигурации и проверяется только непрерывность parentHash. NEED -- сколько точек должно сойтись.
# Нет согласия (точки расходятся / отвечает одна из двух) -- индексатор ЖДЁТ, никогда не идёт по слову одной точки.
WAIT_ALERT_S = float(os.environ.get("STEALTH_WAIT_ALERT_S", "600"))   # через сколько секунд без продвижения писать ALERT в журнал: 10 мин = перезапуск или ресинк узла; дольше -- уже авария, о которой надо знать
REORG_WIN = 100                 # блоков: окно реконсиляции (safe - REORG_WIN) и глубина отката head_done, когда parentHash не сошёлся с сохранённым хэшем
BH_KEEP = 10000                 # блоков: сколько хэшей концов диапазонов держим (та же глубина, что у запасного окна реконсиляции head_done - 10000)
MAX_SINGLE = int(os.environ.get("STEALTH_MAX_SINGLE", "20"))      # аудит 1163 L-4: адресов на запрос без Multicall3 (2 вызова на адрес); клиент балансы берёт из цепи сам, это страховка
REQ_MAX_CALLS = int(os.environ.get("STEALTH_REQ_MAX_CALLS", "100"))   # RPC-вызовов (попыток, с переключением) на один запрос API: 2 x MAX_SINGLE + getCode, ещё x2 на переключение запас
# Аудит 1165 L-2: общее ведро на RPC-вызовы, рождённые API (потолок REQ_MAX_CALLS -- на ОДИН запрос). Ёмкость = REQ_MAX_CALLS (самый тяжёлый законный запрос проходит из полного ведра); скорость 20/с = вдвое выше лимита
# одного клиента на nginx (10 r/s) и на порядок выше честной нагрузки (RPC ходят только /balances и /receipt, оба с кэшем 15 с / 2 с, /usdc-domain -- раз в час); индексатор тем же ключом тратит ~4-8 вызовов/с (RH).
API_RPC_RATE = float(os.environ.get("STEALTH_API_RPC_RATE", "20"))
API_RPC_BURST = float(os.environ.get("STEALTH_API_RPC_BURST", str(REQ_MAX_CALLS)))
ANN_CACHE_ENTRIES = int(os.environ.get("STEALTH_ANN_CACHE_ENTRIES", "2048"))   # аудит 1163 I-1: накладные ~1 КБ на запись (кортеж, int, dict) -> до ~2 МБ сверх байт; канонических ключей и так <= 2 x max_id/1024
PAGES_DIR = os.environ.get("STEALTH_PAGES_DIR", "")             # пусто -> страницы не пишем (клиент идёт по старому пути)
PAGE_SIZE = 1024
PAGES_MARGIN = int(os.environ.get("STEALTH_PAGES_MARGIN", "200"))   # rh: финал = safe - MARGIN (> окна реконсиляции safe-100)
DB = os.environ.get("STEALTH_DB", "/opt/stealth/announcements.db")
PORT = int(os.environ.get("STEALTH_PORT", "3873"))
MIN_KNOWN_USDC = int(os.environ.get("MIN_KNOWN_USDC", "100000"))     # $0.10: мельче через релеер не выводим
KNOWN_SAFE = os.environ.get("STEALTH_KNOWN_SAFE", "1") != "0"     # 0 -- ТОЛЬКО лаборатория/форк (у anvil тег safe не движется): /known верит строкам до проиндексированной головы, а не до safe
# /known на цепи с мягкой финальностью (rh, режим latest): тег safe у узла отстаёт на 10-15 мин (L1-пачки), платёж не вывести. Строке верим через KNOWN_LAG_S секунд после головы индексатора (она и так на CONFIRMATIONS блоков позади latest).
# Страницы истории и final_block остаются на теге safe. На Base (режим safe) граница -- сам safe. Потеря при откате глубже 2 минут -- газ релеера (дневной потолок бюджета), деньги не уходят: перевод с пустого адреса откатится.
KNOWN_LAG_S = int(os.environ.get("STEALTH_KNOWN_LAG_S", "120"))
BLOCK_MS = int(CC.get("block_ms", 2000))
MAX_META = 128
CHUNK0 = int(os.environ.get("STEALTH_CHUNK", "50000"))
RF_SLICE = CHUNK0               # аудит 1183 L-4: длинная сверка от reconcile_from идёт ломтями по одному окну индексации (то же число блоков, что основной цикл уже читает за раз); прогресс сохраняется после каждого ломтя
POLL = int(os.environ.get("STEALTH_POLL", "20" if MODE == "safe" else "2"))
CACHE_TTL = float(os.environ.get("STEALTH_BAL_TTL", "15"))
MAX_ADDRS = 100
MAX_THREADS = int(os.environ.get("STEALTH_MAX_THREADS", "64"))
SOCK_TIMEOUT = float(os.environ.get("STEALTH_SOCK_TIMEOUT", "10"))
REQ_DEADLINE = float(os.environ.get("STEALTH_REQ_DEADLINE", "30"))   # весь запрос целиком (аудит 1158 F-7); самый долгий законный вызов -- мультикол 20 с
ANN_CACHE_BYTES = int(os.environ.get("STEALTH_ANN_CACHE_BYTES", str(16 << 20)))   # аудит 1158 F-5: ~12 полных ответов по 1.3 МБ; раньше 256 записей = 300+ МБ
_env_rpc = [u.strip() for u in os.environ.get("STEALTH_RPC", "").split(",") if u.strip()]
RPCS = _env_rpc or [u for u in [os.environ.get(k) for k in CC["rpc_env"]] + CC["rpcs"] if u]
RPCS = list(dict.fromkeys(RPCS))                                # одинаковые URL -- не два независимых узла
if len(RPCS) > 1 and len({urlparse(u).hostname for u in RPCS}) < len(RPCS):          # аудит 1169 I-6: два URL одного хоста -- почти наверняка один и тот же бэкенд, а модель доверия держится на независимости точек
    print("WARNING: two STEALTH_RPC URLs share one host: they must be independent providers (different backends), otherwise two agreeing endpoints prove nothing", flush=True)
NEED = min(2, len(RPCS))                                        # сколько точек должны вернуть один и тот же хэш блока (1 -- единственная настроенная, доверенный провайдер)
def _loopback(u):                                               # аудит 1165 I-2: разбор URL, а не регулярка (http://localhost:80@evil.example/ имеет хост evil.example)
    try: p = urlparse(u); return p.scheme in ("http", "https") and p.hostname in ("127.0.0.1", "localhost", "::1")
    except ValueError: return False
# Аудит 1163 I-4: STEALTH_KNOWN_SAFE=0 снимает ворота safe у /known -- только лаборатория/форк: все точки на loopback или явный STEALTH_FORK=1.
if not KNOWN_SAFE and os.environ.get("STEALTH_FORK") != "1" and not all(_loopback(u) for u in RPCS):
    raise SystemExit("STEALTH_KNOWN_SAFE=0 only for a local fork (RPC on 127.0.0.1) or with STEALTH_FORK=1")
UA = {"Content-Type": "application/json", "User-Agent": "deepyield-stealth/1.0"}
_lock = threading.Lock()


def rpc1(u, method, params, timeout):
    req = urllib.request.Request(u, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), UA)
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        d = json.load(fh)
    if "error" in d: raise RuntimeError(str(d["error"])[:120])
    return d["result"]


_rot = 0                        # с какой точки начинать: сдвигается после сбоя итерации, чтобы одна больная первая точка не держала индексатор


class RateLimited(Exception): pass
_tb = {"t": time.monotonic(), "n": API_RPC_BURST}; _tb_lock = threading.Lock()


# Аудит 1167 L-3 (принято, не меняем): ведро общее на всех -- запросы с кэш-попаданием RPC не трогают и ведро не тратят; пустое ведро даёт клиентам 429, а не сбой индексатора. Выделенной доли под одиночные адреса нет:
# при ограничении 10 r/s на клиента в nginx это усложнение ради редкого сценария; лимит на клиента и общий потолок остаются на nginx.
def _take_token():
    """Аудит 1165 L-2: одно общее ведро (скорость API_RPC_RATE, ёмкость API_RPC_BURST) на все RPC-вызовы потоков API."""
    with _tb_lock:
        now = time.monotonic(); _tb["n"] = min(API_RPC_BURST, _tb["n"] + (now - _tb["t"]) * API_RPC_RATE); _tb["t"] = now
        if _tb["n"] < 1: return False
        _tb["n"] -= 1; return True


def rpc(method, params, timeout=60, only=None):
    """Первый ответивший узел; only=<url> -- ТОЛЬКО эта точка (логи и квитанции берём у точки, согласившейся с хэшем блока). В потоке API есть общий срок запроса _tl.dl."""
    last = None
    for u in ([only] if only else RPCS):
        t = timeout
        if getattr(_tl, "calls", None) is not None:           # аудит 1163 L-4: потолок RPC-вызовов на запрос API (поток индексатора счётчика не имеет)
            _tl.calls += 1
            if _tl.calls > REQ_MAX_CALLS: raise RuntimeError("request rpc call budget")
            if not _take_token(): raise RateLimited("api rpc rate limit")
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
    c.execute("CREATE TABLE IF NOT EXISTS bh (block INTEGER PRIMARY KEY, hash TEXT)")        # аудит 1167 L-2: хэши концов обработанных диапазонов (последние BH_KEEP блоков): по ним находим точку, где цепь ещё совпадает
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


def heads_now():
    """(голова, safe или None). Аудит 1165 M-1: голова названа не менее чем NEED точками (NEED-я по высоте: при двух точках -- меньшая из двух, при одной -- её собственная); safe -- так же (при двух точках МЕНЬШИЙ из двух тегов).
    Это только кандидат: двигаться к нему можно после согласия по хэшу блока (agreed). Ответили меньше NEED точек -- ждём."""
    seen = []
    for u in RPCS[_rot:] + RPCS[:_rot]:
        try: seen.append(target_head(u))
        except Exception: continue
    if len(seen) < NEED: raise RuntimeError("only %d of %d endpoints answered, need %d: waiting" % (len(seen), len(RPCS), NEED))
    head = sorted((h for h, _ in seen), reverse=True)[NEED - 1]
    sfs = sorted((sf for _, sf in seen if sf is not None), reverse=True)
    return head, (sfs[NEED - 1] if len(sfs) >= NEED else None)


def _block_at(u, n):
    """(hash, parentHash) блока n у точки u или None, если точка блока не отдаёт. Номер в ответе обязан совпасть с запрошенным."""
    try: b = rpc("eth_getBlockByNumber", [hex(n), False], 20, only=u)
    except Exception: return None
    try:
        if b and int(b["number"], 16) == n and re.match(r"^0x[0-9a-f]{64}$", b["hash"]) and re.match(r"^0x[0-9a-f]{64}$", b["parentHash"]): return b["hash"], b["parentHash"]
    except (KeyError, TypeError, ValueError): pass
    return None


def agreed(n, ag):
    """(хэш блока n, [точки, вернувшие именно его]) -- хэш, который вернули не менее NEED точек. Расходятся / отвечает меньше NEED / ничья -- исключение (ждём). ag: кэш на одну итерацию (блок не финален -- между итерациями не помним)."""
    if n in ag: return ag[n]
    votes = {}
    for u in RPCS[_rot:] + RPCS[:_rot]:
        x = _block_at(u, n)
        if x: votes.setdefault(x[0], []).append(u)
    top = sorted(votes.values(), key=len, reverse=True)
    if not top or len(top[0]) < NEED or (len(top) > 1 and len(top[1]) == len(top[0])):
        raise RuntimeError("block %d: no %d endpoints agree on its hash (%s): waiting" % (n, NEED, ", ".join("%d x %s" % (len(v), h[:10]) for h, v in votes.items()) or "no answers"))
    h = next(h for h, v in votes.items() if v is top[0]); ag[n] = (h, top[0]); return ag[n]


def check_logs(logs, a, b, ag):
    """Логи из [a,b]: номера блоков внутри диапазона; при NEED >= 2 blockHash каждого лога равен согласованному хэшу его блока (лог из чужой цепи / выдуманный блок не пройдёт)."""
    for lg in logs:
        n = int(lg["blockNumber"], 16)
        if not (a <= n <= b): raise RuntimeError("getLogs returned a block outside [%d,%d]" % (a, b))
        if NEED >= 2 and (lg.get("blockHash") or "").lower() != agreed(n, ag)[0]: raise RuntimeError("log blockHash differs from the agreed hash of block %d" % n)


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


def _ann_amount(meta):
    """(токен, сумма) из metadata объявления: viewTag|transfer-селектор|токен|сумма (как читает /known); иначе ("", 0)."""
    try:
        m = bytes.fromhex(meta[2:])
        if len(m) >= 57 and m[1:5] == bytes.fromhex("a9059cbb"): return "0x" + m[5:25].hex(), int.from_bytes(m[25:57], "big")
    except Exception: pass
    return "", 0


def _paid_to(rc, stealth, log_index=None, meta=None):
    """Аудит 1158 F-3 / 1163 L-1: сколько токена цепи РЕАЛЬНО пришло на stealth-адрес по ЭТОМУ объявлению. Берём один Transfer(to=stealth) токена цепи с суммой ровно как в объявлении, который сделал контракт
    StealthPay (from в PAY_CALLERS: ветка payWithAuthorization -- плательщик -> контракт -> stealth) ИЛИ стоит в логах раньше объявления (payToken: transferFrom плательщика на stealth, затем announce; плательщик может
    быть контрактом-кошельком, поэтому from не сверяем). Лишние Transfer в той же tx (чужие, другой суммы) paid не раздувают; не нашли -- 0. Раскладка v2 и v3 одинакова: announce идёт ПОСЛЕ перевода на stealth;
    ветка from-в-PAY_CALLERS не зависит от порядка (запас для прежнего контракта)."""
    tok, amt = _ann_amount(meta or "")
    if tok != USDC or amt <= 0: return 0
    for lg in rc.get("logs") or []:
        t = lg.get("topics") or []
        if (lg.get("address") or "").lower() != USDC or len(t) != 3 or t[0].lower() != TRANSFER_T or "0x" + t[2][-40:].lower() != stealth: continue
        try: v = int(lg.get("data") or "0x0", 16); li = int(lg["logIndex"], 16) if lg.get("logIndex") is not None else None
        except ValueError: continue
        if v != amt: continue
        if "0x" + t[1][-40:].lower() in PAY_CALLERS or (li is not None and log_index is not None and li < log_index): return min(v, PAID_CAP)
    return 0


def _rc_key(r, rc, ag):
    """Аудит 1167 M-1: поля квитанции, от которых зависят payer и paid, в сравнимом виде; None -- квитанция не про эту tx / не из согласованного блока.
    transactionHash квитанции и каждого её лога обязан быть хэшем tx строки, blockNumber -- блоком строки, при >= 2 точках blockHash -- согласованным хэшем этого блока."""
    try:
        tx = r["tx"]
        if not isinstance(rc, dict) or (rc.get("transactionHash") or "").lower() != tx: return None
        if r.get("block") is not None:
            if not rc.get("blockNumber") or int(rc["blockNumber"], 16) != r["block"]: return None
            if NEED >= 2 and (rc.get("blockHash") or "").lower() != agreed(r["block"], ag)[0]: return None
        logs = rc.get("logs") or []
        if any((lg.get("transactionHash") or "").lower() != tx for lg in logs): return None
        hx = lambda v: int(v, 16) if isinstance(v, str) else v        # аудит 1169 L-3: "0x1" и "0x01" -- одно число; сравниваем числа, не написание
        return json.dumps([tx, (rc.get("blockHash") or "").lower(), hx(rc.get("blockNumber")), hx(rc.get("status")), (rc.get("from") or "").lower(),
                           [[(lg.get("address") or "").lower(), [str(x).lower() for x in lg.get("topics") or []], (lg.get("data") or "").lower(), hx(lg.get("logIndex"))] for lg in logs
                            if (lg.get("topics") or [""])[0].lower() == TRANSFER_T]])
    except Exception: return None            # нет согласия по хэшу блока (или поле не разобралось) -- квитанции не верим, строка дозаполнится позже


def receipt_of(r, cache, ep=None, ag=None):
    """Квитанция tx (в cache по tx). None = не получили / не прошла _rc_key (чужая tx, другой блок, реорг/отстающий узел) -- строка останется с payer/paid NULL и будет дозаполнена fix_rows (аудит 1158 F-4).
    Аудит 1167 M-1: при >= 2 точках квитанция принимается, только когда ДВЕ разные точки вернули её одинаковой (_rc_key): одна точка paid (а значит /known) выдумать не может, строка, виденная
    одной точкой, остаётся без paid, пока вторая не подтвердит. Одна настроенная точка -- доверенный провайдер, квитанция как отдана (после тех же проверок tx / блока)."""
    if r["tx"] in cache: return cache[r["tx"]]
    if ag is None: ag = {}
    order = ([ep] if ep else []) + [u for u in RPCS if u != ep] if NEED >= 2 else [ep]
    rc = None; keys = []
    for o in order:
        try: x = rpc("eth_getTransactionReceipt", [r["tx"]], 15, only=o) or None
        except RateLimited: raise
        except Exception: continue
        k = _rc_key(r, x, ag) if x else None
        if k is None: continue
        if NEED < 2 or k in keys: rc = x; break
        keys.append(k)
    cache[r["tx"]] = rc
    return rc


def _payer_from(r, rc):
    if not rc: return None
    if r["caller"] in PAY_CALLERS: return _real_payer(rc, r["stealth"])
    return (rc.get("from") or "").lower() or None


def payer_of(r, cache, ep=None, ag=None):
    """cache: tx -> квитанция. Для анонсов не от StealthPay - tx.from через ту же квитанцию."""
    return _payer_from(r, receipt_of(r, cache, ep, ag))


def put_row(c, r, payers, ep=None, ag=None):
    rc = receipt_of(r, payers, ep, ag)
    payer = _payer_from(r, rc); paid = _paid_to(rc, r["stealth"], r.get("log_index"), r.get("meta")) if rc else None
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
        rows = c.execute("SELECT id,tx,stealth,caller,block,payer,paid,log_index,meta FROM ann WHERE id>? AND block<=? AND (payer IS NULL OR (paid IS NULL AND caller IN (%s))) ORDER BY id LIMIT ?" % ",".join("?" * len(pc)),
                         (_fix["after"], upto) + pc + (FIX_BATCH,)).fetchall()
    if not rows: _fix["after"] = 0; return 0
    _fix["after"] = rows[-1][0]
    cache = {}; ag = {}; changed = []; n = 0
    for id_, tx, stealth, caller, block, old, old_paid, li, meta in rows:
        r = {"tx": tx, "stealth": stealth, "caller": caller, "block": block}
        rc = receipt_of(r, cache, ep, ag)
        if not rc: continue
        payer = _payer_from(r, rc); n += 1; paid = _paid_to(rc, stealth, li, meta)
        with _lock: c.execute("UPDATE ann SET payer=COALESCE(?,payer), paid=? WHERE id=?", (payer, paid, id_))
        if payer != old or verified(caller, paid, meta) != verified(caller, old_paid, meta): changed.append(id_)      # M-1: a row that became verified is on a written page: rewrite it
    with _lock: c.commit()
    _rewrite_pages(c, changed)
    if n: print("fix_rows: filled", n, "rows", flush=True)
    return n


def refill_payers():
    """Одноразово (--refill-payers / --backfill-paid): пересчитать payer и paid у строк нашего StealthPay (и у любых с payer NULL), затем перезаписать страницы и поднять версию манифеста."""
    c = db(); cache = {}; ag = {}; n = ch = 0
    q = "SELECT id,tx,stealth,caller,payer,block,log_index,meta FROM ann WHERE caller IN (%s) OR payer IS NULL ORDER BY id" % ",".join("?" * len(PAY_CALLERS))
    for id_, tx, stealth, caller, old, block, li, meta in c.execute(q, tuple(PAY_CALLERS)).fetchall():
        r = {"tx": tx, "stealth": stealth, "caller": caller, "block": block}
        rc = receipt_of(r, cache, None, ag)
        if not rc: continue
        new = _payer_from(r, rc); n += 1
        c.execute("UPDATE ann SET payer=COALESCE(?,payer), paid=? WHERE id=?", (new, _paid_to(rc, stealth, li, meta), id_))
        if new and new != old: ch += 1
        if len(cache) > 500: cache.clear(); ag.clear()
    c.commit()
    if PAGES_DIR and c.execute("SELECT v FROM meta WHERE k='pages'").fetchone():
        st = json.loads(c.execute("SELECT v FROM meta WHERE k='pages'").fetchone()[0])
        for k in range(st["full"]): st["counts"][k] = _write_page(c, k)
        st["version"] += 1; _save_pages(c, st)
        print("pages rewritten:", st["full"], "version", st["version"], flush=True)
    print("refill-payers: checked", n, "changed", ch, flush=True)


def union_logs(a, b, eps, ag):
    """Аудит 1167 M-2: логи [a,b] -- ОБЪЕДИНЕНИЕ ответов нескольких согласившихся точек (одна точка не может скрыть объявление), каждый лог проверен check_logs; дубликаты по (tx, logIndex) убраны.
    Точка из eps не ответила -- исключение (ждём, как и раньше)."""
    seen = {}
    for u in eps:
        logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}], only=u)
        check_logs(logs, a, b, ag)
        for lg in logs: seen.setdefault((str(lg.get("transactionHash")).lower(), lg.get("logIndex")), lg)
    return sorted(seen.values(), key=lambda lg: (int(lg["blockNumber"], 16), int(lg["logIndex"], 16)))


def fetch_range(a, b, ep=None, ag=None):
    """Все декодированные записи Announcer в [a,b]; getLogs режем пополам, если узел отказывает по размеру. ep -- закреплённая точка. Логи проходят check_logs (аудит 1165)."""
    if ag is None: ag = {}
    try:
        logs = rpc("eth_getLogs", [{"address": ANNOUNCER, "fromBlock": hex(a), "toBlock": hex(b)}], only=ep)
    except Exception:
        if b - a < 1000: raise
        m = (a + b) // 2
        return fetch_range(a, m, ep, ag) + fetch_range(m + 1, b, ep, ag)
    check_logs(logs, a, b, ag)
    out = []
    for lg in logs:
        try:
            r = decode(lg)
        except Exception as e:
            print("decode skip", lg.get("transactionHash"), str(e)[:80], flush=True); continue
        if r: out.append(r)
    return out


def _bump_epoch(c, commit=True):
    """commit=False -- вызывающий держит _lock и коммитит сам (аудит 1163 L-2: удаление строк и подъём epoch одной транзакцией)."""
    if commit:
        with _lock: _bump_epoch(c, False); c.commit()
    else: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('epoch',?)", (str(int(_meta_get(c, "epoch") or 0) + 1),))


REC_DONE, REC_NO_SECOND, REC_NOT_REACHED = "done", "second-read-missing", "window-not-reached"      # аудит 1181 L-1: три исхода reconcile; границы доверия открывает только REC_DONE


def reconcile(c, sf, head_done, ep=None, insert_only=False, frm=None, to=None):
    """Реорг-страж (rh): перечитать (safe-REORG_WIN .. head_done], убрать строки, которых в цепи больше нет (или они в другом блоке), добавить новые.
    Аудит 1158 F-4: удаляем ТОЛЬКО то, чего нет в двух чтениях (закреплённая точка + другая, чья голова покрывает окно; нет другой -- та же ещё раз); короткий/отстающий ответ строки не стирает.
    insert_only (base, режим safe: реорга ниже safe нет) -- только добавляем пропущенное.
    frm (аудит 1179 F4: после --rewind) -- окно начинается не позже этого блока, чтобы строки брошенной ветки выше новой головы тоже сверялись. Аудит 1181 L-1: возвращает REC_DONE (проход полный), REC_NO_SECOND (были строки на удаление, но второго чтения не получили -- ничего не удалено) или REC_NOT_REACHED (окно начинается выше head_done); только REC_DONE считается чистым."""
    a = max(START, (sf or head_done - 10000) - REORG_WIN)
    if frm is not None: a = max(START, min(a, frm)) if to is None else max(START, frm)
    hi = head_done if to is None else min(to, head_done)      # аудит 1183 L-4: to -- верхняя граница ломтя (нижний ломоть длинной сверки); без to окно идёт до головы, как раньше
    if a > hi: return REC_NOT_REACHED
    # верхняя граница обязательна: иначе строки новее head_done (их уже записал основной цикл за время getLogs) считались бы "пропавшими" и удалялись
    ag = {}
    want = {}
    for u in (agreed(head_done, ag)[1][:NEED] if NEED >= 2 else [ep]):        # аудит 1167 M-2: объединение чтений двух согласившихся точек, а не одной закреплённой
        for r in fetch_range(a, hi, u, ag): want.setdefault((r["tx"], r["log_index"], r["block"]), r)
    with _lock:
        have = {(t, li, bl): i for i, t, li, bl in c.execute("SELECT id,tx,log_index,block FROM ann WHERE block>=? AND block<=?", (a, hi))}
    gone = {k: i for k, i in have.items() if k not in want}; no_second = False
    if gone and not insert_only:
        second = [u for u in RPCS if u != ep]
        for u in second + [ep]:
            if u is None: continue
            try:
                if u != ep and latest_head(u) < hi: continue          # у этой точки голова не покрывает окно -- её «нет» ничего не значит
                want2 = {(r["tx"], r["log_index"], r["block"]) for r in fetch_range(a, hi, u, ag)}
            except Exception: continue
            gone = {k: i for k, i in gone.items() if k not in want2}; break
        else: gone = {}; no_second = True                                    # второго чтения не получили -> не удаляем, и проход НЕ полный (1181 L-1)
        if gone:
            with _lock:
                c.executemany("DELETE FROM ann WHERE id=?", [(i,) for i in gone.values()]); _bump_epoch(c, False); c.commit()      # одна транзакция: падение между ними не оставит удалённые строки без смены epoch
            print("reconcile: removed", len(gone), "rows changed by reorg (two reads agree)", flush=True)
    new = [r for k, r in want.items() if k not in have]
    payers = {}
    for r in new: put_row(c, r, payers, ep, ag)
    if new:
        with _lock: c.commit()
        print("reconcile: added", len(new), "rows", flush=True)
    return REC_NO_SECOND if no_second else REC_DONE


def _atomic(path, data):
    tmp = path + ".tmp%d" % os.getpid()
    with open(tmp, "wb") as f: f.write(data)
    os.replace(tmp, path)


def _page_name(k): return "p%06d.json" % k


def verified(caller, paid, meta):
    """Аудит 1159 M-1 / 1165 I-3. 1 = объявление сделал один из наших StealthPay (он объявляет только после проверенного перевода) И квитанция разобрана (paid не NULL) И
    токеновая строка (селектор transfer) подтверждена: в квитанции нашёлся Transfer на объявленную сумму (paid > 0). Строка payETH (селектор 0xeeeeeeee): нативную сумму логи не показывают,
    её гарантирует сам контракт (call на stealth-адрес прошёл, объявляется msg.value) -- для неё достаточно разобранной квитанции (paid = 0). Всё прочее -- 0: сумма в metadata не подтверждена."""
    if caller not in PAY_CALLERS or paid is None: return 0
    sel = (meta or "")[4:12]
    return 1 if (sel == "eeeeeeee" or (sel == "a9059cbb" and paid > 0)) else 0


def _write_page(c, k):
    """Записать страницу k (json + json.gz) из БД; вернуть число строк. Строка: [id,block,tx,stealth,eph,meta,payer,verified] (verified добавлен в конец, старые клиенты читают первые 7)."""
    rows = c.execute("SELECT id,block,tx,stealth,eph,meta,payer,caller,paid FROM ann WHERE id>? AND id<=? ORDER BY id", (k * PAGE_SIZE, (k + 1) * PAGE_SIZE)).fetchall()
    raw = json.dumps([list(r[:7]) + [verified(r[7], r[8], r[5])] for r in rows], separators=(",", ":")).encode()
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


_deep_alert = [0.0]


def find_common(c, head_done, ag, hh=None):
    """Аудит 1167 L-2: parentHash не сошёлся -- шагаем назад REORG_WIN, 2*REORG_WIN, ... (не ниже START-1), пока сохранённый хэш блока не совпадёт с тем, что отдаёт цепь сейчас (agreed). Возвращает (блок, хэш).
    Совпадения нет в сохранённых (старая БД без bh, расхождение глубже BH_KEEP) -- ALERT и ожидание оператора: после остановки службы `--rewind N` с достаточным N."""
    if hh and agreed(head_done, ag)[0] == hh: return head_done, hh      # аудит 1169 M-1: сохранённый хэш головы всё ещё согласован -- отката не требуется (ложный parentHash)
    step = REORG_WIN
    while head_done - step >= START - 1:
        with _lock: row = c.execute("SELECT block,hash FROM bh WHERE block<=? AND block>=? ORDER BY block DESC LIMIT 1", (head_done - step, START - 1)).fetchone()
        if not row: break
        if agreed(row[0], ag)[0] == row[1]: return row
        step = max(step * 2, head_done - row[0] + 1)
    if time.time() - _deep_alert[0] >= WAIT_ALERT_S:                # аудит 1169 I-4: раз в WAIT_ALERT_S, как и остальные ALERT (цикл идёт каждые POLL секунд)
        _deep_alert[0] = time.time()
        print("ALERT no stored block hash matches the chain (%s): operator action needed, stop the service and run --rewind N with N large enough" % CHAIN, flush=True)
    raise RuntimeError("deep divergence: waiting for the operator")


def index_loop():
    global START, _rot
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='head'").fetchone()
    if START is None:                                       # rh без STEALTH_START_BLOCK: старт = голова - BACKFILL (запомним в БД)
        r0 = c.execute("SELECT v FROM meta WHERE k='start'").fetchone()
        while r0 is None:
            try:
                st0 = max(0, heads_now()[0] - BACKFILL)
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('start',?)", (str(st0),)); c.commit(); r0 = (str(st0),)
            except Exception as e:
                print("start block lookup failed:", str(e)[:100], flush=True); time.sleep(5)
        START = int(r0[0])
    head_done = int(row[0]) if row else START - 1
    hh = _meta_get(c, "head_hash")                          # хэш блока head_done (нет -- первый запуск или БД старше этого поля: первый шаг его принимает без сверки)
    chunk = CHUNK0
    last_rec = 0; deep = False; pin = None                  # pin -- точка, согласившаяся с последним хэшем: логи, квитанции, реконсиляция идут через неё
    ok_t = alert_t = time.time(); rf_alert_t = rf_prog_t = 0.0
    while True:
        try:
            head, sf = heads_now()                          # кандидат; двигаемся к нему только по согласованным хэшам блоков (agreed)
            ag = {}
            while head_done < head:
                a = head_done + 1; b = min(a + chunk - 1, head)
                hb, eps = agreed(b, ag)                     # хэш блока b подтверждён NEED точками; логи -- с одной из них (точка с другим хэшем в eps не попадает)
                ep = pin = eps[0]; lps = eps[:NEED]
                if hh:                                      # цепочка: родитель блока a обязан быть сохранённым блоком head_done (сменился бэкенд / реорг -- не пропускаем, а перечитываем окно)
                    x = _block_at(ep, a)
                    if not x: raise RuntimeError("endpoint cannot return block %d: waiting" % a)
                    if x[1] != hh and NEED >= 2:                # аудит 1169 M-1: расхождение должно подтвердить ещё одна точка из согласованных (аудит 1179 F6: x2 должна показать ТОТ ЖЕ parentHash, что и первая точка, -- осознанно, покрыто тестом), иначе не откат, а ожидание
                        x2 = _block_at(eps[1], a)
                        if not x2 or x2[1] != x[1]: raise RuntimeError("endpoints disagree on the parentHash of block %d: waiting" % a)
                    if x[1] != hh:
                        print("parentHash of block %d does not match the stored hash of %d (backend switch or reorg): looking for a stored block that still matches" % (a, head_done), flush=True)
                        back, bhash = find_common(c, head_done, ag, hh)
                        if back == head_done: raise RuntimeError("parentHash of block %d differs but the stored hash of %d is still agreed: waiting" % (a, head_done))
                        print("re-reading from %d" % (back + 1), flush=True)
                        with _lock:
                            if head_done - back > REORG_WIN:        # глубже окна реконсиляции строки выше точки совпадения она уже не уберёт: убираем здесь, перечитаем
                                c.execute("DELETE FROM ann WHERE block>?", (back,)); _bump_epoch(c, False)
                            c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(back),)); c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head_hash',?)", (bhash,))
                            c.execute("DELETE FROM bh WHERE block>?", (back,)); c.commit()
                        head_done = back; hh = bhash; last_rec = 0; deep = True
                        continue
                try:
                    logs = union_logs(a, b, lps, ag)
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
                    if r: put_row(c, r, payers, ep, ag)
                with _lock:
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(b),))
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head_hash',?)", (hb,))
                    c.execute("INSERT OR REPLACE INTO bh(block,hash) VALUES(?,?)", (b, hb)); c.execute("DELETE FROM bh WHERE block<?", (b - BH_KEEP,))
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('ts',?)", (str(int(time.time())),))
                    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('chain_head',?)", (str(head),))
                    c.commit()
                head_done = b; hh = hb
                if chunk < CHUNK0:
                    chunk = min(CHUNK0, chunk * 2)
                if logs:
                    print("indexed", len(logs), "announcements up to block", b, flush=True)
            with _lock:                                     # метка свежести и когда догнали (иначе lag/ts стоят, пока нет новых блоков)
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('ts',?)", (str(int(time.time())),))
                c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('chain_head',?)", (str(head),)); c.commit()
            rf = _meta_get(c, "reconcile_from")             # аудит 1179 F1/F4: после --rewind границы стёрты, строки брошенной ветки сверяются ДО того, как границы появятся снова
            clean = True                                    # аудит 1180 L-3: границы пишутся только если reconcile_from нет или сверка до него дошла до конца (1181 L-1: именно REC_DONE)
            if rf is not None:
                rfi = _rf_valid(rf, head_done)
                if rfi is None:                             # аудит 1181 L-2: битое или вне [START, head_done+1] значение ЗАМЕНЯЕТСЯ широким окном (а не стирается: иначе следующий проход открыл бы /known без сверки)
                    rfi = START                         # аудит 1182 I-3: точное окно (долгий первый проход), а не последние BH_KEEP блоков: строки брошенной ветки старше них не остались бы
                    with _lock: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from',?)", (str(rfi),)); c.commit()
                    if time.time() - rf_alert_t >= WAIT_ALERT_S:
                        rf_alert_t = time.time(); print("ALERT bad reconcile_from %r replaced by %d; /known stays closed until a reconcile from there completes" % (str(rf)[:40], rfi), flush=True)
                if pin is None and head_done >= START: pin = agreed(head_done, ag)[1][0]
                res = REC_NOT_REACHED if rfi > head_done else REC_DONE          # аудит 1185 I-1: окно начинается выше головы (rewind 0) -- ломтей нет, boundary не открываем вслепую, обычный reconcile ниже выполнит окно sf-REORG_WIN
                while rfi <= head_done:                     # аудит 1183 L-4: ломти; reconcile_from сдвигается только после завершённого ломтя (сбой в ломте k -- следующий проход начнёт с k), граница закрыта до последнего
                    last_slice = rfi + RF_SLICE > head_done
                    res = reconcile(c, sf, head_done, pin, insert_only=False, frm=rfi, to=None if last_slice else rfi + RF_SLICE - 1)      # последний ломоть -- прежнее окно до головы
                    if res != REC_DONE or last_slice: break
                    rfi += RF_SLICE
                    with _lock: c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from',?)", (str(rfi),)); c.commit()
                    if time.time() - rf_prog_t >= WAIT_ALERT_S:
                        rf_prog_t = time.time(); print("reconcile progress: blocks up to %d checked, %d to go; /known stays closed until it completes" % (rfi - 1, head_done - rfi + 1), flush=True)
                if res == REC_DONE:
                    with _lock: c.execute("DELETE FROM meta WHERE k='reconcile_from'"); c.commit()
                    last_rec = time.time()
                else:
                    clean = False
                    if time.time() - rf_alert_t >= WAIT_ALERT_S:
                        rf_alert_t = time.time(); print("ALERT reconcile from %d incomplete (%s); /known stays closed until it completes" % (rfi, res), flush=True)
            # safe_block -- до него /known верит строкам; final_block -- после него строку реорг уже не тронет (флаг final, страницы). Без safe (rh, узел не отдал) прежние значения остаются.
            safe_b = head_done if (MODE == "safe" or not KNOWN_SAFE) else (min(sf, head_done) if sf is not None else None)
            fin = head_done if MODE == "safe" else (max(0, safe_b - PAGES_MARGIN) if safe_b is not None else None)       # одна формула и для меты, и для страниц (аудит 1163 I-4)
            known_b = safe_b if (MODE == "safe" or not KNOWN_SAFE) else max(-1, head_done - -(-KNOWN_LAG_S * 1000 // BLOCK_MS))
            if clean: _set_meta(c, safe_block=safe_b, final_block=fin, known_block=known_b)
            if pin is None and head_done >= START: pin = agreed(head_done, ag)[1][0]
            if time.time() - last_rec >= RECONCILE_EVERY:
                reconcile(c, sf, head_done, pin, insert_only=(MODE == "safe" and not deep)); last_rec = time.time(); deep = False
            fix_rows(c, pin, head_done)
            pages_step(c, fin)
            ok_t = time.time()
        except Exception as e:
            print("index error:", str(e)[:200], flush=True)
            _rot = (_rot + 1) % max(1, len(RPCS)); pin = None   # следующая итерация начнёт с другой точки
            now = time.time()
            if now - ok_t >= WAIT_ALERT_S and now - alert_t >= WAIT_ALERT_S:
                alert_t = now; print("ALERT indexing has not advanced for %d s (endpoints disagree or fewer than %d answer): %s" % (now - ok_t, NEED, str(e)[:120]), flush=True)
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
    except RateLimited: raise                   # аудит 1167 L-3: пустое ведро -- не «Multicall3 нет»: не кэшируем ok=False на 10 минут
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
    if len(addrs) > MAX_SINGLE: raise RuntimeError("too many addresses without multicall (%d > %d)" % (len(addrs), MAX_SINGLE))     # аудит 1163 L-4: 2 вызова на адрес
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
            except RateLimited: raise                   # аудит 1167 L-3: не уходим в по-адресный путь (больше вызовов) и не сбрасываем _mc
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
        tm = None
        try:                                        # аудит 1163 L-3: Timer внутри try -- если и он не стартует, разрешение возвращается, а сокет закрывается
            try: tm = threading.Timer(REQ_DEADLINE, kill); tm.daemon = True; tm.start()
            except BaseException: tm = None; self.shutdown_request(request); return
            super().process_request_thread(request, client_address)
        finally:
            if tm is not None: tm.cancel()
            self._sem.release()


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
    if len(body) > ANN_CACHE_BYTES: return          # одна запись больше всего бюджета не кэшируется
    with _ann_lock:
        if _ann_size[0] + len(body) > ANN_CACHE_BYTES or (key not in _ann_cache and len(_ann_cache) >= ANN_CACHE_ENTRIES):     # аудит 1163 I-1: и по байтам, и по числу записей
            for k in [k for k, v in _ann_cache.items() if now - v[0] >= ANN_TTL]: _ann_size[0] -= len(_ann_cache.pop(k)[1])
            if _ann_size[0] + len(body) > ANN_CACHE_BYTES or (key not in _ann_cache and len(_ann_cache) >= ANN_CACHE_ENTRIES): _ann_cache.clear(); _ann_size[0] = 0
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
        _tl.dl = time.time() + REQ_DEADLINE; _tl.calls = 0
        u = urlparse(self.path); q = parse_qs(u.query)
        mt = ROUTE.match(u.path); route = mt.group(1) if mt else None
        one = lambda k, d="": (q.get(k, [d])[0] or "").strip()
        try:
            c = rdb()                                  # аудит 1163 I-4: внутри try -- сбой открытия БД даёт 500, а не оборванный запрос
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
                rows = c.execute("SELECT id,block,tx,scheme,stealth,caller,eph,meta,payer,paid FROM ann WHERE id>? ORDER BY id LIMIT ?", (since, limit)).fetchall()
                fb = c.execute("SELECT v FROM meta WHERE k='final_block'").fetchone(); fb = int(fb[0]) if fb else -1
                ep = c.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()
                out = [{"id": r[0], "block": r[1], "tx": r[2], "scheme": r[3], "stealth": r[4], "caller": r[5], "eph": r[6], "meta": r[7], "payer": r[8], "final": r[1] <= fb, "verified": verified(r[5], r[9], r[7])} for r in rows]
                body = json.dumps({"rows": out, "next": out[-1]["id"] if out else since, "final_block": fb if fb >= 0 else None, "epoch": int(ep[0]) if ep else 0}, separators=(",", ":")).encode()
                if canon and since <= c.execute("SELECT COALESCE(MAX(id),0) FROM ann").fetchone()[0]: _ann_put(key, now, body)       # только since в пределах таблицы: пустые ответы за хвостом не копятся (аудит 1163 I-1)
                return self._raw(200, body)
            if route == "known":
                addr = one("addr").lower()
                if not _ADDR.match(addr): return self._json(400, {"error": "addr"})
                sb = c.execute("SELECT v FROM meta WHERE k='known_block'").fetchone() or c.execute("SELECT v FROM meta WHERE k='safe_block'").fetchone(); sb = int(sb[0]) if sb else -1       # нет границы -> никого не признаём (закрыто)
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
        except RateLimited:                            # аудит 1165 L-2: общее ведро RPC пусто -- честный отказ с кодом, который клиент уже умеет повторять
            return self._json(429, {"error": "busy, retry shortly"})
        except Exception as e:
            print("api error:", str(e)[:200], flush=True)
            return self._json(500, {"error": "temporarily unavailable"})


def _rf_valid(v, head_done, lo=None):
    """Аудит 1181 L-2: reconcile_from допустим только как целое в [START, head_done + 1]; иначе None (вызывающий ЗАМЕНЯЕТ значение, а не стирает)."""
    try: x = int(v)
    except (TypeError, ValueError): return None
    lo = START if lo is None else lo
    return x if lo <= x <= head_done + 1 else None


def rewind(n):
    """Аудит 1163 M-1 / 1165 I-5: оператор отодвигает голову индекса на n блоков (СЛУЖБА ОСТАНОВЛЕНА: иначе цикл перезапишет значение своим). Строки выше остаются, перечитывание вставляет только недостающее (INSERT OR IGNORE по (tx, log_index)), а первая реконсиляция сверяет их с цепью и убирает ушедшие (reconcile_from)."""
    c = db(); r = c.execute("SELECT v FROM meta WHERE k='head'").fetchone(); st = c.execute("SELECT v FROM meta WHERE k='start'").fetchone()
    lo = (START if START is not None else int(st[0]) if st else 0) - 1
    if not r: raise SystemExit("rewind: no head in the database yet")
    new = max(lo, int(r[0]) - n)
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('head',?)", (str(new),)); c.execute("DELETE FROM meta WHERE k='head_hash'"); c.execute("DELETE FROM bh WHERE block>?", (new,))     # хэша блока new у нас нет: первый шаг его примет без сверки
    c.execute("DELETE FROM meta WHERE k IN ('known_block','safe_block','final_block')")                                                  # аудит 1179 F1: граница доверия закрыта (/known -- никого), пока полный проход заново её не посчитает
    old_rf = c.execute("SELECT v FROM meta WHERE k='reconcile_from'").fetchone()
    keep = new + 1
    if old_rf:                                                                                                                            # аудит 1180 L-3: второй --rewind не теряет диапазон первого (берётся меньшее)
        ov = _rf_valid(old_rf[0], int(r[0]), lo + 1)                                                                                      # аудит 1181 L-2: битое / вне [START, старая голова + 1] значение НЕ отбрасывается, а заменяется точным окном от START (аудит 1182 I-3)
        keep = min(ov if ov is not None else lo + 1, new + 1)
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reconcile_from',?)", (str(keep),))                                               # аудит 1179 F4: первая реконсиляция покрывает от новой головы; расходуется один раз
    _bump_epoch(c, False); c.commit()                                                                                                    # аудит 1165 I-5: клиент, считающий по epoch, перечитает; новые id у перечитанных строк он иначе не заметит
    print("rewind: head %s -> %d (rows above stay; the service re-reads from %d and only inserts what is missing)" % (r[0], new, new + 1), flush=True)


if __name__ == "__main__":
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    init_db()
    if "--refill-payers" in sys.argv or "--backfill-paid" in sys.argv:
        refill_payers(); raise SystemExit(0)
    if "--rewind" in sys.argv:
        try: n = int(sys.argv[sys.argv.index("--rewind") + 1])
        except (IndexError, ValueError): n = 0
        if n <= 0: raise SystemExit("usage: stealth_indexer.py --rewind <N blocks > 0>   (stop the service first)")
        rewind(n); raise SystemExit(0)
    threading.Thread(target=index_loop, daemon=True).start()
    print("stealth indexer", CHAIN, "mode", MODE, "conf", CONF, "on", PORT, "db", DB, "from block", START if START is not None else "(head-%d)" % BACKFILL, "stealthpay", STEALTHPAY, "legacy", ",".join(LEGACY) or "-", flush=True)
    BoundedServer(("127.0.0.1", PORT), H).serve_forever()
