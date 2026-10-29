#!/usr/bin/env python3
"""Stealth watchdog: one run = one check of every chain (run each minute by stealth-watch.timer).

Per chain checks:
  indexer   GET <idx>/stealth-api/head answers; lag in blocks (chain_head - head) and age in seconds (now - ts) under thresholds
  relayer   GET <rel>/stealth-api/relay/stats answers; relayer native balance >= threshold (eth_getBalance on the chain RPC from chains.json / env)
  log       relayer log: new lines containing "ALERT" or "reverted" since the previous run (byte offset kept in the state file)
Alerts: ONE Telegram message per run (all new problems together). The same alert key is re-sent at most once per ALERT_REPEAT_S (6 h);
when a key that was alerting is healthy again a single "recovered" message is sent. State: JSON file (atomic write).
Telegram: env TG_BOT_TOKEN / TG_CHAT_ID; without them the message goes to stdout (journal). Replace `notify()` to plug another channel.

Env:
  STEALTH_WATCH_CHAINS   "name=idx_url|relayer_url|relayer_log|min_balance_eth;name2=..."  (default: base + rh as in rh.env.example)
  STEALTH_WATCH_STATE    default /opt/stealth/data-watch/watch_state.json
  STEALTH_WATCH_MAX_LAG_BLOCKS[_<name>]  default 60 (base) / 400 (rh)      STEALTH_WATCH_MAX_AGE_S  default 120
  STEALTH_WATCH_REPEAT_S default 21600
Exit code is always 0 (a oneshot unit must not flap); problems are reported through notify()."""
import json, os, re, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
E = os.environ
STATE_FILE = E.get("STEALTH_WATCH_STATE", "/opt/stealth/data-watch/watch_state.json")
REPEAT_S = int(E.get("STEALTH_WATCH_REPEAT_S", str(6 * 3600)))
MAX_AGE = int(E.get("STEALTH_WATCH_MAX_AGE_S", "120"))
ALERT_TEMPLATES = ("relayer balance low", "state save failed", "nonce gap fill failed", "sanctions list is older than", "sanctions list reload failed", "sanctions list missing",
                   "receipt wait failed", "fee sent but main failed")
LOG_TEMPLATE = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z (?:ALERT (" + "|".join(re.escape(t) for t in ALERT_TEMPLATES) + r")|reverted (?:main|fee|pay) 0x[0-9a-fA-F]{64}$)")
DEFAULT_CHAINS = ("base=http://127.0.0.1:3873|http://127.0.0.1:3874|/opt/stealth/relayer.base.log|0.0003;"
                  "rh=http://127.0.0.1:3883|http://127.0.0.1:3884|/opt/stealth/data-rh/relayer.rh.log|0.0003")


def get_json(url, timeout=8):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "stealth-watch/1"}), timeout=timeout) as r:
        return json.load(r)


def rpc(urls, method, params, timeout=10):
    last = None
    for u in urls:
        try:
            req = urllib.request.Request(u, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                         {"Content-Type": "application/json", "User-Agent": "stealth-watch/1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.load(r)
            if "error" not in d:
                return d["result"]
            last = d["error"]
        except Exception as e:
            last = e
    raise RuntimeError(str(last)[:100])


def notify(text):
    tok, chat = E.get("TG_BOT_TOKEN", ""), E.get("TG_CHAT_ID", "")
    if not (tok and chat):
        print("NOTIFY (no telegram configured):", text, flush=True); return
    try:
        data = json.dumps({"chat_id": chat, "text": text[:3900], "disable_web_page_preview": True}).encode()
        urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % tok, data, {"Content-Type": "application/json"}), timeout=15).read()
    except Exception as e:
        print("telegram send failed:", str(e).replace(tok, "***")[:120], flush=True)
        raise


def load_state():
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {"alerts": {}, "log_pos": {}}


def save_state(st):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE_FILE)


def chain_cfg():
    out = []
    for part in E.get("STEALTH_WATCH_CHAINS", DEFAULT_CHAINS).split(";"):
        if "=" not in part: continue
        name, rest = part.split("=", 1); f = rest.split("|")
        out.append({"name": name.strip(), "idx": f[0].rstrip("/"), "rel": f[1].rstrip("/"), "log": f[2] if len(f) > 2 else "", "min_eth": float(f[3]) if len(f) > 3 else 0.0003})
    return out


def check_chain(c, st):
    """Returns {alert_key: message} for problems found now."""
    n = c["name"]; probs = {}
    ch = json.load(open(os.path.join(HERE, "chains.json"))).get(n, {})
    # indexer
    try:
        h = get_json(c["idx"] + "/stealth-api/head")
        lag = h.get("lag"); age = int(time.time()) - h["ts"] if h.get("ts") else None
        mx = int(E.get("STEALTH_WATCH_MAX_LAG_BLOCKS_" + n, E.get("STEALTH_WATCH_MAX_LAG_BLOCKS", "60" if n == "base" else "400")))
        if h.get("head") is None: probs[n + ":idx-empty"] = "[%s] indexer has no head yet" % n
        if lag is not None and lag > mx: probs[n + ":idx-lag"] = "[%s] indexer lag %d blocks (max %d), head %s" % (n, lag, mx, h.get("head"))
        if age is not None and age > MAX_AGE: probs[n + ":idx-age"] = "[%s] indexer last update %d s ago (max %d)" % (n, age, MAX_AGE)
    except Exception as e:
        probs[n + ":idx-down"] = "[%s] indexer not answering: %s" % (n, str(e)[:80])
    # relayer + balance
    try:
        s = get_json(c["rel"] + "/stealth-api/relay/stats")
        try:
            urls = [u for u in [os.environ.get(k) for k in ch.get("rpc_env", [])] + ch.get("rpcs", []) if u]
            bal = int(rpc(urls, "eth_getBalance", [s["relayer"], "latest"]), 16) / 1e18
            if bal < c["min_eth"]: probs[n + ":balance"] = "[%s] relayer %s balance %.6f ETH < %.6f" % (n, s["relayer"], bal, c["min_eth"])
        except Exception as e:
            probs[n + ":rpc"] = "[%s] cannot read relayer balance: %s" % (n, str(e)[:80])
        try:
            spent, budget = float(s["gas_spent_today_eth"]), float(s["gas_budget_eth"])
            if budget > 0 and spent >= 0.8 * budget: probs[n + ":budget"] = "[%s] daily gas budget %.0f%% used (%.6f/%.6f ETH)" % (n, 100 * spent / budget, spent, budget)
        except Exception:
            pass
    except Exception as e:
        probs[n + ":rel-down"] = "[%s] relayer not answering: %s" % (n, str(e)[:80])
    # relayer log: new ALERT / reverted lines since last run
    if c["log"] and os.path.exists(c["log"]):
        try:
            size = os.path.getsize(c["log"]); pos = st["log_pos"].get(c["log"])
            if pos is None or pos > size: pos = size           # first run / rotated: start from now
            with open(c["log"], "rb") as f:
                f.seek(pos); chunk = f.read(256 * 1024).decode("utf8", "replace")
                st["log_pos"][c["log"]] = f.tell()
            # audit 1099 M-1: only the relayer's FIXED line templates count ("<ISO time> ALERT <template> ..." / "<ISO time> reverted ..."); user-influenced text
            # is logged only as later arguments, never at the template position, and the relayer breaks up the words ALERT/reverted inside it
            bad = {}
            for l in chunk.splitlines():
                m = LOG_TEMPLATE.match(l)
                if m: bad.setdefault((m.group(1) or "reverted").strip().replace(" ", "-"), []).append(l)
            for kind, ls in bad.items():
                # one key per template: a different real alert is never swallowed by an earlier one; repeated identical alerts stay deduplicated for 6 h
                probs[n + ":log-" + kind] = "[%s] relayer log: %d new '%s' line(s); last: %s" % (n, len(ls), kind, ls[-1][:200])
        except Exception as e:
            probs[n + ":log-read"] = "[%s] cannot read relayer log: %s" % (n, str(e)[:80])
    return probs


def main():
    st = load_state(); st.setdefault("alerts", {}); st.setdefault("log_pos", {}); now = time.time()
    probs = {}
    for c in chain_cfg():
        try: probs.update(check_chain(c, st))
        except Exception as e: probs[c["name"] + ":watch"] = "[%s] watchdog error: %s" % (c["name"], str(e)[:100])
    lines = []
    for k, msg in probs.items():
        a = st["alerts"].get(k)
        if not a or now - a["sent"] >= REPEAT_S:
            lines.append("ALERT " + msg); st["alerts"][k] = {"sent": now, "first": a["first"] if a else now, "msg": msg}
        else:
            st["alerts"][k]["msg"] = msg                          # still firing, already told within 6 h
    rec = []
    for k in list(st["alerts"]):
        if k not in probs and ":log-" not in k:
            rec.append("RECOVERED " + st["alerts"].pop(k)["msg"])
        elif k not in probs:                                     # log-based alerts clear after one quiet run, no "recovered" noise
            if now - st["alerts"][k]["sent"] >= REPEAT_S: st["alerts"].pop(k)
    text = "\n".join(lines + rec)
    if text:
        try: notify("Stealth watchdog\n" + text)
        except Exception:
            # send failed: forget "sent" so the next run retries
            for k in list(st["alerts"]):
                if any(("ALERT " + st["alerts"][k]["msg"]) == l for l in lines): st["alerts"][k]["sent"] = 0
    save_state(st)
    print(time.strftime("%H:%M:%S"), "problems:", sorted(probs) or "none", flush=True)


if __name__ == "__main__":
    main()
