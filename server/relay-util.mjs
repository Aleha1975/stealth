/* Small pure helpers of the relayer (no env, no network), so they can be unit-tested on their own. */

/** Audit 1087 L-1: log lines are parsed by stealth_watch.py (ALERT / reverted). User-controlled text must never be able to start a new line:
 *  every control character, CR/LF and the Unicode line separators become one space. */
export const cleanLog = s => String(s).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");

/** Audit 1087 M-1: the key of the per-network limit. IPv4 as is; an IPv6 address becomes its /64 (one customer owns a whole /64, so per-address limits cost the attacker nothing);
 *  IPv4-mapped IPv6 (::ffff:a.b.c.d) is the IPv4 address. Anything unparsable is kept as it is. */
export function ipKey(ip) {
  ip = String(ip || "").trim().toLowerCase().split("%")[0];
  if (!ip.includes(":")) return ip;
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return m[1];
  let g;
  if (ip.includes("::")) { const [a, b, ...rest] = ip.split("::"); if (rest.length) return ip; const ha = a ? a.split(":") : [], hb = b ? b.split(":") : [], gap = 8 - ha.length - hb.length; if (gap < 1) return ip; g = [...ha, ...Array(gap).fill("0"), ...hb]; }
  else g = ip.split(":");
  if (g.length !== 8 || g.some(x => !/^[0-9a-f]{1,4}$/.test(x))) return ip;
  return g.slice(0, 4).map(x => x.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

/** Audit 1087 L-2: one line of an env file. `KEY=value`, `KEY="value # kept"`, `KEY='x'`, `KEY=value  # comment`; quotes may hold # and the other quote. Returns [key, value] or null. */
export function parseEnvLine(line) {
  const m = String(line).match(/^\s*(?:export\s+)?([A-Z0-9_]+)=(?:"([^"]*)"|'([^']*)'|([^#\n]*?))\s*(?:#.*)?$/);
  return m ? [m[1], (m[2] ?? m[3] ?? m[4] ?? "").trim()] : null;
}

/** Audit 1099 M-1: user-influenced text in a log line must not contain the words the watchdog keys on. The words are broken up (ALERT -> A_LERT, reverted -> rev_erted);
 *  the watchdog additionally matches only fixed line templates (stealth_watch.py), so this is the second layer. */
export const neutral = s => cleanLog(s).replace(/alert/gi, m => m[0] + "_" + m.slice(1)).replace(/reverted/gi, m => m.slice(0, 3) + "_" + m.slice(3));

/** Audit 1099 M-1: an address-like token for the log; anything else becomes "-". */
export const safeIp = ip => (/^[0-9a-fA-F:.\/]{1,64}$/.test(String(ip)) ? String(ip) : "-");

/** Audit 1099 I-2: keep a Map bounded by dropping the OLDEST entries (insertion order), never clear it wholesale. */
export function capMap(m, max) { while (m.size > max) m.delete(m.keys().next().value); }

/** Audit 1099 M-2: failure budgets, independent of nginx. Per network key (ipKey): at most `perKey` failures per hour; globally at most `perMin` failures per minute --
 *  while the global rate is exceeded, networks that have already failed in this hour are refused before any RPC; clean networks still pass. Memory bounded by `maxKeys`. */
export function makeFailBudget({ perKey = 30, perMin = 120, maxKeys = 10000, now = () => Date.now() } = {}) {
  const per = new Map(); let winStart = 0, winN = 0;
  const cur = k => { const e = per.get(k); if (!e) return 0; if (now() - e.t > 3600_000) { per.delete(k); return 0; } return e.n; };
  return {
    /** null if allowed, else the refusal text */
    check(k) {
      const n = cur(k);
      if (n >= perKey) return "too many failed requests from this network, try again later";
      if (n > 0 && now() - winStart < 60_000 && winN >= perMin) return "the relayer is busy with failing requests, try again later";
      return null;
    },
    fail(k) {
      const t = now(); if (t - winStart >= 60_000) { winStart = t; winN = 0; } winN++;
      const e = per.get(k); if (e && t - e.t <= 3600_000) e.n++; else { per.delete(k); per.set(k, { n: 1, t }); }
      capMap(per, maxKeys);
    },
    size: () => per.size,
  };
}

/** Audit 1099 M-2: at most `max` log lines of a kind per minute; the rest is counted and reported by one summary line. take() returns true (log it) / false (suppress);
 *  flush() returns the number suppressed in the finished minute (or 0). */
export function makeLineLimiter(max = 20, now = () => Date.now()) {
  let start = 0, n = 0, dropped = 0;
  return { take() { const t = now(); let summary = 0; if (t - start >= 60_000) { summary = dropped; start = t; n = 0; dropped = 0; } n++; if (n > max) { dropped++; return { log: false, summary }; } return { log: true, summary }; } };
}
