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

/** Audit 1113 I-1: one canonical form for allow-list entries: an optional prefix length (/64, /128) is dropped, then the same ipKey() as for requests (compressed IPv6 included). */
export const allowKey = x => ipKey(String(x).trim().replace(/\/\d{1,3}$/, ""));
export const parseAllow = str => new Set(String(str || "").split(",").map(x => x.trim()).filter(Boolean).map(x => safeIp(allowKey(x))));

/** Audit 1113 M-3: a small in-memory counter map: LRU (a touched key moves to the back), bounded. */
export function makeCounters(max = 20000) {
  const m = new Map();
  return { get: k => m.get(k) || 0, inc(k) { const n = (m.get(k) || 0) + 1; m.delete(k); m.set(k, n); capMap(m, max); return n; }, clear: () => m.clear(), size: () => m.size };
}

/** Audit 1099 M-2 / 1108: abuse limits are PER KEY only (key = ipKey: IPv4 or IPv6 /64). Nothing here is global state, so no party can lock out another key.
 *  makeFailBudget: a cheap counter of failed requests per key and hour (offline-rejected junk costs ~0 to refuse; nginx limits the rate). Memory bounded by `maxKeys`.
 *  makeTokenBucket: admission of RPC-costly requests per key (burst `cap`, one token back every `refillMs`). */
export function makeFailBudget({ perKey = 30, maxKeys = 10000, now = () => Date.now() } = {}) {
  const per = new Map();
  const cur = k => { const e = per.get(k); if (!e) return 0; if (now() - e.t > 3600_000) { per.delete(k); return 0; } return e.n; };
  return {
    /** null if allowed, else the refusal text */
    check(k) { return cur(k) >= perKey ? "too many failed requests from this network, try again later" : null; },
    /** w = weight toward the per-key hour budget (honest state refusals weigh less, audit 1102 L-1) */
    fail(k, w = 1) {
      const t = now(), e = per.get(k);
      if (e && t - e.t <= 3600_000) { e.n += w; per.delete(k); per.set(k, e); }   // audit 1113 I-3: LRU, a failing key moves to the back
      else { per.delete(k); per.set(k, { n: w, t }); }
      capMap(per, maxKeys);
    },
    size: () => per.size,
  };
}
export function makeTokenBucket({ cap = 20, refillMs = 10_000, maxKeys = 10000, now = () => Date.now() } = {}) {
  const m = new Map();
  const level = k => { const e = m.get(k), t = now(); if (!e) return cap; return Math.min(cap, e.n + (t - e.t) / refillMs); };
  const put = (k, n) => { m.delete(k); m.set(k, { n, t: now() }); capMap(m, maxKeys); };
  return {
    take(k) { const n = level(k); if (n < 1) return false; put(k, n - 1); return true; },
    refund(k) { if (m.has(k)) put(k, Math.min(cap, level(k) + 1)); },
    size: () => m.size,
  };
}

/** Audit 1099 M-2: at most `max` log lines of a kind per minute; the rest is counted and reported by one summary line. take() returns true (log it) / false (suppress);
 *  flush() returns the number suppressed in the finished minute (or 0). */
export function makeLineLimiter(max = 20, now = () => Date.now()) {
  let start = 0, n = 0, dropped = 0;
  return { take() { const t = now(); let summary = 0; if (t - start >= 60_000) { summary = dropped; start = t; n = 0; dropped = 0; } n++; if (n > max) { dropped++; return { log: false, summary }; } return { log: true, summary }; } };
}

/** Audit 1102 L-3: FiatToken-style contracts reject high-s signatures (s > n/2); reject them offline, before any RPC. */
export const SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
export const isLowS = s => { try { const x = BigInt(s); return x > 0n && x <= SECP_N / 2n; } catch { return false; } };

/** Audit 1107 L-1: a refusal thrown by the state-dependent checks. honest = depends on the caller's own state (weight 0.2 against the shared per-network budget, so one abuser
 *  behind a shared IPv4 cannot lock honest users out with ordinary errors). failWeight looks at the class, never at message text
 *  (messages can embed user input, e.g. BigInt SyntaxErrors). */
export class Refusal extends Error {
  constructor(msg, { honest = false, unknown = false, net = false } = {}) { super(msg); this.name = "Refusal"; this.honest = honest; this.unknown = unknown; this.net = net; }   // audit 1120 M-1: net = not caused by a fresh signed request of the signer (replay, used, expired, being confirmed): charged to the NETWORK key, never to the signer
}
/** Infrastructure trouble (RPC / indexer down or slow) after the offline checks. Answered 503; consumes no failure budget. */
export class Upstream extends Error { constructor(msg) { super(msg); this.name = "Upstream"; } }
/** The pay fee (token units) required for a payment of `amount`: the flat fee/minimum, or `bps` basis points of the amount (rounded UP) when that is more. bps 0 = the flat fee only.
 *  Same formula as payFeeFor in web/pay-auth.js (a test keeps the two equal). */
export const payFeeFor = (amount, flat, bps = 0) => { const p = (BigInt(amount) * BigInt(bps) + 9999n) / 10000n; return p > BigInt(flat) ? p : BigInt(flat); };
export const failWeight = e => (e instanceof Refusal && e.honest ? 0.2 : 1);

/** Audit 1108 M-3: classify an error by CAUSE (viem error names along the .cause chain, never the caller's text). Demonstrable transport trouble -> Upstream (503, nothing charged);
 *  a simulation revert -> Refusal (charged to the key); anything else -> Refusal{unknown} (charged at weight 1, never refunded). */
const TRANSPORT = /^(TimeoutError|WebSocketRequestError|SocketClosedError)$/;
const REVERT = /^(ContractFunctionRevertedError|ExecutionRevertedError)$/;
/** A plain HTTP 429 anywhere in the cause chain (the provider rate-limiting us). */
export const rateLimited = e => { for (let x = e, i = 0; x && i < 8; i++, x = x.cause) if (x.status === 429) return true; return false; };
export function classifyError(e) {
  if (e instanceof Refusal || e instanceof Upstream) return e;
  let transport = false, revert = false;
  for (let x = e, i = 0; x && i < 8; i++, x = x.cause) {
    const n = String(x.name || "");
    // audit 1113 L-3: an HTTP error counts as infrastructure trouble only without a status (connection level) or with a 5xx status; 4xx (403, 413) is not. 1135 L-1: 429 is the provider's rate limit on US, not the signer's doing: Upstream, never charged
    if (TRANSPORT.test(n) || (n === "HttpRequestError" && !(x.status < 500)) || (typeof x.status === "number" && x.status >= 500) || x.status === 429 || (n === "TypeError" && /fetch failed/i.test(String(x.message)))) transport = true;
    if (REVERT.test(n) || /execution reverted/i.test(String(x.details || x.shortMessage || ""))) revert = true;
  }
  if (transport) return new Upstream(String(e && (e.shortMessage || e.message) || e).slice(0, 100));
  if (revert) return new Refusal("the transaction would fail on chain");
  return Object.assign(new Refusal("the request could not be processed", { unknown: true }), { detail: String(e && ((e.details ? e.shortMessage + " / " + e.details : e.shortMessage) || e.message) || e).slice(0, 160) });
}
