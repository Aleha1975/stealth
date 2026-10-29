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
