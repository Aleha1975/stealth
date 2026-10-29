/* Sanctions screening: loads sanctions/evm.json (written by update.py from the OFAC SDN list) and reloads it whenever the file changes
   (mtime checked at most once a second, no restart needed). Fail-closed on a first-load failure unless the file is absent AND
   STEALTH_SANCTIONS_OPTIONAL=1 (then screening is off and a warning is logged). A later broken reload keeps the previous list. */
import fs from "fs"; import path from "path"; import { fileURLToPath } from "url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SANCTIONS_ERROR = "address is on a sanctions list";
export function makeScreen(file = process.env.STEALTH_SANCTIONS_FILE || path.join(HERE, "evm.json"), log = console.log) {
  let set = null, mtime = 0, checked = 0, meta = {};
  // audit 1087 L-3: old list = persistent ALERT (at most hourly; stealth_watch forwards it), refusal to serve would turn a broken timer into an outage for everyone
  let staleAt = 0;
  const stale = () => {
    const maxDays = Number(process.env.STEALTH_SANCTIONS_MAX_AGE_DAYS || 14), t = Date.parse(meta.fetched || "");
    if (Number.isFinite(t) && Date.now() - t > maxDays * 86400000 && Date.now() - staleAt > 3600_000) { staleAt = Date.now(); log("ALERT sanctions list is older than", maxDays, "days (fetched " + meta.fetched + "): the daily updater is not running"); }
  };
  const reload = () => {
    const now = Date.now(); if (set && now - checked < 1000) return; checked = now;
    try {
      const m = fs.statSync(file).mtimeMs; if (set && m === mtime) { stale(); return; }
      const j = JSON.parse(fs.readFileSync(file, "utf8"));
      if (!Array.isArray(j.addresses)) throw new Error("no addresses array");
      // audit 1087 L-3: a broken updater must not leave us with an empty list. Minimum size is configurable (the shipped list has 127; tests use tiny fixtures).
      const min = Number(process.env.STEALTH_SANCTIONS_MIN || 1); if (j.addresses.length < min) throw new Error("list has " + j.addresses.length + " addresses, minimum " + min);
      set = new Set(j.addresses.map(a => String(a).toLowerCase())); mtime = m; meta = { count: set.size, published: j.published, fetched: j.fetched };
      log("sanctions list loaded:", set.size, "addresses, published", j.published);
      stale();
    } catch (e) {
      if (set) { log("ALERT sanctions list reload failed, keeping previous:", String(e).slice(0, 80)); return; }
      if (process.env.STEALTH_SANCTIONS_OPTIONAL === "1" && e.code === "ENOENT") { log("ALERT sanctions list missing, screening is OFF (STEALTH_SANCTIONS_OPTIONAL=1: lab use only)"); set = new Set(); return; }
      throw new Error("sanctions list unavailable: " + String(e).slice(0, 80));   // fail closed
    }
  };
  reload();
  return {
    isListed(addr) { reload(); return set.has(String(addr || "").toLowerCase()); },
    /** throws SANCTIONS_ERROR if any address is listed; logs which role matched */
    check(roles, ip) {
      reload();
      for (const [role, a] of Object.entries(roles)) if (a && set.has(String(a).toLowerCase())) { log("sanctions refused", role, a, "ip", ip || "-"); throw new Error(SANCTIONS_ERROR); }
    },
    meta: () => (reload(), meta),
  };
}
