/* Sanctions screening: loads sanctions/evm.json (written by update.py from the OFAC SDN list) and reloads it whenever the file changes
   (mtime checked at most once a second, no restart needed). Fail-closed on a first-load failure unless the file is absent AND
   STEALTH_SANCTIONS_OPTIONAL=1 (then screening is off and a warning is logged). A later broken reload keeps the previous list. */
import fs from "fs"; import path from "path"; import { fileURLToPath } from "url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SANCTIONS_ERROR = "address is on a sanctions list";
export function makeScreen(file = process.env.STEALTH_SANCTIONS_FILE || path.join(HERE, "evm.json"), log = console.log) {
  let set = null, mtime = 0, checked = 0, meta = {};
  const reload = () => {
    const now = Date.now(); if (set && now - checked < 1000) return; checked = now;
    try {
      const m = fs.statSync(file).mtimeMs; if (set && m === mtime) return;
      const j = JSON.parse(fs.readFileSync(file, "utf8"));
      if (!Array.isArray(j.addresses)) throw new Error("no addresses array");
      set = new Set(j.addresses.map(a => String(a).toLowerCase())); mtime = m; meta = { count: set.size, published: j.published, fetched: j.fetched };
      log("sanctions list loaded:", set.size, "addresses, published", j.published);
    } catch (e) {
      if (set) { log("ALERT sanctions list reload failed, keeping previous:", String(e).slice(0, 80)); return; }
      if (process.env.STEALTH_SANCTIONS_OPTIONAL === "1" && e.code === "ENOENT") { log("WARN sanctions list missing, screening OFF"); set = new Set(); return; }
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
