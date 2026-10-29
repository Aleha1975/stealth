/* Progress card of the private transfer (DOM only via createElement/textContent). Pure view of a hop record: no network, no keys.
   h = { st (hop state, see zec-hop.js), msg (last progress text), running (this tab is driving it) } */
import { CHAINS } from "./chains.js";
import { remainingMs, STEPS, STEP_MIN } from "./zec-hop.js";

export const STEP_UI = [   // one entry per zec-hop.js STEPS item, in order
  { name: "Preparing", line: "Preparing the swap", wait: "a few seconds" },
  { name: "Converting to ZEC", line: "Converting to ZEC", wait: "~3–5 min" },
  { name: "Receiving ZEC", line: "Waiting for Zcash confirmations", wait: "~12 min" },
  { name: "Entering the shielded pool", line: "Moving the ZEC into the shielded pool", wait: "usually 2–5 min" },
  { name: "Mixing delay", line: "Mixing delay", wait: "2–10 min, random" },
  { name: "Converting back", line: "Preparing the swap back", wait: "a few seconds" },
  { name: "Sending to recipient", line: "Sending to the recipient", wait: "usually 3–10 min" },
];
const STEP_ORDER = ["QUOTE_IN", "DEPOSIT_IN", "WAIT_T", "SHIELD", "DELAY", "QUOTE_OUT", "SEND_OUT"];
/** raw 1Click status -> friendly word (the raw name never reaches the screen) */
export const friendly = s => ({ SUCCESS: "done", REFUNDED: "refunded", FAILED: "failed" })[s] || "in progress";
const short = a => a ? a.slice(0, 6) + "…" + a.slice(-4) : "";
const amt = (v, dec) => (Number(v) / 10 ** dec).toFixed(2);
export const fmtElapsed = ms => { const s = Math.max(0, Math.floor(ms / 1000)), m = Math.floor(s / 60); return m + ":" + String(s % 60).padStart(2, "0"); };
/** "27 min left" / "4:05 left" */
export const fmtLeft = ms => ms >= 600_000 ? "≈ " + Math.ceil(ms / 60_000) + " min left" : fmtElapsed(Math.max(60_000, ms)) + " left";
const LEFT = new Map();   // hop -> last shown remainder; keeps the countdown from jumping up (never +1 min between ticks, except when the step changes)
const PCT = new Map();
export const resetLeft = () => { LEFT.clear(); PCT.clear(); };
/** progress percent from time: elapsed / (elapsed + time left), 1..99 until done, never decreasing */
export function shownPct(key, st, leftMs, now) {
  const i = Math.max(0, STEPS.indexOf(st.step)), typ = STEPS.slice(0, i).reduce((a, k) => a + STEP_MIN[k] * 60_000, 0) + Math.max(0, now - (st.stepAt || now));
  const el = st.startedAt ? Math.max(0, now - st.startedAt) : typ, p = Math.min(99, Math.max(1, Math.floor(100 * el / (el + leftMs))));
  const v = Math.max(p, PCT.get(key) || 0); PCT.set(key, v); return v;
}
/** one line for the status area: "● 42% · ≈ 18 min left · Waiting for ..." */
export const statusLine = v => "● " + v.pct + "% · " + v.left + " · " + v.what;
export function shownLeft(key, step, raw, now) {
  const p = LEFT.get(key); let v = raw;
  if (p && p.step === step) { const dt = now - p.at; if (dt >= 0) v = Math.min(raw, Math.max(p.v - dt, 0) + 60_000); }   // may not rise by more than 1 min over what the previous tick would now show
  v = Math.max(60_000, v); LEFT.set(key, { step, v, at: now }); return v;
}
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

/** Everything the card says, as plain data (testable). */
export function hopView(h, now = Date.now()) {
  const st = h.st, src = CHAINS[st.chain] || {}, dst = CHAINS[st.dest] || src, tok = (src.token || { symbol: "", decimals: 6 }), dtok = dst.token || tok;
  const idx = Math.max(0, STEP_ORDER.indexOf(st.step)), ui = STEP_UI[idx];
  const v = { idx, total: STEP_UI.length, stepName: ui.name, amountLine: amt(st.amount, tok.decimals) + " " + tok.symbol + " → " + short(st.recipient),
    left: "", pct: 0, what: "", elapsed: st.startedAt ? fmtElapsed((st.doneAt || now) - st.startedAt) : "", kind: "run", title: "Private transfer in progress", line: "", body: "", detail: "", action: null, link: null };
  if (st.step === "DONE") {
    const got = st.outQuote ? amt(st.outQuote.amountOut, dtok.decimals) : amt(st.amount, tok.decimals), p = st.payoutTx;
    v.kind = "done"; v.pct = 100; v.title = "Sent privately: " + got + " " + dtok.symbol + " to " + short(st.recipient); v.amountLine = ""; v.idx = v.total;
    v.line = "Total time " + v.elapsed + " (min:sec).";
    if (p && p.hash) v.link = { text: "Payout tx " + p.hash.slice(0, 10) + "…", href: /^https:\/\//.test(p.url || "") ? p.url : (dst.explorer || "") + "/tx/" + p.hash };
  } else if (st.step === "FAILED_IN") {
    v.kind = "warn"; v.title = "Swap refunded"; v.body = "Your " + amt(st.amount, tok.decimals) + " " + tok.symbol + " is back on the stealth address (minus a small refund fee). Nothing was sent.";
    v.detail = "First swap ended as " + (st.result || "unknown") + ".";
  } else if (st.step === "FAILED") {
    v.kind = "bad"; v.title = "Transfer stopped"; v.body = "Your funds are safe. Any ZEC left sits in a temporary wallet that can be rebuilt from this payment's key."; v.action = "funds";
    v.detail = "Last swap ended as " + (st.result || "unknown") + (st.outQuote && st.outQuote.depositAddress ? " (deposit address " + st.outQuote.depositAddress + ")" : "") + "." + (h.extra ? "\n" + h.extra : "");
  } else if (h.running) {
    const hk = (st.stealth || "") + "#" + (st.n || 0), lm = shownLeft(hk, st.step, remainingMs(st, now), now); v.left = fmtLeft(lm); v.pct = shownPct(hk, st, lm, now);
    const m = /: ([A-Z_]+)$/.exec(h.msg || ""), left = st.step === "DELAY" && st.delayUntil ? Math.max(0, Math.ceil((st.delayUntil - now) / 1000)) : null;
    const state = m && (st.step === "DEPOSIT_IN" || st.step === "SEND_OUT") ? friendly(m[1]) : null;
    v.what = ui.line + (state ? " · " + state : "");
    v.line = v.what + " · " + (left != null ? fmtElapsed(left * 1000) + " left" : ui.wait);
  } else {
    v.kind = "warn"; v.title = "Transfer paused"; v.body = "Your funds are safe. Press Continue transfer to carry on from step " + (idx + 1) + " of " + v.total + ".";
    v.action = "continue"; v.detail = st.err || ""; v.pct = shownPct((st.stealth || "") + "#" + (st.n || 0), st, remainingMs(st, now), now);
  }
  return v;
}

/** Build the card. cb = { onContinue, onFunds, onDismiss } */
export function hopCard(h, cb = {}, now = Date.now()) {
  const v = hopView(h, now), card = el("div", "hop " + v.kind);
  card.appendChild(el("div", "hop-t", v.title));
  if (v.amountLine) card.appendChild(el("div", "hop-amt", v.amountLine));
  if (v.kind === "run" || v.action === "continue" || v.kind === "done") {
    const bar = el("div", "hop-bar"); bar.setAttribute("role", "progressbar"); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", String(v.total)); bar.setAttribute("aria-valuenow", String(v.kind === "done" ? v.total : v.idx + 1));
    STEP_UI.forEach((s, i) => { const seg = el("i", v.kind === "done" || i < v.idx ? "d" : i === v.idx ? "c" : ""); seg.title = (i + 1) + ". " + s.name; bar.appendChild(seg); });
    const fill = el("div", "hop-fill"), fi = el("i"); fi.style.width = v.pct + "%"; fill.appendChild(fi); card.appendChild(fill);
    if (v.kind === "run") card.appendChild(el("div", "hop-pct", v.pct + "%" + " · " + v.left));
    card.appendChild(bar);
    if (v.kind !== "done") card.appendChild(el("div", "hop-step", "Step " + (v.idx + 1) + " of " + v.total + " · " + v.stepName));
  }
  if (v.line) card.appendChild(el("div", "hop-line", v.line));
  if (v.body) card.appendChild(el("div", "hop-line", v.body));
  if (v.link) { const a = el("a", "hop-link", v.link.text); a.href = v.link.href; a.target = "_blank"; a.rel = "noopener noreferrer"; card.appendChild(a); }
  if (h.running) card.appendChild(el("div", "note hop-foot", "Keep this tab open · " + v.elapsed + " elapsed"));
  if (v.detail) { const d = el("details", "hop-det"); d.appendChild(el("summary", null, "details")); d.appendChild(el("div", "note", v.detail)); card.appendChild(d); }
  const acts = el("div", "row hop-act");
  const btn = (txt, cls, fn) => { const b = el("button", "btn " + cls, txt); b.type = "button"; b.addEventListener("click", () => fn(b)); acts.appendChild(b); };
  if (v.action === "continue") btn("Continue transfer", "", b => cb.onContinue && cb.onContinue(b));
  if (v.action === "funds") btn("Show funds", "", b => cb.onFunds && cb.onFunds(b));
  if (!h.running && (v.kind === "done" || v.kind === "warn" && !v.action)) btn("Dismiss", "ghost", () => cb.onDismiss && cb.onDismiss());
  if (acts.childNodes.length) card.appendChild(acts);
  return card;
}
