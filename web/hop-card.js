/* Progress card of the private transfer (DOM only via createElement/textContent). Pure view of a hop record: no network, no keys.
   h = { st (hop state, see zec-hop.js), msg (last progress text), running (this tab is driving it) } */
import { CHAINS } from "./chains.js";
import { remainingMs, STEPS, STEP_MIN, partsLabel, modeOf } from "./zec-hop.js";

export const STEP_UI = [   // one entry per zec-hop.js STEPS item, in order
  { name: "Preparing", line: "Preparing the swap", wait: "a few seconds" },
  { name: "Converting to ZEC", line: "Converting to ZEC", wait: "~" + Math.round(STEP_MIN.DEPOSIT_IN) + " min" },
  { name: "Receiving ZEC", line: "Waiting for Zcash confirmations", wait: "~" + Math.round(STEP_MIN.WAIT_T) + " min" },
  { name: "Entering the shielded pool", line: "Moving the ZEC into the shielded pool", wait: "~" + Math.round(STEP_MIN.SHIELD) + " min" },
  { name: "Mixing delay", line: "Mixing delay", wait: "random" },
  { name: "Converting back", line: "Preparing the swap back", wait: "a few seconds" },
  { name: "Sending to recipient", line: "Sending to the recipient", wait: "~" + Math.round(STEP_MIN.SEND_OUT) + " min" },
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
/** 1129 / owner: the percent is a function of REAL progress only: steps that are completed, plus sub-progress inside the current step that comes from something the machine has actually seen (Zcash confirmations n/T, the payout part index,
 *  and the mixing delay's own timer while the machine is alive). It never advances on elapsed time alone: a step that has not finished stays below its end, and a stuck hop stays where it is. Weights are the typical step times.
 *  The three payout steps are shared by the payout parts: part j of k contributes j/k of them done before it starts. 1..99 until done; it never goes down within a run. */
export function realProgress(st, sub = 0) {
  const i = Math.max(0, STEPS.indexOf(st.step)), w = k => STEP_MIN[k], di = STEPS.indexOf("DELAY"), parts = Array.isArray(st.parts) ? st.parts.length : 0, pIdx = st.partIdx || 0;
  const pre = STEPS.slice(0, di).reduce((a, k) => a + w(k), 0), pay = STEPS.slice(di).reduce((a, k) => a + w(k), 0), total = pre + pay, f = Math.min(0.95, Math.max(0, sub));
  let done;
  if (i < di) done = STEPS.slice(0, i).reduce((a, k) => a + w(k), 0) + f * w(st.step);
  else { const k = Math.max(1, parts), inPart = STEPS.slice(di, i).reduce((a, x) => a + w(x), 0) + f * w(st.step); done = pre + pay * (Math.min(pIdx, k - 1) + inPart / pay) / k; }
  return Math.min(99, Math.max(1, Math.floor(100 * done / total)));
}
/** sub-progress 0..1 inside the current step, only from facts: "(n/T)" in the last message of the confirmation wait; the delay's elapsed share of its own scheduled length while the machine is alive */
export function subProgress(h, now = Date.now()) {
  const st = h.st, m = /\((\d+)\/(\d+)\)/.exec(h.msg || "");
  if (st.step === "WAIT_T" && m && Number(m[2]) > 0) return Number(m[1]) / Number(m[2]);
  if (st.step === "DELAY" && st.delayUntil && st.stepAt && h.running && h.beatAt && now - h.beatAt <= STALE_MS) { const len = st.delayUntil - st.stepAt; return len > 0 ? Math.min(1, Math.max(0, (now - st.stepAt) / len)) : 0; }
  return 0;
}
export function shownPct(key, st, sub, now) {
  const v = Math.max(realProgress(st, sub), PCT.get(key) || 0); PCT.set(key, v); return v;
}
/** one line for the status area: "● 42% · ≈ 18 min left · Waiting for ..." */
export const statusLine = v => "● " + v.pct + "% · " + v.left + " · " + v.what;
export function shownLeft(key, step, raw, now) {
  const p = LEFT.get(key); let v = raw;
  if (p && p.step === step) { const dt = now - p.at; if (dt >= 0) v = Math.min(raw, Math.max(p.v - dt, 0) + 60_000); }   // may not rise by more than 1 min over what the previous tick would now show
  v = Math.max(60_000, v); LEFT.set(key, { step, v, at: now }); return v;
}
export const STALE_MS = 30_000;
/** one short line from a raw error (first line, no stack/URL noise, max 140 chars) */
export const oneLine = e => String(e || "").split("\n")[0].replace(/https?:\/\/\S+/g, "…").replace(/\s+/g, " ").trim().slice(0, 140);
/** the live sub-step text from the machine's last progress message; plain status echoes ("... : PENDING_DEPOSIT") and empty text give "" so the generic step line stays */
export const subStep = m => { m = String(m || "").trim(); return !m || /: [A-Z_]+$/.test(m) || /^Private transfer/.test(m) ? "" : m.replace(/…$/, ""); };
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

/** Everything the card says, as plain data (testable). */
export function hopView(h, now = Date.now()) {
  const st = h.st, src = CHAINS[st.chain] || {}, dst = CHAINS[st.dest] || src, tok = (src.token || { symbol: "", decimals: 6 }), dtok = dst.token || tok;
  const idx = Math.max(0, STEP_ORDER.indexOf(st.step)), ui0 = STEP_UI[idx], pl = partsLabel(st), inParts = pl && idx >= STEP_ORDER.indexOf("DELAY");    // "payout 2 of 3" on the three payout steps
  const m = st.mode ? modeOf(st.mode) : null, delayWait = m ? (m.totalMax >= 60 ? "random, spread over " + m.totalMin / 60 + "–" + m.totalMax / 60 + " h" : m.totalMin + "–" + m.totalMax + " min, random") : "2–10 min, random";
  const ui = { ...ui0, name: ui0.name + (inParts ? " · " + pl : ""), line: ui0.line + (inParts ? " (" + pl + ")" : ""), wait: st.step === "DELAY" ? delayWait : ui0.wait };
  const v = { idx, total: STEP_UI.length, stepName: ui.name, amountLine: st.rebuilt ? (Number(st.zecFound || 0) / 1e8) + " ZEC (found on the chain)" + (st.recipient ? " → " + short(st.recipient) : "") : amt(st.amount, tok.decimals) + " " + tok.symbol + " → " + short(st.recipient),
    left: "", pct: 0, what: "", elapsed: st.startedAt ? fmtElapsed((st.doneAt || now) - st.startedAt) : "", kind: "run", title: "Private transfer in progress", line: "", note: "", body: "", detail: "", action: null, link: null };
  if (st.step === "DONE") {
    const got = st.outTotal ? amt(st.outTotal, dtok.decimals) : st.outQuote ? amt(st.outQuote.amountOut, dtok.decimals) : amt(st.amount, tok.decimals), p = st.payoutTx;
    v.kind = "done"; v.pct = 100; v.title = "Sent privately: " + got + " " + dtok.symbol + " to " + short(st.recipient); v.amountLine = ""; v.idx = v.total;
    v.line = "Total time " + v.elapsed + " (min:sec).";
    if (p && p.hash) v.link = { text: "Payout tx " + p.hash.slice(0, 10) + "…", href: /^https:\/\//.test(p.url || "") ? p.url : (dst.explorer || "") + "/tx/" + p.hash };
  } else if (st.step === "FAILED_IN") {
    v.kind = "warn"; v.title = "Swap refunded"; v.body = "Your " + amt(st.amount, tok.decimals) + " " + tok.symbol + " should be back on the stealth address (minus a small refund fee): check the balance. Nothing was sent.";
    v.detail = "First swap ended as " + (st.result || "unknown") + "." + (st.inDeposit ? " Deposit address " + st.inDeposit + (st.txIn ? ", transaction " + st.txIn : "") + "." : "");
  } else if (st.step === "FAILED" && st.earlierFunds) {       // 1111 L-4: a new transfer was refused because this earlier one still holds ZEC
    v.kind = "warn"; v.title = "Earlier transfer still holds ZEC"; v.body = "Finish or return the earlier transfer first. Press Return money to send the ZEC back to your wallet, then start the new transfer."; v.zec = true;
  } else if (st.step === "FAILED") {
    v.kind = "bad"; v.title = "Transfer stopped"; v.body = "Your funds are safe. Any ZEC left sits in a temporary wallet that can be rebuilt from this payment's key."; v.action = "funds";
    v.detail = "Last swap ended as " + (st.result || "unknown") + (st.outQuote && st.outQuote.depositAddress ? " (deposit address " + st.outQuote.depositAddress + ")" : "") + "." + (h.extra ? "\n" + h.extra : "");
  } else if (h.running) {
    const hk = (st.stealth || "") + "#" + (st.n || 0), lm = shownLeft(hk, st.step, remainingMs(st, now), now); v.left = fmtLeft(lm); v.pct = shownPct(hk, st, subProgress(h, now), now);
    const m = /: ([A-Z_]+)$/.exec(h.msg || ""), left = st.step === "DELAY" && st.delayUntil ? Math.max(0, Math.ceil((st.delayUntil - now) / 1000)) : null;
    const state = m && (st.step === "DEPOSIT_IN" || st.step === "SEND_OUT") ? friendly(m[1]) : null;
    const sub = subStep(h.msg), age = h.beatAt ? now - h.beatAt : 0;       // the live sub-step ("Waiting for Zcash confirmations (7/10)") replaces the generic step line
    v.what = sub || ui.line + (state ? " · " + state : "");
    v.line = v.what + " · " + (left != null ? fmtElapsed(left * 1000) + " left" : ui.wait);
    if (age > STALE_MS) v.note = "No update for " + Math.round(age / 1000) + " s" + (h.hidden ? ": this tab is in the background, so the browser slows it down. Bring it to the front and keep the screen on." : ". Still trying; if this stays, press Continue transfer after it pauses.");
    else if (h.hidden) v.note = "This tab is in the background: updates may be slow. Keep it in front and the screen on.";
  } else {
    const early = idx < STEPS.indexOf("WAIT_T");               // nothing has left the stealth address yet / no ZEC exists yet
    const cause = oneLine(st.err), wait = h.retryAt && h.retryAt > now ? Math.ceil((h.retryAt - now) / 1000) : 0;
    v.kind = "warn"; v.title = "Transfer paused"; v.body = (wait ? "Problem: " + (cause || "network hiccup") + ". Retrying by itself in " + (wait < 120 ? wait + " s" : Math.ceil(wait / 60) + " min") + ". " : st.err ? "Stopped: " + cause + ". " : "") + (early && !(st.auth || st.relayed || st.txIn) ? "Your money has not moved." : early ? "The deposit may already be on its way: your funds are safe, but do not send from this address again until this transfer finishes." : "Your funds are safe.") + " Press Continue transfer to try again.";
    v.action = "continue"; v.detail = ""; v.zec = !early; v.pct = shownPct((st.stealth || "") + "#" + (st.n || 0), st, 0, now);
  }
  return v;
}

/** Build the card. cb = { onContinue, onFunds, onDismiss, onReturn } */
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
  if (v.note) card.appendChild(el("div", "note hop-stale", v.note));
  if (v.body) card.appendChild(el("div", "hop-line", v.body));
  if (v.link) { const a = el("a", "hop-link", v.link.text); a.href = v.link.href; a.target = "_blank"; a.rel = "noopener noreferrer"; card.appendChild(a); }
  if (h.running) card.appendChild(el("div", "note hop-foot", "Keep this tab open · " + v.elapsed + " elapsed"));
  if (v.detail) { const d = el("details", "hop-det"); d.appendChild(el("summary", null, "details")); d.appendChild(el("div", "note", v.detail)); card.appendChild(d); }
  const acts = el("div", "row hop-act");
  const btn = (txt, cls, fn) => { const b = el("button", "btn " + cls, txt); b.type = "button"; b.addEventListener("click", () => fn(b)); acts.appendChild(b); };
  if (v.action === "continue") btn("Continue transfer", "", b => cb.onContinue && cb.onContinue(b));
  if (v.action === "funds") btn("Show funds", "", b => cb.onFunds && cb.onFunds(b));
  if (!h.running && v.kind === "warn" && v.zec && cb.onReturn) btn("Return money", "", b => cb.onReturn(b, card));
  if (!h.running && (v.kind === "done" || v.kind === "warn" && !v.action)) btn("Dismiss", "ghost", () => cb.onDismiss && cb.onDismiss());
  if (acts.childNodes.length) card.appendChild(acts);
  return card;
}
