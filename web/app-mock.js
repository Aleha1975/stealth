// Design-only stand-in for the real app logic: same element ids, same states, fake data, no network, no wallet, no keys.
// Every place the real app talks to a wallet or a server is marked "REAL:" — see UI_API.md for what the real code provides.
const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const SYM = "USDG", FEE = 0.05;
const say = (id, text, kind) => { const h = $(id); h.textContent = text || ""; h.className = "hint" + (kind ? " " + kind : ""); };
document.querySelectorAll(".chain-name").forEach(e => e.textContent = "Robinhood Chain");
document.querySelectorAll(".tok-sym").forEach(e => e.textContent = SYM);
$("token").options[0].textContent = SYM; $("token").options[1].textContent = "ETH";
$("sp-addr").textContent = "0x0000…demo";

// ---- tabs and deep link (same as the real app)
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach(x => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".pane").forEach(p => p.hidden = p.id !== "pane-" + b.dataset.pane);
}));
const q = new URLSearchParams(location.search);
if (q.get("to")) { $("to-meta").value = q.get("to"); document.querySelector('[data-pane="pay"]').click(); }
else if (["receive", "payments", "pay"].includes(q.get("tab"))) document.querySelector('[data-pane="' + q.get("tab") + '"]').click();

// ---- wallet button. REAL: connects the browser wallet; clicking again opens the wallet's account picker.
let acct = null;
$("wbtn").addEventListener("click", () => { acct = acct ? null : "0x3e26a1b2c3d4e5f60718293a4b5c6d7e8f908be0"; $("wbtn").textContent = acct ? acct.slice(0, 6) + "…" + acct.slice(-4) : "Connect wallet"; $("wbtn").classList.toggle("on", !!acct); });

// ---- Receive. REAL: one wallet signature, keys derived in the browser, meta-address + pay link shown.
const META = "st:rh:0x02" + "a7".repeat(32) + "03" + "5c".repeat(32);
$("btn-keys").addEventListener("click", async () => {
  say("recv-hint", "Sign the message in your wallet…"); $("btn-keys").disabled = true; await sleep(700);
  $("meta").textContent = META; $("paylink").textContent = location.origin + location.pathname.replace(/[^/]*$/, "") + "app.html?to=" + META;
  $("recv-out").hidden = false; $("btn-keys").hidden = true; say("recv-hint", "Share the link. Every payment gets a new address.", "ok"); $("scan-note").textContent = "";
});
$("copy-link").addEventListener("click", () => say("recv-hint", "Link copied.", "ok"));
$("copy-meta").addEventListener("click", () => say("recv-hint", "Meta-address copied.", "ok"));

// ---- My payments. REAL: scans announcements on-chain, keeps the ones that belong to your keys, reads balances.
const found = [
  { stealth: "0x090925c228fee67e886299d7fc415c0aef73c9a3", amount: 19.95, block: 101020035 },
  { stealth: "0x01a45a7b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5", amount: 4.95, block: 100998112 },
];
let wd = null;
function render() {
  const list = $("pay-list"); list.textContent = "";
  found.forEach((f, i) => {
    const row = el("div", "pay"), top = el("div", "row"); top.style.justifyContent = "space-between";
    top.appendChild(el("span", "amt", f.amount.toFixed(2) + " " + SYM)); top.appendChild(el("span", "mono", f.stealth.slice(0, 8) + "…" + f.stealth.slice(-4)));
    row.appendChild(top); row.appendChild(el("small", null, "block " + f.block + " · " + (f.busy ? "in private transfer" : "now holds " + f.amount.toFixed(2) + " " + SYM)));
    if (!f.busy && f.amount > 0) { const d = el("div"); d.style.marginTop = "8px"; const b = el("button", "btn ghost", "Withdraw " + SYM); b.type = "button"; b.addEventListener("click", () => openWithdraw(i)); d.appendChild(b); row.appendChild(d); }
    list.appendChild(row);
  });
}
$("btn-scan").addEventListener("click", async () => {
  say("pay-hint", "Scanning…"); $("btn-scan").disabled = true; await sleep(800); $("btn-scan").disabled = false;
  render(); say("pay-hint", "128 announcements scanned, " + found.length + " are yours.", "ok");
});
function openWithdraw(i) {
  wd = found[i]; $("wd-from").textContent = wd.stealth.slice(0, 8) + "…" + wd.stealth.slice(-4); $("withdraw").hidden = false;
  $("wd-priv-wrap").hidden = false; $("wd-private").checked = true; $("wd-priv-opts").hidden = false; pvReset();
}
let pv = false;
function pvReset() { pv = false; $("wd-quote").hidden = true; $("btn-wd").textContent = $("wd-private").checked ? "Preview" : "Send without gas"; }
$("wd-private").addEventListener("change", () => { $("wd-priv-opts").hidden = !$("wd-private").checked; pvReset(); });
["wd-to", "wd-amt", "wd-mode"].forEach(id => $(id).addEventListener("input", pvReset));
$("btn-wd-cancel").addEventListener("click", () => { $("withdraw").hidden = true; say("pay-hint", ""); });
const ETA = { fast: "30–60 min", private: "1.5–7 h" };
$("btn-wd").addEventListener("click", async () => {
  const amt = Number($("wd-amt").value) || wd.amount, mode = $("wd-mode").value;
  if (!$("wd-private").checked) { say("pay-hint", "Sending…"); await sleep(900); say("pay-hint", "Sent " + amt.toFixed(2) + " " + SYM + ". No gas paid.", "ok"); $("withdraw").hidden = true; return; }
  if (!pv) {   // REAL: two dry quotes from NEAR Intents, nothing is sent
    say("pay-hint", "Asking for a quote…"); await sleep(700);
    const out = amt * 0.957, box = $("wd-quote"); box.textContent = ""; const qt = el("div", "qt");
    [["Recipient gets", "≈ " + out.toFixed(2) + " " + SYM], ["Fee", "≈ " + (amt - out).toFixed(2) + " (" + ((1 - out / amt) * 100).toFixed(1) + "%)"], ["Takes about", ETA[mode]]]
      .forEach(([k, v]) => { const c = el("div"); c.appendChild(el("span", "note", k)); c.appendChild(el("span", "big", v)); qt.appendChild(c); });
    box.appendChild(qt); box.appendChild(el("div", "note", "Keep this tab open")); box.hidden = false;
    pv = true; $("btn-wd").textContent = "Confirm private transfer"; say("pay-hint", "Check the quote, then confirm.", "warn"); return;
  }
  $("withdraw").hidden = true; wd.busy = true; render(); runDemoHop(wd, amt, mode);
});

// ---- Private transfer progress card (the real one is web/hop-card.js on the main branches). Demo: 7 steps, sped up.
const STEPS = ["Swap to ZEC", "Waiting for the deposit", "Confirmations", "Entering the shielded pool", "Random delay", "Quote", "Payout"];
async function runDemoHop(f, amt, mode) {
  const box = $("hop-resume"); box.hidden = false; const total = STEPS.length, parts = mode === "private" ? 3 : 2;
  for (let i = 0; i <= total; i++) {
    const done = i === total, card = el("div", "hop " + (done ? "done" : "run"));
    card.appendChild(el("div", "hop-t", done ? "Private transfer done" : "Private transfer"));
    card.appendChild(el("div", "hop-amt", amt.toFixed(2) + " " + SYM + " → 0x3e26…8be0"));
    const pct = Math.round(i / total * 100), fill = el("div", "hop-fill"), fi = el("i"); fi.style.width = pct + "%"; fill.appendChild(fi); card.appendChild(fill);
    if (!done) card.appendChild(el("div", "hop-pct", pct + "% · ≈ " + Math.max(1, 35 - i * 5) + " min left"));
    const bar = el("div", "hop-bar"); STEPS.forEach((s, k) => { const seg = el("i", done || k < i ? "d" : k === i ? "c" : ""); seg.title = (k + 1) + ". " + s; bar.appendChild(seg); }); card.appendChild(bar);
    if (!done) card.appendChild(el("div", "hop-step", "Step " + (i + 1) + " of " + total + " · " + STEPS[i] + (i >= 4 ? " · payout 1 of " + parts : "")));
    card.appendChild(el("div", "hop-line", done ? "≈ " + (amt * 0.957).toFixed(2) + " " + SYM + " delivered in " + parts + " payouts." : "Keep this tab open"));
    box.textContent = ""; box.appendChild(card);
    say("pay-hint", done ? "Private transfer done" : "● " + pct + "% · ≈ " + Math.max(1, 35 - i * 5) + " min left · " + STEPS[i], "ok");
    if (!done) await sleep(1600);
  }
  f.amount = 0; f.busy = false; render();
}

// ---- Pay someone. REAL: one wallet signature (EIP-3009), a relayer pays the gas; fixed 0.05 fee.
const num = v => Number(String(v).replace(",", "."));
$("amount").addEventListener("input", () => { const a = num($("amount").value); $("amount-get").value = a > FEE ? (a - FEE).toFixed(2) : ""; calc(); });
$("amount-get").addEventListener("input", () => { const g = num($("amount-get").value); $("amount").value = g > 0 ? (g + FEE).toFixed(2) : ""; calc(); });
function calc() { const a = num($("amount").value); $("pay-calc").textContent = a > FEE ? "Fee " + FEE.toFixed(2) + " " + SYM + " · no gas" : ""; }
$("btn-pay").addEventListener("click", async () => {
  if (!$("to-meta").value.trim()) return say("send-hint", "Paste the recipient's link first.", "bad");
  if (!(num($("amount").value) > FEE)) return say("send-hint", "Enter an amount.", "bad");
  say("send-hint", "Sign in your wallet…"); await sleep(900); say("send-hint", "Paid. The recipient will find it with Scan.", "ok");
});
