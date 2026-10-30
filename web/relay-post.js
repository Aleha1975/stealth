import { timeoutSignal } from "./chain-read.js";
/* POST to the relayer with automatic retry when the front proxy is rate limiting (nginx answers 503/429 with a NON-JSON body once an IP goes over its
   per-minute allowance). Shows a friendly "Busy, retrying…" instead of a JSON parse error and retries with backoff; any real relayer answer
   (200 or a JSON 400 error) is returned at once and never retried. Used by app.js, private-withdraw.js and zec-hop.js. No DOM here.
   Audit 1098 L-3: 502/504 (and a dropped connection) are AMBIGUOUS: the relayer may have received the request and broadcast it. Before any retry the caller's
   `check()` is asked whether the signed authorization is already used on chain. true -> the relayer got it (returned as { used: true }); false -> safe to retry
   (the authorization is single-use, a duplicate cannot pay twice); throws/undefined -> we cannot tell, so we stop and say so instead of inviting a second payment. */
export const RELAY_POST_TIMEOUT_MS = 60000;      // 1109 L-2: a hung POST becomes an AMBIGUOUS outcome (settled on chain by check()), never an endless wait
export const RELAY_RETRY_MS = [2000, 4000, 8000, 16000, 30000];
/** -> { r, d } where d is the parsed JSON ({} if the body was not JSON). onBusy(message) is called before each wait. */
export async function postRelay(fetchFn, url, body, { sleep = ms => new Promise(r => setTimeout(r, ms)), onBusy = () => {}, delays = RELAY_RETRY_MS, check = null } = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  for (let i = 0; ; i++) {
    let r = null, d = null, netErr = null;
    try { r = await fetchFn(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: payload, signal: timeoutSignal(RELAY_POST_TIMEOUT_MS) }); d = await r.json().catch(() => null); }
    catch (e) { netErr = e; }
    const ambiguous = netErr !== null || ((r.status === 502 || r.status === 504) && d === null);
    const busy = !ambiguous && (r.status === 503 || r.status === 429);
    if (!ambiguous && !busy) return { r, d: d || {} };
    if (ambiguous) {
      if (!check) { if (netErr) throw netErr; }
      else {
        onBusy("The relayer may or may not have received it — checking on chain…");
        let used; try { used = await check(); } catch { used = undefined; }
        if (used === true) return { r: { ok: true, status: 202 }, d: { used: true } };
        if (used !== false) throw new Error("The relayer may or may not have received your signed request, and the chain could not be read to find out. Do not pay again yet: wait a minute and check your balance and the explorer.");
      }
    }
    if (i >= delays.length) throw new Error(ambiguous ? "The relayer did not answer, and the request was NOT found on chain. It may still be processing: wait a minute and check before paying again." : "The relayer is busy right now or could not confirm the send, so a transaction may be out. Wait a minute and check the explorer and your balance before paying again.");
    onBusy(ambiguous ? "No answer, not on chain yet; retrying the same signed request… (" + (i + 1) + "/" + delays.length + ")" : "Busy, retrying… (" + (i + 1) + "/" + delays.length + ")");
    await sleep(delays[i]);
  }
}
