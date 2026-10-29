/* POST to the relayer with automatic retry when the front proxy is rate limiting (nginx answers 503/429 with a NON-JSON body once an IP goes over its
   per-minute allowance). Shows a friendly "Busy, retrying…" instead of a JSON parse error and retries with backoff; any real relayer answer
   (200 or a JSON 400 error) is returned at once and never retried. Used by app.js, private-withdraw.js and zec-hop.js. No DOM here. */
export const RELAY_RETRY_MS = [2000, 4000, 8000, 16000, 30000];
/** -> { r, d } where d is the parsed JSON ({} if the body was not JSON). onBusy(message) is called before each wait. */
export async function postRelay(fetchFn, url, body, { sleep = ms => new Promise(r => setTimeout(r, ms)), onBusy = () => {}, delays = RELAY_RETRY_MS } = {}) {
  for (let i = 0; ; i++) {
    const r = await fetchFn(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });
    const d = await r.json().catch(() => null);
    const busy = r.status === 503 || r.status === 429 || ((r.status === 502 || r.status === 504) && d === null);
    if (!busy) return { r, d: d || {} };
    if (i >= delays.length) throw new Error("The relayer is busy right now. Nothing was sent; please try again in a minute.");
    onBusy("Busy, retrying… (" + (i + 1) + "/" + delays.length + ")");
    await sleep(delays[i]);
  }
}
