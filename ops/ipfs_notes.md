# IPFS build notes (ops/build_ipfs.sh)

Build: `ops/build_ipfs.sh [--api-base https://app.deepyield.ai]` -> `ops/build/ipfs/site/` (what is pinned), `ops/build/stealth-web.car`, `ops/build/ROOT_CID`. Nothing is uploaded or pinned. Same web/ + same API base = same CID (re-run verified).
Root CID is a plain directory (index.html at the root), so `ipfs://<cid>/`, `https://<cid>.ipfs.<gateway>/` and `https://<gateway>/ipfs/<cid>/` all work.

## What the script rewrites in its COPY (web/ untouched) and what the web owner should change at source
| Finding in web/ | Why it breaks on IPFS | Build rewrite | Proper source fix |
|---|---|---|---|
| `chains.js` `api: "/stealth-api"` and `"/stealth-api/rh"`; `app.js` fallback `C.api \|\| "/stealth-api"` | root-absolute: on a gateway it hits the gateway, not our API | replaced by `$API_BASE/stealth-api[/rh]` | read the API base from one config value (e.g. `window.STEALTH_API_BASE \|\| ""` prefixed to the paths, or `<meta name="stealth-api-base">`), default empty = same origin |
| `index.html` `<a href="/stealth/">` (brand) | root-absolute | `./` | use `./` |
| `index.html` `<a href="/hedge/">` | root-absolute, other product | `$SITE_URL/hedge/` | keep absolute `https://app.deepyield.ai/hedge/` |
| `index.html` `<link rel="icon" href="/favicon.svg">` | root-absolute, file is not in web/ | line removed | ship `web/favicon.svg` and use `./favicon.svg` |
| `app.js` `location.origin + "/stealth/?"` (payment link) | would print a gateway URL without the `/ipfs/<cid>/` path | `location.origin + location.pathname + "?"` | build the link from `location.pathname` (also fixes any non-root hosting) |
| `index.html` CSP `connect-src 'self' https://1click.chaindefuser.com` | blocks `fetch` to the API origin from a gateway page | API origin appended to `connect-src` | same, from the one API-base config; note `private-withdraw.js` also calls NEAR RPCs (`rpc.mainnet.near.org`, `free.rpc.fastnear.com`) that are NOT in connect-src on any host: web owner to check |
JS imports are already relative (`./stealth-crypto.js`, `./vendor/noble.js`, ...); no workers, no wasm, no service worker, no `SharedArrayBuffer`. After the rewrites the script greps for any remaining root-absolute reference and fails if one is left.

## Required on the server (otherwise the IPFS page cannot call the API)
The page origin is the gateway, the API is `app.deepyield.ai`: cross-origin. nginx must answer, for `/stealth-api/` (all locations incl. `/rh/`, POST `/relay`, `/relay/pay`, and the OPTIONS preflight for `Content-Type: application/json`):
`add_header Access-Control-Allow-Origin "*" always; add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always; add_header Access-Control-Allow-Headers "Content-Type" always;` and `if ($request_method = OPTIONS) { return 204; }`.
`*` is acceptable: the API has no cookies/credentials. The current `limit_except POST { deny all; }` blocks OPTIONS and must allow it. Rate limits are per client IP, unchanged. Not applied by this task (nginx is out of scope for the build).

## COOP/COEP and gateway limits
- Nothing in the app needs cross-origin isolation (no SharedArrayBuffer/wasm threads), so do not set COOP/COEP on the gateway; if a gateway forces `Cross-Origin-Embedder-Policy: require-corp`, cross-origin `fetch` to the API still works only if the API replies with `Cross-Origin-Resource-Policy: cross-origin` (add it next to the CORS headers) - another reason to prefer a gateway that does not force COEP.
- `window.ethereum` injection works on `https://<cid>.ipfs.dweb.link`-style subdomain gateways and on path gateways; it does NOT exist on `ipfs://` in desktop browsers without an extension (use a gateway URL). Each CID is its own origin: localStorage/keys from app.deepyield.ai are not shared and a new CID is a new origin (users re-sign to derive keys; nothing to migrate since keys are derived from a signature).
- `ipfs://` + path gateways make `location.pathname` contain `/ipfs/<cid>/`; the payment-link rewrite keeps it, but meta-addresses/links shared from IPFS point at that one CID (immutable). Use IPNS/DNSLink for a stable name.
- Any `?chain=rh&to=...` query works on gateways; fragments are not needed.
- Integrity: the page is immutable per CID, which is the point; the API base is baked in, so a changed API origin needs a new build/CID.
