#!/usr/bin/env bash
# Static IPFS build of web/ -> ops/build/ipfs/site + ops/build/stealth-web.car, prints the root CID. Uploads / pins NOTHING.
# web/ is not modified: a copy is made and rewritten (see the REWRITES block). Usage: ops/build_ipfs.sh [--api-base https://app.deepyield.ai]
#   API_BASE (env or flag) = origin that serves /stealth-api and /stealth-api/rh. It needs `Access-Control-Allow-Origin` for the gateway
#   origin(s) (nginx, see ops/ipfs_notes.md) because an IPFS page runs on another origin than the API.
# Content-addressed: same web/ + same flags => same CID (files sorted by ipfs-car; mtimes are not part of UnixFS).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; API_BASE="${API_BASE:-https://app.deepyield.ai}"; SITE_URL="${SITE_URL:-https://app.deepyield.ai}"
while [ $# -gt 0 ]; do case "$1" in --api-base) API_BASE="$2"; shift;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
API_BASE="${API_BASE%/}"; OUT="$ROOT/ops/build"; SITE="$OUT/ipfs/site"; CAR="$OUT/stealth-web.car"
rm -rf "$OUT/ipfs"; mkdir -p "$SITE"
# only what the page needs (no tests/vectors)
( cd "$ROOT/web" && cp -R index.html app.js chains.js pay-auth.js private-withdraw.js stealth-crypto.js vendor "$SITE/" )
# ---- REWRITES (in the copy only) ----
# 1. API base: same-origin "/stealth-api" -> absolute origin (CORS needed)
sed -i.bak -e "s#\"/stealth-api/rh\"#\"$API_BASE/stealth-api/rh\"#g" -e "s#\"/stealth-api\"#\"$API_BASE/stealth-api\"#g" "$SITE/chains.js" "$SITE/app.js"
# 2. root-absolute links in index.html: brand -> this page, favicon dropped (no such file in web/), sister product -> site URL
sed -i.bak -e 's#href="/stealth/"#href="./"#' -e "s#href=\"/hedge/\"#href=\"$SITE_URL/hedge/\"#" -e '/<link rel="icon" href="\/favicon.svg">/d' "$SITE/index.html"
# 3. payment link: location.origin + "/stealth/" breaks on gateways (path /ipfs/<cid>/): use the current page URL
sed -i.bak 's#location.origin + "/stealth/?"#location.origin + location.pathname + "?"#' "$SITE/app.js"
# 4. CSP: connect-src 'self' would block the cross-origin API on a gateway -> add the API origin
sed -i.bak "s#connect-src 'self'#connect-src 'self' $API_BASE#" "$SITE/index.html"
grep -q "connect-src 'self' $API_BASE" "$SITE/index.html" || { echo "CSP connect-src rewrite did not apply"; exit 1; }
find "$SITE" -name '*.bak' -delete
# ---- checks: no root-absolute reference may remain ----
BAD=$(grep -nE "(src|href)=\"/[^/]|from \"/|import\(\"/|fetch\(\"/|\"/stealth|\"/hedge|\"/favicon" "$SITE"/*.html "$SITE"/*.js || true)
[ -z "$BAD" ] || { echo "ABSOLUTE PATHS LEFT:"; echo "$BAD"; exit 1; }
grep -q "$API_BASE/stealth-api" "$SITE/chains.js" || { echo "API base rewrite did not apply"; exit 1; }
echo "built $SITE ($(du -sk "$SITE" | cut -f1) KiB, $(find "$SITE" -type f | wc -l | tr -d ' ') files), API base $API_BASE"
# ---- CAR (pinned tool version; npx downloads from the npm registry) ----
rm -f "$CAR"
CID=$(npx --yes ipfs-car@3.1.0 pack "$SITE" --output "$CAR" 2>&1 | tail -1)
echo "$CID" | grep -Eq '^(bafy|bafk|Qm)[A-Za-z0-9]+$' || { echo "could not read CID from ipfs-car output: $CID"; exit 1; }
echo "$CID" > "$OUT/ROOT_CID"
echo "CAR   $CAR ($(wc -c < "$CAR" | tr -d ' ') bytes)"
echo "ROOT CID $CID"
echo "test locally (not uploaded):  npx ipfs-car unpack $CAR --output /tmp/check && diff -r /tmp/check $SITE"
