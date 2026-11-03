#!/usr/bin/env bash
# Deploy web/ to the PROD path (/var/www/stealth-zec/, no --delete: lab/ stays) with cache-busting: every relative .js/.css reference gets ?v=<commit>, so a normal reload always picks up a new deploy.
# The blueprint page, selftest and test vectors stay on the lab only. Usage: ops/deploy_prod.sh [user@host] [remote dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; HOST="${1:-root@46.224.154.72}"; DEST="${2:-/var/www/stealth-zec/}"
V="$(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo "-$(date +%s)")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# the wallet wasm receives the seed phrase: ship only files that match the committed hashes (web/vendor/webzjs/SHA256SUMS)
# audit 1180 L-4: copy the tree FIRST, check the copy, ship the copy (a file swapped after the check cannot reach the server); and every file in the vendor dirs must be LISTED in its manifest
SRC="$TMP/src"; OUT="$TMP/out"; mkdir "$SRC" "$OUT"; rsync -a --exclude .DS_Store "$ROOT/web/" "$SRC/"
sumcheck() { if command -v sha256sum >/dev/null; then sha256sum -c --quiet SHA256SUMS; else shasum -a 256 -c --quiet SHA256SUMS; fi; }
unlisted() { # extra find args: files of the current dir (webzjs/ pruned) that SHA256SUMS does not name; README.md of webzjs is documentation the builder keeps out of the manifest
  comm -23 <(find . -path ./webzjs -prune -o ! -type d ! -path ./SHA256SUMS "$@" -print | sed 's#^\./##' | LC_ALL=C sort) <(awk '{sub(/^\*/, "", $2); print $2}' SHA256SUMS | LC_ALL=C sort); }
( cd "$SRC/vendor/webzjs" && sumcheck && [ -z "$(unlisted ! -name README.md)" ] ) || { echo "web/vendor/webzjs does not match SHA256SUMS (or holds an unlisted file): refusing to deploy"; exit 1; }
# same gate for the other vendored code that handles keys (noble.js, bip39 wordlist, zec-hash.js; audit 1179 F7): manifest in web/vendor/SHA256SUMS, paths relative to web/vendor
( cd "$SRC/vendor" && sumcheck && [ -z "$(unlisted)" ] ) || { echo "web/vendor does not match SHA256SUMS (or holds an unlisted file): refusing to deploy"; exit 1; }
rsync -a --exclude vendor/webzjs --exclude .DS_Store --exclude blueprint --exclude selftest.html --exclude selftest.js --exclude erc5564_vectors.json "$SRC/" "$OUT/"
# html: src="./x.js" href="./x.css"; js: from "./x.js", import("./x.js")
find "$OUT" -maxdepth 1 \( -name '*.html' -o -name '*.js' \) -print0 | xargs -0 perl -pi -e 's#((?:src|href)="\./[\w.-]+\.(?:js|css))"#$1?v='"$V"'"#g; s#((?:from |import\()\s*"\./[\w.-]+\.js)"#$1?v='"$V"'"#g'
rsync -az "$OUT/" "$HOST:$DEST"
rsync -az --exclude .DS_Store "$SRC/vendor/webzjs/" "$HOST:${DEST}vendor/webzjs/"
echo "deployed $V to $HOST:$DEST"
