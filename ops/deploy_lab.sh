#!/usr/bin/env bash
# Deploy web/ to the lab path with cache-busting: every relative .js/.css reference gets ?v=<commit>, so a normal reload always picks up a new deploy.
# Usage: ops/deploy_lab.sh [user@host] [remote dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; HOST="${1:-root@46.224.154.72}"; DEST="${2:-/var/www/stealth-zec/lab/}"
V="$(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo "-$(date +%s)")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# the wallet wasm receives the seed phrase: ship only files that match the committed hashes (web/vendor/webzjs/SHA256SUMS)
( cd "$ROOT/web/vendor/webzjs" && { command -v sha256sum >/dev/null && sha256sum -c --quiet SHA256SUMS || shasum -a 256 -c --quiet SHA256SUMS; } ) || { echo "web/vendor/webzjs does not match SHA256SUMS: refusing to deploy"; exit 1; }
rsync -a --exclude vendor/webzjs --exclude .DS_Store "$ROOT/web/" "$TMP/"
# html: src="./x.js" href="./x.css"; js: from "./x.js", import("./x.js")
find "$TMP" -maxdepth 1 \( -name '*.html' -o -name '*.js' \) -print0 | xargs -0 perl -pi -e 's#((?:src|href)="\./[\w.-]+\.(?:js|css))"#$1?v='"$V"'"#g; s#((?:from |import\()\s*"\./[\w.-]+\.js)"#$1?v='"$V"'"#g'
rsync -az "$TMP/" "$HOST:$DEST"
rsync -az --exclude .DS_Store "$ROOT/web/vendor/webzjs/" "$HOST:${DEST}vendor/webzjs/"
echo "deployed $V to $HOST:$DEST"
