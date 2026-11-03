#!/usr/bin/env bash
# Deploy web/ to the lab path with cache-busting: every relative .js/.css reference gets ?v=<commit>, so a normal reload always picks up a new deploy.
# Usage: ops/deploy_lab.sh [user@host] [remote dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; HOST="${1:-root@46.224.154.72}"; DEST="${2:-/var/www/stealth-zec/lab/}"
# audit 1181 I-3: a dirty web/ (modified, STAGED or untracked files: `git diff --quiet` sees neither of the last two) is refused; FORCE_DIRTY=1 deploys it anyway under a "-<time>" version
DIRTY="$(git -C "$ROOT" status --porcelain --untracked-files=all -- web)"
if [ -n "$DIRTY" ] && [ "${FORCE_DIRTY:-0}" != 1 ]; then echo "web/ has uncommitted changes (commit them, or FORCE_DIRTY=1 to deploy them anyway): refusing to deploy"; echo "$DIRTY" | head -10; exit 1; fi
# audit 1182 L-4: `git status --porcelain` does not list git-ignored files, but rsync ships them: any ignored path under web/ other than the wasm build files that .gitignore names (web/vendor/webzjs/*, covered by the SHA256SUMS manifest below) is refused, FORCE_DIRTY or not
IGN="$(git -C "$ROOT" status --porcelain --ignored --untracked-files=all -- web | grep '^!! ' | grep -v -E -e '^!! (.*/)?\.DS_Store$' -e '^!! web/vendor/webzjs/(package\.json|snippets/.*|webzjs_wallet\.d\.ts|webzjs_wallet\.js|webzjs_wallet_bg\.wasm|webzjs_wallet_bg\.wasm\.d\.ts)$' || true)"
if [ -n "$IGN" ]; then echo "web/ holds git-ignored files that would be shipped (remove them): refusing to deploy"; echo "$IGN" | head -10; exit 1; fi
# audit 1183 L-5: a tracked file flagged assume-unchanged (lowercase) or skip-worktree (S) hides its local edits from `git status`, but rsync ships them: refused, FORCE_DIRTY or not
HID="$(git -C "$ROOT" ls-files -v -- web | grep -E '^[a-zS] ' || true)"
if [ -n "$HID" ]; then echo "web/ holds files flagged assume-unchanged or skip-worktree (git update-index --no-assume-unchanged / --no-skip-worktree): refusing to deploy"; echo "$HID" | head -10; exit 1; fi
V="$(git -C "$ROOT" rev-parse --short HEAD)$([ -z "$DIRTY" ] || echo "-$(date +%s)")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# the wallet wasm receives the seed phrase: ship only files that match the committed hashes (web/vendor/webzjs/SHA256SUMS)
# audit 1180 L-4: copy the tree FIRST, check the copy, ship the copy (a file swapped after the check cannot reach the server); and every file in the vendor dirs must be LISTED in its manifest
# audit 1181 L-6: `rsync -a` copies a symlink AS a symlink, so the copy would not freeze what it points to (the check follows it, the ship follows it again later): web/vendor/webzjs itself may not be one, and the copy may hold no symlink or special file at all
if [ -L "$ROOT/web/vendor/webzjs" ]; then echo "web/vendor/webzjs is a symlink: refusing to deploy"; exit 1; fi
SRC="$TMP/src"; OUT="$TMP/out"; mkdir "$SRC" "$OUT"; rsync -a --exclude .DS_Store "$ROOT/web/" "$SRC/"
ODD="$(find "$SRC" \( -type l -o ! -type f ! -type d \) -print)"
if [ -n "$ODD" ]; then echo "web/ holds a symlink or a special file (only regular files are shipped): refusing to deploy"; echo "$ODD" | head -10; exit 1; fi
# --strict: a manifest line shasum cannot parse is an error, not a skipped line
sumcheck() { if command -v sha256sum >/dev/null; then sha256sum -c --quiet --strict SHA256SUMS; else shasum -a 256 -c --quiet --strict SHA256SUMS; fi; }
unlisted() { # extra find args: files of the current dir (webzjs/ pruned) that SHA256SUMS does not name; README.md of webzjs is documentation the builder keeps out of the manifest
  comm -23 <(find . -path ./webzjs -prune -o ! -type d ! -path ./SHA256SUMS "$@" -print | sed 's#^\./##' | LC_ALL=C sort) <(awk '{sub(/^\*/, "", $2); print $2}' SHA256SUMS | LC_ALL=C sort); }
( cd "$SRC/vendor/webzjs" && sumcheck && [ -z "$(unlisted ! -name README.md)" ] ) || { echo "web/vendor/webzjs does not match SHA256SUMS (or holds an unlisted file): refusing to deploy"; exit 1; }
# same gate for the other vendored code that handles keys (noble.js, bip39 wordlist, zec-hash.js; audit 1179 F7): manifest in web/vendor/SHA256SUMS, paths relative to web/vendor
( cd "$SRC/vendor" && sumcheck && [ -z "$(unlisted)" ] ) || { echo "web/vendor does not match SHA256SUMS (or holds an unlisted file): refusing to deploy"; exit 1; }
rsync -a --exclude vendor/webzjs --exclude .DS_Store "$SRC/" "$OUT/"
# html: src="./x.js" href="./x.css"; js: from "./x.js", import("./x.js")
find "$OUT" -maxdepth 1 \( -name '*.html' -o -name '*.js' \) -print0 | xargs -0 perl -pi -e 's#((?:src|href)="\./[\w.-]+\.(?:js|css))"#$1?v='"$V"'"#g; s#((?:from |import\()\s*"\./[\w.-]+\.js)"#$1?v='"$V"'"#g'
rsync -az "$OUT/" "$HOST:$DEST"
rsync -az --exclude .DS_Store "$SRC/vendor/webzjs/" "$HOST:${DEST}vendor/webzjs/"
echo "deployed $V to $HOST:$DEST"
