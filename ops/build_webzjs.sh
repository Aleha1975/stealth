#!/usr/bin/env bash
# Ironwood (NU6.3) build of the WebZjs browser wallet.
# Reproduces the WebZjs wallet build into web/vendor/webzjs/ and writes web/vendor/webzjs/SHA256SUMS.
# Pins: ChainSafe/WebZjs a50df944c32243cb8da9f86e7d52cb65ac926439 + webzjs-ironwood.patch (librustzcash 0.25, vendored zcash_client_memory ported to Ironwood)
#       rust nightly-2025-06-20 = rustc 1.89.0-nightly (set by the patch in rust-toolchain.toml; librustzcash 0.25 MSRV is 1.89, nightly-2025-01-07 is too old; NEWER nightlies (tested 2026-10-28) make wasm-bindgen 0.2.100 skip its threads transform -> non-shared memory, DataCloneError)
#       clang 18.1.8 · wasm-bindgen-cli 0.2.100 (= wasm-bindgen in Cargo.lock) · just/wasm-pack from stable.
# Usage: ops/build_webzjs_ironwood.sh                 full build in $WORK (default ~/.cache/webzjs-build); no system changes
#        PKG_DIR=<dir> ops/build_webzjs_ironwood.sh   skip the build, only patch + copy + hash an existing wasm-pack output (packages/webzjs-wallet)
# PATCH (default: next to this script) = the diff a50df94..spike/ironwood; its sha256 is checked against PATCH_SHA256.
# The ~60 MB wasm and generated JS are NOT committed; only SHA256SUMS and README.md are. The build is not bit-for-bit reproducible.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; OUT="$ROOT/web/vendor/webzjs"
COMMIT=a50df944c32243cb8da9f86e7d52cb65ac926439; CLANG=18.1.8; WBG=0.2.100; NIGHTLY=nightly-2025-06-20
PATCH="${PATCH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/webzjs-ironwood.patch}"; PATCH_SHA256="${PATCH_SHA256:-cace4fc171f132b9e1f0b35936bf788e03f88b1b821bbb33ee34f7670f5d62f0}"
WORK="${WORK:-$HOME/.cache/webzjs-build}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
if [ -z "${PKG_DIR:-}" ]; then
  mkdir -p "$WORK"; export RUSTUP_HOME="$WORK/rustup" CARGO_HOME="$WORK/cargo"; export PATH="$WORK/llvm/bin:$CARGO_HOME/bin:$PATH"
  if [ -s "$PATCH" ]; then [ "$PATCH_SHA256" = "$(sha "$PATCH" | cut -d' ' -f1)" ] || { echo "patch hash mismatch (set PATCH_SHA256 after reviewing $PATCH)"; exit 1; }
  else echo "missing patch $PATCH"; exit 1; fi
  if [ ! -x "$WORK/llvm/bin/clang" ]; then       # clang 18 (the system clang has no usable wasm32 backend for the C deps: secp256k1, blake2 ...)
    case "$(uname -s)-$(uname -m)" in
      Darwin-arm64) T="clang+llvm-$CLANG-arm64-apple-macos11";; Linux-x86_64) T="clang+llvm-$CLANG-x86_64-linux-gnu-ubuntu-18.04";; *) echo "unsupported platform; put clang $CLANG in $WORK/llvm"; exit 1;;
    esac
    curl -fL "https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG/$T.tar.xz" | tar -xJ -C "$WORK" && mv "$WORK/$T" "$WORK/llvm"
  fi
  [ -x "$CARGO_HOME/bin/rustup" ] || { curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal; }
  rustup toolchain list | grep -q '^stable' || rustup toolchain install stable --profile minimal
  rustup toolchain list | grep -q "^$NIGHTLY" || rustup toolchain install "$NIGHTLY" --profile minimal -c rust-src -t wasm32-unknown-unknown
  # build tools with STABLE (they need a newer rustc than any old nightly)
  [ -x "$CARGO_HOME/bin/just" ] || cargo +stable install --locked just
  [ -x "$CARGO_HOME/bin/wasm-pack" ] || cargo +stable install --locked wasm-pack
  [ "$(wasm-bindgen --version 2>/dev/null)" = "wasm-bindgen $WBG" ] || cargo +stable install --locked wasm-bindgen-cli --version "$WBG" --force
  [ "$(clang --version | head -1 | grep -o '[0-9.]*' | head -1)" = "$CLANG" ] || { echo "clang $CLANG not first in PATH"; exit 1; }
  export CC_wasm32_unknown_unknown="$WORK/llvm/bin/clang" AR_wasm32_unknown_unknown="$WORK/llvm/bin/llvm-ar"
  SRC="$WORK/WebZjs"
  [ -d "$SRC/.git" ] || git clone https://github.com/ChainSafe/WebZjs "$SRC"
  git -C "$SRC" fetch -q origin && git -C "$SRC" reset -q --hard && git -C "$SRC" clean -qfd && git -C "$SRC" checkout -q --detach "$COMMIT"
  [ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ] || { echo "wrong commit"; exit 1; }
  git -C "$SRC" apply --index "$PATCH"            # Cargo.lock is part of the patch: crates are resolved exactly as audited
  # one cargo at a time, 4 jobs max; rust-toolchain.toml (from the patch) selects $NIGHTLY
  ( cd "$SRC" && CARGO_BUILD_JOBS=4 nice just build-wallet )   # wasm-pack build -t web --release --features "wasm wasm-parallel" -Z build-std, then add-worker-module.sh
  PKG_DIR="$SRC/packages/webzjs-wallet"
fi
[ -f "$PKG_DIR/webzjs_wallet_bg.wasm" ] || { echo "no wasm in $PKG_DIR"; exit 1; }
rm -rf "$OUT.new"; mkdir -p "$OUT.new"; rsync -a --exclude .gitignore "$PKG_DIR/" "$OUT.new/"
# the two import patches: the bundler-style bare directory imports ('../../..') do not resolve in a browser without a bundler
W="$OUT.new/snippets"/wasm-bindgen-rayon-*/src/workerHelpers.js; T="$OUT.new/snippets"/wasm_thread-*/src/wasm32/js/web_worker_module.bundler.js
sed -i.bak "s#import('../../..')#import('../../../webzjs_wallet.js')#" $W
sed -i.bak 's#from "../../../../../";#from "../../../../../webzjs_wallet.js";#' $T
grep -q "webzjs_wallet.js')" $W && grep -q 'webzjs_wallet.js";' $T || { echo "import patches did not apply"; exit 1; }
# third patch: wasm_thread calls js_sys::eval with exactly two strings: "self" and a script_path() snippet that reads this glue module's URL
# from a stack trace; answer both without eval (import.meta.url is that URL) so the page keeps a CSP without 'unsafe-eval'
G="$OUT.new/webzjs_wallet.js"
python3 - "$G" <<'PY'
import sys; p = sys.argv[1]; s = open(p).read()
o = "const ret = eval(getStringFromWasm0(arg0, arg1));"
n = 'const src = getStringFromWasm0(arg0, arg1); const ret = src === "self" ? self : /^\\/\\/\\/ Extracts current script file path[\\s\\S]*\\nscript_path\\(\\)$/.test(src) ? import.meta.url : (() => { throw new Error("eval is disabled: " + src.slice(0, 40)); })();'
assert s.count(o) == 1, "eval patch did not apply"; open(p, "w").write(s.replace(o, n))
PY
grep -q '"eval is disabled' "$G" && ! grep -q "eval(" "$G" || { echo "eval patch did not apply"; exit 1; }
find "$OUT.new" -name '*.bak' -delete
# keep the committed files, swap in the new build
for f in README.md SHA256SUMS; do [ -f "$OUT/$f" ] && cp "$OUT/$f" "$OUT.new/$f"; done
rm -rf "$OUT"; mv "$OUT.new" "$OUT"
( cd "$OUT" && find . -type f ! -name SHA256SUMS ! -name README.md | sed 's#^\./##' | LC_ALL=C sort | xargs -I{} bash -c "$(declare -f sha); sha '{}'" > SHA256SUMS )
echo "web/vendor/webzjs ready: $(wc -l < "$OUT/SHA256SUMS") files, wasm $(du -h "$OUT/webzjs_wallet_bg.wasm" | cut -f1)"
