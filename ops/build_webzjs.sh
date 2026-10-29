#!/usr/bin/env bash
# Reproduces the WebZjs wallet build used by the hidden Zcash hop (web/zec-hop.js) into web/vendor/webzjs/ and writes web/vendor/webzjs/SHA256SUMS.
# Pins: ChainSafe/WebZjs a50df944c32243cb8da9f86e7d52cb65ac926439 · rust nightly-2025-01-07 (from the repo's rust-toolchain.toml) · clang 18.1.8 · wasm-bindgen-cli 0.2.100.
# Usage: ops/build_webzjs.sh                 full build in $WORK (default ~/.cache/webzjs-build): installs rustup/just/wasm-pack/wasm-bindgen-cli/clang there, no system changes
#        PKG_DIR=<dir> ops/build_webzjs.sh   skip the build, only patch + copy + hash an existing wasm-pack output (packages/webzjs-wallet)
# The 60 MB wasm and the generated JS are NOT committed (.gitignore); only SHA256SUMS and README.md are. The build is not bit-for-bit reproducible: SHA256SUMS records the audited artifact.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; OUT="$ROOT/web/vendor/webzjs"
COMMIT=a50df944c32243cb8da9f86e7d52cb65ac926439; CLANG=18.1.8; WBG=0.2.100
WORK="${WORK:-$HOME/.cache/webzjs-build}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
if [ -z "${PKG_DIR:-}" ]; then
  mkdir -p "$WORK"; export RUSTUP_HOME="$WORK/rustup" CARGO_HOME="$WORK/cargo"; export PATH="$WORK/llvm/bin:$CARGO_HOME/bin:$PATH"
  if [ ! -x "$WORK/llvm/bin/clang" ]; then       # clang 18 (the system clang is too old/new for the zcash C deps on wasm32)
    case "$(uname -s)-$(uname -m)" in
      Darwin-arm64) T="clang+llvm-$CLANG-arm64-apple-macos11";; Linux-x86_64) T="clang+llvm-$CLANG-x86_64-linux-gnu-ubuntu-18.04";; *) echo "unsupported platform; put clang $CLANG in $WORK/llvm"; exit 1;;
    esac
    curl -fL "https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG/$T.tar.xz" | tar -xJ -C "$WORK" && mv "$WORK/$T" "$WORK/llvm"
  fi
  [ -x "$CARGO_HOME/bin/rustup" ] || { curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal; }
  rustup toolchain list | grep -q '^stable' || rustup toolchain install stable --profile minimal
  # tools are built with STABLE: nightly-2025-01-07 is too old for current icu/time crates (rustc 1.88)
  [ -x "$CARGO_HOME/bin/just" ] || cargo +stable install --locked just
  [ -x "$CARGO_HOME/bin/wasm-pack" ] || cargo +stable install --locked wasm-pack
  [ "$(wasm-bindgen --version 2>/dev/null)" = "wasm-bindgen $WBG" ] || cargo +stable install --locked wasm-bindgen-cli --version "$WBG" --force
  [ "$(clang --version | head -1 | grep -o '[0-9.]*' | head -1)" = "$CLANG" ] || { echo "clang $CLANG not first in PATH"; exit 1; }
  export CC_wasm32_unknown_unknown="$WORK/llvm/bin/clang" AR_wasm32_unknown_unknown="$WORK/llvm/bin/llvm-ar"
  SRC="$WORK/WebZjs"
  [ -d "$SRC/.git" ] || git clone https://github.com/ChainSafe/WebZjs "$SRC"
  git -C "$SRC" fetch -q origin && git -C "$SRC" checkout -q --detach "$COMMIT"
  [ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ] || { echo "wrong commit"; exit 1; }
  ( cd "$SRC" && just build-wallet )              # wasm-pack build -t web --release --features "wasm wasm-parallel" -Z build-std (nightly from rust-toolchain.toml), then add-worker-module.sh
  PKG_DIR="$SRC/packages/webzjs-wallet"
fi
[ -f "$PKG_DIR/webzjs_wallet_bg.wasm" ] || { echo "no wasm in $PKG_DIR"; exit 1; }
rm -rf "$OUT.new"; mkdir -p "$OUT.new"; rsync -a --exclude .gitignore "$PKG_DIR/" "$OUT.new/"
# the two import patches: the bundler-style bare directory imports ('../../..') do not resolve in a browser without a bundler
W="$OUT.new/snippets"/wasm-bindgen-rayon-*/src/workerHelpers.js; T="$OUT.new/snippets"/wasm_thread-*/src/wasm32/js/web_worker_module.bundler.js
sed -i.bak "s#import('../../..')#import('../../../webzjs_wallet.js')#" $W
sed -i.bak 's#from "../../../../../";#from "../../../../../webzjs_wallet.js";#' $T
grep -q "webzjs_wallet.js')" $W && grep -q 'webzjs_wallet.js";' $T || { echo "import patches did not apply"; exit 1; }
find "$OUT.new" -name '*.bak' -delete
# keep the committed files, swap in the new build
for f in README.md SHA256SUMS; do [ -f "$OUT/$f" ] && cp "$OUT/$f" "$OUT.new/$f"; done
rm -rf "$OUT"; mv "$OUT.new" "$OUT"
( cd "$OUT" && find . -type f ! -name SHA256SUMS ! -name README.md | sed 's#^\./##' | LC_ALL=C sort | xargs -I{} bash -c "$(declare -f sha); sha '{}'" > SHA256SUMS )
echo "web/vendor/webzjs ready: $(wc -l < "$OUT/SHA256SUMS") files, wasm $(du -h "$OUT/webzjs_wallet_bg.wasm" | cut -f1)"
