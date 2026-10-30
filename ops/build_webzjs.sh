#!/usr/bin/env bash
# Ironwood (NU6.3) build of the WebZjs browser wallet.
# Reproduces the WebZjs wallet build into web/vendor/webzjs/ and writes web/vendor/webzjs/SHA256SUMS.
# Pins: ChainSafe/WebZjs a50df944c32243cb8da9f86e7d52cb65ac926439 + webzjs-ironwood.patch (librustzcash 0.25, vendored zcash_client_memory ported to Ironwood)
#       rust nightly-2025-06-20 = rustc 1.89.0-nightly (set by the patch in rust-toolchain.toml; librustzcash 0.25 MSRV is 1.89, nightly-2025-01-07 is too old; NEWER nightlies (tested 2026-10-28) make wasm-bindgen 0.2.100 skip its threads transform -> non-shared memory, DataCloneError)
#       clang 18.1.8 · wasm-bindgen-cli 0.2.100 (= wasm-bindgen in Cargo.lock) · just/wasm-pack from stable.
# Usage: ops/build_webzjs.sh                 full build in $WORK (default ~/.cache/webzjs-build); no system changes
#        PKG_DIR=<dir> ops/build_webzjs.sh   skip the build, only patch + copy + hash an existing wasm-pack output (packages/webzjs-wallet); BUILD_INFO then says "UNVERIFIED BUILD" and the pins in web/zec-hop.js are NOT rewritten (no patch/toolchain check was done)
# web/vendor/webzjs/BUILD_INFO records the provenance (patch sha256, commit, tool versions); "verified build" only if this run checked the patch sha256 and the toolchain pins, else "UNVERIFIED BUILD". Reproducibility is measured by ops/check_repro.sh, not claimed. Env: OUT, PIN_JS=0 (do not rewrite web/zec-hop.js).
# PATCH (default: next to this script) = the diff a50df94..spike/ironwood; its sha256 is checked against PATCH_SHA256.
# The ~60 MB wasm and generated JS are NOT committed; only SHA256SUMS and README.md are. The build is meant to be bit-for-bit reproducible (paths are remapped to /build), and this script (re)writes SHA256SUMS and the pinned hashes
# in web/zec-hop.js (WEBZJS_SHA256); ops/deploy_lab.sh refuses to ship files that do not match SHA256SUMS and loadZjs() refuses to run a wasm/glue that does not match WEBZJS_SHA256.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; OUT="${OUT:-$ROOT/web/vendor/webzjs}"; PIN_JS="${PIN_JS:-1}"   # OUT/PIN_JS=0: build somewhere else without touching web/zec-hop.js (ops/check_repro.sh)
COMMIT=a50df944c32243cb8da9f86e7d52cb65ac926439; CLANG=18.1.8; WBG=0.2.100; NIGHTLY=nightly-2025-06-20; RUSTC_PIN="rustc 1.89.0-nightly (255aa2208 2025-06-19)"; JUST=1.59.0; WASMPACK=0.15.0
# sha256 of the downloads; empty = not recorded yet: the script prints the hash it got and refuses until it is filled in (CLANG_SHA256_<platform>, RUSTUP_INIT_SHA256)
CLANG_SHA256_Darwin_arm64="${CLANG_SHA256_Darwin_arm64:-4573b7f25f46d2a9c8882993f091c52f416c83271db6f5b213c93f0bd0346a10}"; CLANG_SHA256_Linux_x86_64="${CLANG_SHA256_Linux_x86_64:-}"; RUSTUP_INIT_SHA256="${RUSTUP_INIT_SHA256:-9502b514362a21096210d498f143b8cdacda365d3dfcf45e8f5541e089ccafc0}"
PATCH="${PATCH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/webzjs-ironwood.patch}"; PATCH_SHA256=af76b20dbcb2e9ee432a6aa08667a4d56b997558d464468961e6b0847952eecc   # fixed: the audited patch (not overridable by the environment)
WORK="${WORK:-$HOME/.cache/webzjs-build}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
if [ -z "${PKG_DIR:-}" ]; then
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS   # a caller's RUSTFLAGS would REPLACE the patch's .cargo/config.toml flags (+atomics, getrandom backend)
  mkdir -p "$WORK"; WORK_RAW="$WORK"; WORK="$(cd "$WORK" && pwd -P)"   # canonical path (macOS: /var -> /private/var): cargo hands rustc canonical paths, so the remap must match those
  export RUSTUP_HOME="$WORK/rustup" CARGO_HOME="$WORK/cargo"; export PATH="$WORK/llvm/bin:$CARGO_HOME/bin:$PATH"
  if [ -s "$PATCH" ]; then [ "$PATCH_SHA256" = "$(sha "$PATCH" | cut -d' ' -f1)" ] || { echo "patch hash mismatch (only the audited patch can be built; edit PATCH_SHA256 in this script after reviewing $PATCH)"; exit 1; }
  else echo "missing patch $PATCH"; exit 1; fi
  if [ ! -x "$WORK/llvm/bin/clang" ]; then       # clang 18 (the system clang has no usable wasm32 backend for the C deps: secp256k1, blake2 ...)
    case "$(uname -s)-$(uname -m)" in
      Darwin-arm64) T="clang+llvm-$CLANG-arm64-apple-macos11";; Linux-x86_64) T="clang+llvm-$CLANG-x86_64-linux-gnu-ubuntu-18.04";; *) echo "unsupported platform; put clang $CLANG in $WORK/llvm"; exit 1;;
    esac
    curl -fL -o "$WORK/$T.tar.xz" "https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG/$T.tar.xz"
    want="$(eval echo "\${CLANG_SHA256_$(uname -s)_$(uname -m | tr - _):-}")"; got="$(sha "$WORK/$T.tar.xz" | cut -d' ' -f1)"
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "clang tarball sha256 $got does not match the recorded one ('$want'); review it and set CLANG_SHA256_$(uname -s)_$(uname -m | tr - _)"; rm -f "$WORK/$T.tar.xz"; exit 1; }
    tar -xJ -C "$WORK" -f "$WORK/$T.tar.xz" && mv "$WORK/$T" "$WORK/llvm" && rm -f "$WORK/$T.tar.xz"
  fi
  if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    curl -fsSL -o "$WORK/rustup-init.sh" https://sh.rustup.rs; got="$(sha "$WORK/rustup-init.sh" | cut -d' ' -f1)"
    [ -n "$RUSTUP_INIT_SHA256" ] && [ "$RUSTUP_INIT_SHA256" = "$got" ] || { echo "rustup installer sha256 $got does not match the recorded one ('$RUSTUP_INIT_SHA256'); review it and set RUSTUP_INIT_SHA256"; rm -f "$WORK/rustup-init.sh"; exit 1; }
    sh "$WORK/rustup-init.sh" -y --no-modify-path --profile minimal; rm -f "$WORK/rustup-init.sh"
  fi
  rustup toolchain list | grep -q '^stable' || rustup toolchain install stable --profile minimal
  rustup toolchain list | grep -q "^$NIGHTLY" || rustup toolchain install "$NIGHTLY" --profile minimal -c rust-src -t wasm32-unknown-unknown
  # build tools with STABLE (they need a newer rustc than any old nightly)
  [ "$(just --version 2>/dev/null)" = "just $JUST" ] || cargo +stable install --locked just --version "$JUST" --force
  [ "$(wasm-pack --version 2>/dev/null)" = "wasm-pack $WASMPACK" ] || cargo +stable install --locked wasm-pack --version "$WASMPACK" --force
  [ "$(wasm-bindgen --version 2>/dev/null)" = "wasm-bindgen $WBG" ] || cargo +stable install --locked wasm-bindgen-cli --version "$WBG" --force
  [ "$(clang --version | head -1 | grep -o '[0-9.]*' | head -1)" = "$CLANG" ] || { echo "clang $CLANG not first in PATH"; exit 1; }
  [ "$(rustc +$NIGHTLY --version | sed 's/^\(rustc [^)]*)\).*/\1/')" = "$RUSTC_PIN" ] || { echo "rustc +$NIGHTLY is not '$RUSTC_PIN'"; exit 1; }   # the only way to reach "verified build" below: patch sha256 + all toolchain pins checked in this run
  export CC_wasm32_unknown_unknown="$WORK/llvm/bin/clang" AR_wasm32_unknown_unknown="$WORK/llvm/bin/llvm-ar"
  SRC="$WORK/WebZjs"
  [ -d "$SRC/.git" ] || git clone https://github.com/ChainSafe/WebZjs "$SRC"
  git -C "$SRC" fetch -q origin && git -C "$SRC" reset -q --hard && git -C "$SRC" clean -qfdx && git -C "$SRC" checkout -q --detach "$COMMIT"
  [ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ] || { echo "wrong commit"; exit 1; }
  git -C "$SRC" apply --index "$PATCH"            # Cargo.lock is part of the patch: crates are resolved exactly as audited
  # one cargo at a time, 4 jobs max; rust-toolchain.toml (from the patch) selects $NIGHTLY
  # reproducibility: no absolute path of the builder may reach the wasm (std sources, registry crates, the checkout and C objects all live under $WORK). RUSTFLAGS replaces the config.toml
  # flags, so they are repeated here and checked to be identical to the patch's; the remap is the only addition.
  FLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals --cfg getrandom_backend="wasm_js"'
  grep -qF 'rustflags = ["-C", "target-feature=+atomics,+bulk-memory,+mutable-globals", "--cfg", "getrandom_backend=\"wasm_js\""]' "$SRC/.cargo/config.toml" || { echo "patch .cargo/config.toml rustflags differ from FLAGS in this script"; exit 1; }
  RM="--remap-path-prefix=$WORK=/build"; CM="-ffile-prefix-map=$WORK=/build"
  if [ "$WORK_RAW" != "$WORK" ]; then RM="$RM --remap-path-prefix=$WORK_RAW=/build"; CM="$CM -ffile-prefix-map=$WORK_RAW=/build"; fi   # also the non-canonical spelling
  export RUSTFLAGS="$FLAGS $RM"; export CFLAGS_wasm32_unknown_unknown="$CM"
  ( cd "$SRC" && CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" nice just build-wallet )   # wasm-pack build -t web --release --features "wasm wasm-parallel" -Z build-std, then add-worker-module.sh
  PKG_DIR="$SRC/packages/webzjs-wallet"; PROV="verified build: this run checked the patch sha256 $PATCH_SHA256 and the toolchain pins (rustc, clang, just, wasm-pack, wasm-bindgen-cli), applied to WebZjs $COMMIT
$RUSTC_PIN | wasm-pack $WASMPACK | wasm-bindgen $WBG | just $JUST | clang $CLANG
not pinned: the wasm-opt that wasm-pack downloads at build time. built $(date -u +%FT%TZ) (paths remapped to /build)"
else
  UNVERIFIED=1; PROV="UNVERIFIED BUILD: PKG_DIR=$PKG_DIR was used as is; the patch hash, WebZjs commit and toolchain were NOT checked by this script
built $(date -u +%FT%TZ)${PROV_NOTE:+
note (from the builder, not checked): $PROV_NOTE}"; echo "WARNING: UNVERIFIED BUILD (PKG_DIR given): the output is hashed as is and marked in BUILD_INFO" >&2
fi
[ -f "$PKG_DIR/webzjs_wallet_bg.wasm" ] || { echo "no wasm in $PKG_DIR"; exit 1; }
rm -rf "$OUT.new"; mkdir -p "$OUT.new"; rsync -a --exclude .gitignore "$PKG_DIR/" "$OUT.new/"
# the two import patches: the bundler-style bare directory imports ('../../..') do not resolve in a browser without a bundler
W="$OUT.new/snippets"/wasm-bindgen-rayon-*/src/workerHelpers.js; T="$OUT.new/snippets"/wasm_thread-*/src/wasm32/js/web_worker_module.bundler.js
sed -i.bak "s#import('../../..')#import('../../../webzjs_wallet.js')#" $W
sed -i.bak 's#from "../../../../../";#from "../../../../../webzjs_wallet.js";#' $T
[ "$(grep -cF "import('../../../webzjs_wallet.js')" $W)" = 1 ] && grep -q 'webzjs_wallet.js";' $T || { echo "import patches did not apply"; exit 1; }
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
printf '%s\n' "$PROV" > "$OUT.new/BUILD_INFO"
# keep the committed files, swap in the new build
for f in README.md SHA256SUMS; do [ -f "$OUT/$f" ] && cp "$OUT/$f" "$OUT.new/$f"; done
rm -rf "$OUT"; mv "$OUT.new" "$OUT"
( cd "$OUT" && find . -type f ! -name SHA256SUMS ! -name README.md | sed 's#^\./##' | LC_ALL=C sort | xargs -I{} bash -c "$(declare -f sha); sha '{}'" > SHA256SUMS )
echo "web/vendor/webzjs ready: $(wc -l < "$OUT/SHA256SUMS") files, wasm $(du -h "$OUT/webzjs_wallet_bg.wasm" | cut -f1)"
if [ "$PIN_JS" != 1 ] || [ -n "${UNVERIFIED:-}" ]; then
  echo "pins NOT written to web/zec-hop.js (PIN_JS=$PIN_JS${UNVERIFIED:+, unverified build}); WEBZJS_SHA256 would be:"; grep -E ' (webzjs_wallet\.js|webzjs_wallet_bg\.wasm|snippets/.*\.js)$' "$OUT/SHA256SUMS"; exit 0
fi
python3 - "$OUT" "$ROOT/web/zec-hop.js" <<'PY'
import re, sys
out, js = sys.argv[1], sys.argv[2]
want = {f: v for v, f in (l.split() for l in open(out + "/SHA256SUMS").read().splitlines())}
pin = sorted(f for f in want if f in ("webzjs_wallet.js", "webzjs_wallet_bg.wasm") or (f.startswith("snippets/") and f.endswith(".js")))   # exactly what loadZjs fetches and checks
body = ",\n  ".join('"%s": "%s"' % (f, want[f]) for f in pin)
s = open(js).read(); s2 = re.sub(r'const WEBZJS_SHA256 = \{[^}]*\};', lambda m: 'const WEBZJS_SHA256 = { ' + body + ' };', s, count=1)
assert s2 != s or "%s" % want["webzjs_wallet.js"] in s, "WEBZJS_SHA256 not found in web/zec-hop.js"; open(js, "w").write(s2)
PY
