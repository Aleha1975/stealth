#!/usr/bin/env bash
# Measures reproducibility: runs ops/build_webzjs.sh twice with different WORK dirs (full toolchain + build each, so slow and several GB) and compares
# the sha256 of every output file except BUILD_INFO (timestamp) and SHA256SUMS (lists the BUILD_INFO hash). Does not touch web/vendor/webzjs or web/zec-hop.js. Exit 0 = identical. Both builds download wasm-opt (unpinned) separately, so a PASS also covers wasm-opt drift between the two downloads, but NOT drift over weeks.
set -euo pipefail
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; mkdir -p "$HOME/.cache"; T="$(cd "$(mktemp -d "$HOME/.cache/webzjs-repro.XXXXXX")" && pwd -P)"; trap 'rm -rf "$T"' EXIT
for i in a b; do
  echo "== build $i in $T/$i"
  # 1123 L-5: nothing is shared between the two builds: own WORK (so own RUSTUP_HOME / CARGO_HOME registry and git caches) and own wasm-pack cache (where wasm-pack keeps the wasm-opt it downloads) and XDG cache
  mkdir -p "$T/$i/wasm-pack-cache" "$T/$i/xdg-cache"
  WASM_PACK_CACHE="$T/$i/wasm-pack-cache" XDG_CACHE_HOME="$T/$i/xdg-cache" WORK="$T/$i/work" OUT="$T/$i/out" PIN_JS=0 nice -n 10 "$HERE/build_webzjs.sh" >"$T/$i.log" 2>&1 || { tail -30 "$T/$i.log"; echo "build $i failed"; exit 1; }
  ( cd "$T/$i/out" && find . -type f ! -name BUILD_INFO ! -name SHA256SUMS | LC_ALL=C sort | xargs $SHA ) >"$T/$i.sums"
  rm -rf "$T/$i/work" "$T/$i/wasm-pack-cache" "$T/$i/xdg-cache"      # the toolchain and the target dir are large; keep only the sums
done
if diff "$T/a.sums" "$T/b.sums"; then echo "REPRODUCIBLE: $(wc -l <"$T/a.sums" | tr -d ' ') files identical, wasm $(grep bg.wasm$ "$T/a.sums" | cut -d' ' -f1)"; else echo "NOT REPRODUCIBLE (diff above)"; exit 1; fi
