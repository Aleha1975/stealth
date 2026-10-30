#!/usr/bin/env bash
# Measures reproducibility: runs ops/build_webzjs.sh twice with different WORK dirs (full toolchain + build each, so slow and several GB) and compares
# the sha256 of every output file except BUILD_INFO (it holds a timestamp). Does not touch web/vendor/webzjs or web/zec-hop.js. Exit 0 = identical.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; T="$(mktemp -d "${TMPDIR:-/tmp}/webzjs-repro.XXXXXX")"; trap 'rm -rf "$T"' EXIT
for i in a b; do
  echo "== build $i in $T/$i"
  WORK="$T/$i/work" OUT="$T/$i/out" PIN_JS=0 nice -n 10 "$HERE/build_webzjs.sh" >"$T/$i.log" 2>&1 || { tail -30 "$T/$i.log"; echo "build $i failed"; exit 1; }
  ( cd "$T/$i/out" && find . -type f ! -name BUILD_INFO | LC_ALL=C sort | xargs shasum -a 256 ) >"$T/$i.sums"
  rm -rf "$T/$i/work"      # the toolchain and the target dir are large; keep only the sums
done
if diff "$T/a.sums" "$T/b.sums"; then echo "REPRODUCIBLE: $(wc -l <"$T/a.sums" | tr -d ' ') files identical, wasm $(grep bg.wasm$ "$T/a.sums" | cut -d' ' -f1)"; else echo "NOT REPRODUCIBLE (diff above)"; exit 1; fi
