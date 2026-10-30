# webzjs (Zcash wallet, WebAssembly)

ChainSafe/WebZjs at `a50df944c32243cb8da9f86e7d52cb65ac926439`, built by `ops/build_webzjs.sh` (nightly-2025-06-20, clang 18.1.8, wasm-bindgen-cli 0.2.100, two import patches).
Only this README, `SHA256SUMS` and `BUILD_INFO` (patch sha256, commit, tool versions, "UNVERIFIED BUILD" marker for `PKG_DIR` builds) are in git; the 58 MB wasm and the generated JS are rebuilt with the script and checked against `SHA256SUMS`:

    cd web/vendor/webzjs && sha256sum -c SHA256SUMS    # macOS: shasum -a 256 -c SHA256SUMS

Used only by `web/zec-hop.js`, loaded on demand. Needs a cross-origin isolated page (COOP/COEP, see `ops/nginx-stealth-zec.conf`).

Integrity pin, honestly: `loadZjs` compares the glue and the wasm with hashes that live in `web/zec-hop.js`, served from the same origin as the files. That protects against a stale, mixed or partially swapped vendor directory, NOT against a compromised origin (whoever can change the files can change the hashes). Pinning the hashes outside the origin (or SRI on the module graph, including the four `snippets/` scripts) is not done yet.

Scope of the memory-wallet patch, honestly: the "unscanned range" test (`note_in_unscanned_range`) applies to Sapling notes only (the scan queue is mapped to Sapling tree positions); for Orchard and Ironwood notes it never excludes anything, so a note behind an unscanned gap is counted and selected and fails when its witness is built. Note selection stops at the target per pool; with notes in several pools of `sources` the total can exceed it, and if the eligible notes fall short they are all returned (the caller's InsufficientFunds check decides). `ops/check_repro.sh` measures reproducibility (two builds in different dirs); BUILD_INFO does not claim it. The wasm-opt that wasm-pack downloads at build time is not pinned.
