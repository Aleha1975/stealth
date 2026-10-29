# webzjs (Zcash wallet, WebAssembly)

ChainSafe/WebZjs at `a50df944c32243cb8da9f86e7d52cb65ac926439`, built by `ops/build_webzjs.sh` (nightly-2025-01-07, clang 18.1.8, wasm-bindgen-cli 0.2.100, two import patches).
Only this README and `SHA256SUMS` are in git; the 58 MB wasm and the generated JS are rebuilt with the script and checked against `SHA256SUMS`:

    cd web/vendor/webzjs && sha256sum -c SHA256SUMS    # macOS: shasum -a 256 -c SHA256SUMS

Used only by `web/zec-hop.js`, loaded on demand. Needs a cross-origin isolated page (COOP/COEP, see `ops/nginx-stealth-zec.conf`).
