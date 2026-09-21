# Development

## JavaScript Package Layout

`wasm-pack` does not generate a single JavaScript package which can be used in
every environment; you must choose a `--target`. That makes it hard to depend
on keyhive transitively, which we expect many packages to do.

We therefore build the package with [`wasm-bodge`](https://github.com/alexjg/wasm-bodge),
which produces one npm package with conditional exports for Node (ESM + CJS),
bundlers, plain browsers (base64-embedded wasm), Cloudflare Workers, and an IIFE
build, plus a `./slim` subpath for manual initialisation. Run it with
`wasm:bodge` inside `nix develop` (or `pnpm build` if you have `wasm-bodge`,
`wasm-bindgen-cli`, `wasm-opt`, and `esbuild` installed). Output lands in
`dist/`; `package.json` is updated in place with the export map.

We pass `--panic abort`: wasm-bodge's default unwind strategy needs a rustup
nightly toolchain, which the nix shell does not provide.

`wasm-pack build --target web` (`pnpm build:web`) is still used for the
Playwright end-to-end tests, which load `pkg/` through `e2e/server/pkg`.

## Release Process

Releases are pushed to npm by `.github/workflows/release-js.yml` when a GitHub
release is published for a tag of the form `keyhive-wasm/<version>`. The
workflow builds inside `nix develop` with `wasm:bodge` (the same pinned
`wasm-bindgen-cli` / `wasm-bodge` as CI), checks that the tag matches
`package.json`'s `version`, installs the packed tarball and loads every advertised entry point, and publishes
with `pnpm publish` (`--tag next` for pre-releases). Bump `version` in
`package.json` before tagging.
