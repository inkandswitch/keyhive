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

Every entry point also has a `./debug/*` twin, built from the `wasm-debug`
Cargo profile (see the root `Cargo.toml`), which keeps DWARF for stepping
through Rust in Chrome DevTools. It is about 28 MB of Wasm, versus about 2 MB
for release; npm installs it but bundlers only pull it in when imported.

We pass `--panic abort`: wasm-bodge's default unwind strategy needs a rustup
nightly toolchain, which the nix shell does not provide.

`wasm-pack build --target web` (`pnpm build:web`) is still used for the
Playwright end-to-end tests, which load `pkg/` through `e2e/server/pkg`.

## Release Process

The publishable tarball is a Nix derivation, `nix/js-package.nix`:

```sh
nix build .#keyhive-js   # result/keyhive.tgz
```

It runs `wasm-bodge` offline against the committed `Cargo.lock` (and fails if
bodge changes it), packs with `npm pack`, then runs
`scripts/check-js-package.mjs` against the _extracted tarball_. That script
checks every `main`/`module`/`types`/`exports` target exists under `./dist/`,
and loads the package by name in Node ESM and CJS to sign and verify with an
RFC 8032 test key. CI builds the same derivation on every PR.

Releases are pushed to npm by `.github/workflows/release-js.yml` when a GitHub
release is published for a tag of the form `keyhive-wasm/<version>`:

1. The `build` job requires the tagged commit to be on `main` and the tag to
   match `package.json`'s `version`. It then builds `.#keyhive-js` and uploads
   the tarball as an artifact.
2. The `publish` job (GitHub environment `npm`) checks the tarball's name and
   version against the tag, and skips the upload if that version is already
   on npm. Otherwise it publishes the tarball unchanged with
   [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC, no
   token), using `--tag next` for pre-releases.

Bump `version` in `package.json` before tagging.

> [!NOTE]
> The trusted publisher on npmjs.com must name this repository, the workflow
> file `release-js.yml`, and the environment `npm`. Renaming any of them
> breaks publishing.
