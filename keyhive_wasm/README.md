# Keyhive Wasm bindings

`@keyhive/keyhive` wraps [`keyhive_core`](../keyhive_core) for JavaScript and TypeScript via `wasm-bindgen`. It runs in browsers and Node, and ships as a single npm package with per-environment builds selected through conditional exports (see [HACKING.md](./HACKING.md)).

> [!WARNING]
> Pre-alpha. See the [root README](../README.md) and [threat model](../design/threat_model.md) before depending on this.

## Install

```sh
pnpm add @keyhive/keyhive
```

## Usage

```ts
import { Access, ChangeId, CiphertextStore, Keyhive, Signer } from "@keyhive/keyhive";

// A Signer holds the local Ed25519 key. `Signer.generate()` prefers a
// non-extractable WebCrypto key and falls back to memory; use
// `Signer.generateMemory()` to force an in-memory key (e.g. in tests).
const signer = await Signer.generate();
const store = CiphertextStore.newInMemory();
const keyhive = await Keyhive.init(signer, store, console.log);

// Create a group and a document whose initial membership is that group.
const group = await keyhive.generateGroup([]);
const head = new ChangeId(initialChangeHash); // Uint8Array: your CRDT's first change hash
const doc = await keyhive.generateDocument([group.toPeer()], head, []);

// Encrypt a CRDT change, naming its causal predecessors.
const next = new ChangeId(nextChangeHash);
const encrypted = await keyhive.tryEncrypt(doc, next, [head], payload);

// Grant a collaborator Read access. Their contact card comes from
// `theirKeyhive.contactCard()`, exchanged out of band.
const bob = await keyhive.receiveContactCard(bobsContactCard);
await keyhive.addMember(bob.toAgent(), doc.toMembered(), Access.read(), []);
```

`Keyhive` carries the operations: `generateGroup` / `generateDocument`, `addMember` / `revokeMember`, `tryEncrypt` / `tryDecrypt`, `reachableDocs`, `forcePcsUpdate`, and event ingestion for sync. `Document` and `Group` are handles (`id`, `members`, `toPeer` / `toAgent` / `toMembered`; `Document` adds `cgkaMembers`, `Group` adds `transitiveMembers`) passed to those operations. See [`e2e/`](./e2e) for complete examples and `dist/index.d.ts` (after a build) for signatures.

## Building

With the repository's Nix shell (recommended):

```sh
nix develop
wasm:build:web      # wasm-pack build --target web
wasm:bodge          # full npm package via wasm-bodge
```

Without Nix:

```sh
pnpm install
pnpm build          # wasm-bodge; needs wasm-bodge, wasm-bindgen-cli, wasm-opt, esbuild on PATH
```

## Testing

| Suite | Command | What it runs |
|-------|---------|--------------|
| Rust unit tests under Node | `nix run .#ci-wasm-node` | `cargo test -p keyhive_wasm --target wasm32-unknown-unknown` |
| Same suite in Chromium + Firefox | `nix run .#ci-browser` | `--features browser_test` with chromedriver / geckodriver |
| Playwright end-to-end | `nix run .#ci-e2e` (or `test:ts:web` in the shell) | Builds the web target, serves `e2e/server`, runs `e2e/*.spec.ts` |

The Playwright run defaults to Chromium and Firefox. Arguments replace that default, so to include WebKit pass all three: `-- --project chromium --project firefox --project webkit` (WebKit works on macOS; the nixpkgs build times out on Linux).

Without Nix, the equivalent is:

```sh
pnpm install
pnpm exec playwright install
wasm-pack build --target web --release .
pnpm exec playwright test
pnpm exec playwright show-report
```

## Known issues

- `./slim` and `./wasm-base64` ship without complete TypeScript declarations: `dist/index.d.ts` omits `initSync`, the default `init`, and the `Init*` types ([wasm-bodge](https://github.com/alexjg/wasm-bodge) limitation). Import those types from `dist/wasm_bindgen/web/keyhive_wasm.d.ts` or suppress with `// @ts-expect-error` until it is fixed upstream.

## Boundary rules

`#[wasm_bindgen]` methods MUST NOT take `&mut self` or `&mut T`: JavaScript can re-enter during an `await`, and `wasm-bindgen` will panic with "recursive use of an object". Use shared handles with interior mutability instead. `scripts/lint-wasm-mut.sh` (run as `nix run .#ci-wasm-mut`) enforces this.
