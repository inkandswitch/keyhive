# Hacking on Keyhive

A contributor guide for the Keyhive workspace.

## Workspace Structure

```
keyhive/
  keyhive_crypto/    Shared crypto primitives (no_std, forbid unsafe)
  beekem/            CGKA state machine (no_std, forbid unsafe)
  keyhive_core/      Orchestration: principals, delegation, encryption
  keyhive_wasm/      Wasm + JS bindings (wasm-bindgen)
  test-utils/        Shared test helpers
  scripts/           CI lints and tooling
  design/            Design documents and rationale
```

### Dependency Graph

```
keyhive_wasm
    |
    v
keyhive_core
    |    |
    v    |
beekem   |
    |    |
    v    v
  keyhive_crypto
```

Both `keyhive_core` and `keyhive_wasm` depend directly on `keyhive_crypto` and `beekem`.

## Build & Test

```sh
# Check everything
cargo check --workspace

# Run all tests
cargo test --workspace

# Clippy (with test_utils for full coverage)
cargo clippy --workspace --all-targets --features=test_utils -- -D warnings

# Wasm build
cd keyhive_wasm && pnpm install && pnpm build

# Wasm &mut boundary lint
scripts/lint-wasm-mut.sh
```

### Nix

The project includes a Nix flake. Use `nix develop` for a reproducible dev shell with all dependencies.

## Key Patterns

### Interior Mutability at the Wasm Boundary

`wasm-bindgen` enforces Rust's borrow rules at runtime. A `&mut self` method on an exported type will panic if JS re-enters the object during the call. All `#[wasm_bindgen]` methods use `&self` and `RefCell` for interior mutability.

The `scripts/lint-wasm-mut.sh` script catches `&mut` in `wasm_bindgen` fn signatures. Suppress intentionally with:

```rust
// lint:allow(wasm_mut) -- reason goes here
&mut self,
```

### Orphan Rule Workarounds

With crypto primitives in `keyhive_crypto` and domain types in `keyhive_core`, some patterns hit the orphan rule:

- **Digest coercions**: `Digest::coerce()` replaces `From<Digest<A>> for Digest<B>`. The `From` impls cannot be written in `keyhive_core` because `Digest` (the outermost type) is foreign.

- **Extension traits**: `Signed::id()` and `Signed::subject_id()` return `keyhive_core` types (`IndividualId`, `AgentId`). They live as extension traits in `keyhive_core::crypto::signed_ext` since inherent methods on `Signed<T>` cannot return foreign types.

### `no_std` Conditional Compilation

`keyhive_crypto` and `beekem` are `#![no_std]` with a default-on `std` feature:

| With `std` | Without `std` |
|---|---|
| `HashMap` / `HashSet` | `BTreeMap` / `BTreeSet` |
| `thiserror` | Manual `Display` + `Error` impls |
| `bincode` serialization | _(blocked, needs no_std serializer)_ |
| `dupe::Dupe` | `Clone` only |

The `beekem::collections` module provides `Map`/`Set`/`Entry` type aliases that switch based on the `std` feature.

### Transactional Fork/Merge

`keyhive_core::transact` provides optimistic transactions via `Fork`/`Merge` traits. A transaction forks the data structure, runs operations on the fork, and merges back on success. On failure, the fork is discarded with no cleanup needed.

Variants: `transact_blocking`, `transact_async`, `transact_sendable`.

### Agent Hierarchy

Agents form a subtyping hierarchy:

```
Document <: Group (Stateful) <: Individual (Stateless)
```

- _Individual_: a public key with prekeys, no internal membership
- _Group_: adds mutable membership (delegation/revocation DAG)
- _Document_: adds encrypted content and CGKA

## Documentation Layout

| Location | Purpose | Committed? |
|----------|---------|------------|
| `design/` | Protocol specifications and design rationale | Yes |
| `HACKING.md` | This contributor guide | Yes |
| `.ignore/` | Session artifacts: `CONTEXT.md`, `DECISIONS.md`, `FIXME.md`, `TODO.md` | No (gitignored) |

### `.ignore/` Files

| File | Purpose |
|------|---------|
| `CONTEXT.md` | Living codebase overview (update with timestamps) |
| `DECISIONS.md` | Architecture decision records with rationale |
| `FIXME.md` | Known bugs and technical debt |
| `TODO.md` | Task backlog |
| `SCRATCH.md` | Temporary working notes |

### Task Notation

| Notation | Meaning |
|----------|---------|
| `[ ]` | Not started |
| `[x]` | Complete |
| `[-]` | In progress |
| `[>]` | Deferred |
| `[?]` | Needs clarification |
