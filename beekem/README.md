# beekem

BeeKEM: a concurrent variant of TreeKEM for Continuous Group Key Agreement (CGKA).

## Overview

BeeKEM adapts the [TreeKEM] protocol (used in [MLS]) for local-first contexts where strict linearizability is impossible. When merging concurrent updates, BeeKEM keeps all concurrent public keys at conflict nodes until a future update resolves them. This ensures a passive adversary needs _all_ historical secret keys at a leaf to read the root secret after a merge.

## Key Types

| Type                 | Module      | Purpose                                                                            |
|----------------------|-------------|------------------------------------------------------------------------------------|
| `Cgka`               | `cgka`      | Top-level CGKA state machine: add/remove members, rotate keys, derive secrets      |
| `BeeKem`             | `tree`      | The underlying binary tree (leaf nodes = members, inner nodes = encrypted secrets) |
| `CgkaOperation`      | `operation` | Signed operations: Add, Remove, Update                                             |
| `CgkaOperationGraph` | `operation` | Causal graph of all operations seen                                                |
| `PcsKey`             | `pcs_key`   | Post-compromise security key derived from the tree root                            |
| `ApplicationSecret`  | `pcs_key`   | Per-content encryption key (PCS key + content ref)                                 |
| `EncryptedContent`   | `encrypted` | Ciphertext with causal predecessor links                                           |
| `MemberId`           | `id`        | Member identity (wraps `VerifyingKey`)                                             |
| `TreeId`             | `id`        | Tree/document identity (wraps `VerifyingKey`)                                      |

## `no_std` Support

This crate is `no_std`-compatible with `alloc`. The `std` feature (enabled by default) uses `HashMap`/`HashSet`; without it, the crate falls back to `BTreeMap`/`BTreeSet`.

```toml
[dependencies]
beekem = { version = "0.1", default-features = false }
```

## References

- [TreeKEM][TreeKEM] — The base protocol
- [MLS][MLS] — Messaging Layer Security (uses TreeKEM)
- [Causal TreeKEM][Causal TreeKEM] — Matthew Weidner's causal adaptation (inspiration)

[TreeKEM]: https://inria.hal.science/hal-02425247/file/treekem+(1).pdf
[MLS]: https://messaginglayersecurity.rocks/
[Causal TreeKEM]: https://mattweidner.com/assets/pdf/acs-dissertation.pdf
