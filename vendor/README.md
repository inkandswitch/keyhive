# Vendored crates

`dupe` and `dupe_derive` from the `dupe-no_std` branch of
[expede/buck2](https://github.com/expede/buck2/tree/dupe-no_std/gazebo),
pending upstream release of [meta/buck2#1664](https://github.com/meta/buck2/pull/1664)
(`no_std` support). The root `Cargo.toml` wires them in via `[patch.crates-io]`.

The manifests are rewritten to stand alone (no `workspace = true` inheritance);
the sources are unchanged. Licensed `MIT OR Apache-2.0`; each crate carries its license files.

Once `dupe` 0.9.2 is on crates.io, delete this directory and the
`[patch.crates-io]` and `exclude` entries in the root `Cargo.toml`.
