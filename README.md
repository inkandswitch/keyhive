# Keyhive 🗝 🐝

> [!NOTE]
> For background on this project, you can read the [Ink & Switch Keyhive Dev Notebook](https://www.inkandswitch.com/keyhive/notebook/).

🦀 This repo contains the Rust workspace for Keyhive and related crates

We're excited to announce that we're opening the _pre-alpha_ code for the following libraries:

* [`keyhive_core`]: The core signing, encryption, and delegation system
* [`keyhive_crypto`]: Shared cryptographic primitives (digests, signatures, key exchange)
* [`beekem`]: BeeKEM, a concurrent TreeKEM variant for continuous group key agreement
* [`keyhive_wasm`]: [Wasm] wrapper around `keyhive_core`, plus TypeScript bindings

Auth-enabled sync over end-to-end encrypted data lives in a separate repository: [Subduction] (the successor to Beelay).

> [!WARNING]
> DO NOT use this release in production applications

This is an early preview for those curious about the project. Expect bugs, inconsistencies, and unstable APIs. The code has not had a security audit, and the nonce / key-commitment construction in [`design/ciphersuite.md`](./design/ciphersuite.md) has not been independently reviewed. See the [threat model](./design/threat_model.md) for what Keyhive does and does not defend against, and [SECURITY.md](./SECURITY.md) for reporting issues.

## Development

The repository ships a Nix flake with the complete toolchain:

```sh
nix develop            # dev shell; prints a `menu` of commands
nix run .#ci           # fast checks: fmt, clippy, tests, docs, wasm, deny, msrv, no_std
nix run .#ci-e2e       # Playwright tests against the Wasm build
```

Without Nix, `rust-toolchain.toml` pins the compiler and `cargo test --workspace --exclude keyhive_wasm --features test_utils` runs the host suite. Design documents are in [`design/`](./design/README.md). See [CONTRIBUTING.md](./CONTRIBUTING.md).

If you have any questions, thoughts, or feedback, please contact the team by filing a [GitHub Issue], or in the [`keyhive` channel in the Automerge Discord][Channel] (if you're not part of the Automerge Discord you can join [here](https://discord.gg/cEYmnaduTX)).

<!-- External Links -->

[Channel]: https://discord.com/channels/1200006940210757672/1347253710048333884
[GitHub Issue]: https://github.com/inkandswitch/keyhive/issues/new
[Subduction]: https://github.com/inkandswitch/subduction
[Wasm]: https://webassembly.org/

[`beekem`]: https://github.com/inkandswitch/keyhive/tree/main/beekem
[`keyhive_core`]: https://github.com/inkandswitch/keyhive/tree/main/keyhive_core
[`keyhive_crypto`]: https://github.com/inkandswitch/keyhive/tree/main/keyhive_crypto
[`keyhive_wasm`]: https://github.com/inkandswitch/keyhive/tree/main/keyhive_wasm
