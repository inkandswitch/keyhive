# Keyhive 🗝 🐝

> [!NOTE]
> For background on this project, you can read the [Ink & Switch Keyhive Dev Notebook](https://www.inkandswitch.com/keyhive/notebook/).

🦀 This repo contains the Rust workspace for Keyhive and related crates

We're excited to announce that we're opening the _pre-alpha_ code for the following libraries:

* [`beelay-core`]: Auth-enabled sync over end-to-end encrypted data
* [`keyhive_core`]: The core signing, encryption, and delegation system
* [`keyhive_wasm`]: [Wasm] wrapper around `keyhive_core`, plus TypeScript bindings


> [!WARNING]
> DO NOT use this release in production applications

We want to emphasize that this is an early preview release for those that are curious about the project. Expect there to be bugs, inconsistencies, and unstable APIs. This code has also not been through a security audit at time of writing.

If you have any questions, thoughts, or feedback, please contact the team at by filing a [GitHub Issue], or in the [`keyhive-beelay` channel in the Automerge Discord][Channel] (if you're not part of the Automerge Discord you can join [here](https://discord.gg/cEYmnaduTX)).

<!-- External Links -->

[Channel]: https://discord.com/channels/1200006940210757672/1347253710048333884
[GitHub Issue]:https://github.com/inkandswitch/keyhive/issues/new 
[Wasm]: https://webassembly.org/

[`beelay-core`]: https://github.com/inkandswitch/keyhive/tree/main/beelay/beelay-core
[`keyhive_core`]: https://github.com/inkandswitch/keyhive/tree/main/keyhive_core
[`keyhive_wasm`]: https://github.com/inkandswitch/keyhive/tree/main/keyhive_wasm
