# Security Policy

## Status

Keyhive is _pre-alpha_ and has not been audited. Do not use it to protect production data. In particular, the key-commitment / nonce construction described in [`design/ciphersuite.md`](./design/ciphersuite.md) is awaiting independent review.

## Reporting a Vulnerability

Please do _not_ open a public GitHub issue for security problems. Use GitHub's private vulnerability reporting instead: [Report a vulnerability](https://github.com/inkandswitch/keyhive/security/advisories/new). Include a description of the issue, steps or a test case to reproduce it, and the affected commit.

There is no formal disclosure process, response-time commitment, or bug bounty while the project is in alpha. We read and follow up on every report. A formal policy will replace this section at the first stable release.

## Scope

In scope: `keyhive_core`, `keyhive_crypto`, `beekem`, `keyhive_wasm`, and the design documents under [`design/`](./design). Issues in the sync layer belong to [Subduction](https://github.com/inkandswitch/subduction/security).

## Dependency Advisories

`cargo audit` and `cargo deny` run in CI. Accepted advisories are listed with rationale in [`deny.toml`](./deny.toml).
