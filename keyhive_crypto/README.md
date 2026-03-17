# keyhive_crypto

Shared cryptographic primitives for the Keyhive ecosystem.

## Overview

`keyhive_crypto` provides typed digests, signatures, key exchange, symmetric encryption, and domain separation. It is `#![no_std]`-compatible and `#![forbid(unsafe_code)]`.

## Key Types

| Type              | Module              | Purpose                                                  |
|-------------------|---------------------|----------------------------------------------------------|
| `Digest<T>`       | `digest`            | Typed content-addressed BLAKE3 hash                      |
| `Signed<T>`       | `signed`            | Ed25519 signature wrapper with embedded verifying key    |
| `ShareKey`        | `share_key`         | X25519 public key for key exchange                       |
| `ShareSecretKey`  | `share_key`         | X25519 secret key                                        |
| `SymmetricKey`    | `symmetric_key`     | Symmetric encryption key                                 |
| `Siv`             | `siv`               | Synthetic initialization vector (nonce-misuse resistant) |
| `ReadCap`         | `read_capability`   | Encrypted key for granting read access                   |
| `MemorySigner`    | `signer::memory`    | In-memory Ed25519 signer                                 |
| `EphemeralSigner` | `signer::ephemeral` | Wraps any signer with a temporary inner key              |

## `no_std` Support

This crate is `no_std`-compatible. The `std` feature (enabled by default) gates functionality that depends on `bincode`, `dupe`, and `thiserror`. In `no_std` mode, the crate requires `alloc`.

```toml
[dependencies]
keyhive_crypto = { version = "0.1", default-features = false }
```
