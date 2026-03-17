# keyhive_core

The core signing, encryption, and delegation library for Keyhive.

## Overview

`keyhive_core` provides the primary API for managing local-first authorization. It orchestrates the agent hierarchy (individuals, groups, documents), capability delegation and revocation, continuous group key agreement (CGKA), and causal encryption.

## Key Types

| Type         | Module                         | Purpose                                                      |
|--------------|--------------------------------|--------------------------------------------------------------|
| `Keyhive`    | `keyhive`                      | Top-level API: manages agents, groups, documents, and events |
| `Active`     | `principal::active`            | The current user agent (can sign and encrypt)                |
| `Individual` | `principal::individual`        | A single agent identified by a public key, with prekeys      |
| `Group`      | `principal::group`             | A collection of agents with mutable membership               |
| `Document`   | `principal::document`          | A group with associated encrypted content                    |
| `Agent`      | `principal::agent`             | Union over all agent types                                   |
| `Delegation` | `principal::group::delegation` | Authority delegation from one agent to another               |
| `Revocation` | `principal::group::revocation` | Removal of a delegation                                      |
| `Cgka`       | `cgka`                         | Continuous group key agreement wrapper                       |
| `Access`     | `access`                       | Capability levels: Pull, Read, Write, Manage                 |

## Usage

```rust
use keyhive_core::keyhive::Keyhive;
use keyhive_crypto::signer::memory::MemorySigner;

// Create a new Keyhive instance
let signer = MemorySigner::generate(&mut rand::thread_rng());
let keyhive = Keyhive::generate(signer, /* ... */).await;
```

## Features

- `test_utils` — Enables test helper methods and exposes internal state for testing
- `debug_events` — Enables debug event logging
