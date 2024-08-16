# Beelay - the *bee*hive *relay*

Beelay is a library and network protocol for transferring beehive data (both the auth graphs and the documents they pertain to) between machines. 

## Concepts

Beelay is concerned with synchronising the history of both documents and the auth graph between machines. To achieve this we represent any entity which has history as a "commit DAG" and synchronise these DAGs. A commit DAG is a directed acyclic graph where each node is a commit - identified by a hash - which refers to it's parents by their hash and which has an arbitrary byte array as a payload.

The beelay protocol is an RPC style protocol which synchronizes these commit DAGS. The details on how this actually works are currently very much in flux.

## Design Goals

* Operate over either encrypted or plaintext contents. I.e. it should never look at the contents of the commit payloads
* Synchronize large sets of DAGs with bandwidth and latency use proportional to the difference between the sets
* Have minimal requirements for the underlying transport and storage layers


## Code Organisation

Beelay is designed to be implemented once in Rust and then wrapped in language bindings for other platforms. The core implementation is in `beelay-core`, which provides a "sans-IO" implementation of the protocol.

The `beelay` crate provides a high-level Rust API based on an asynchronous runtime (with a default implementation based on `tokio`).

The `beelay-js` folder contains a JavaScript wrapper which uses `wasm-bindgen` to expose the `beelay-core` crate to JavaScript and then provides a more idiomatic JavaScript API.
