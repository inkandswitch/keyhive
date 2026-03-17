//! Authorization for local-first collaborative data.
//!
//! `keyhive_core` is the primary library for managing access control over
//! [Automerge] documents (or any causal op-based CRDT). It provides:
//!
//! - **Convergent capabilities** (concap): a CRDT-aware capability system with
//!   delegation, attenuation, and revocation
//! - **Agent hierarchy**: [`Individual`], [`Group`], and [`Document`] principals
//!   arranged in a directed (possibly cyclic) authority graph
//! - **Causal encryption**: end-to-end encryption with per-content keys linked
//!   to causal predecessors, providing post-compromise security (PCS)
//! - **CGKA integration**: wraps the BeeKEM protocol for continuous group key
//!   agreement, driving read-access membership
//! - **Pluggable stores**: trait-based delegation, revocation, and ciphertext stores
//! - **Event system**: observable events for delegation changes, key operations,
//!   and CGKA updates
//!
//! The main entry point is [`Keyhive`](keyhive::Keyhive), which manages the
//! current user's agent, known peers, groups, and documents.
//!
//! [Automerge]: https://automerge.org
//! [`Individual`]: principal::individual::Individual
//! [`Group`]: principal::group::Group
//! [`Document`]: principal::document::Document

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_debug_implementations,
    future_incompatible,
    let_underscore,
//     missing_docs,
    rust_2021_compatibility,
    nonstandard_style
)]
#![deny(unreachable_pub)]

pub mod ability;
pub mod access;
pub mod archive;
pub mod cgka;
pub mod contact_card;
pub mod content;
pub mod crypto;
pub mod error;
pub mod event;
pub mod invocation;
pub mod keyhive;
pub mod listener;
pub mod principal;
pub mod reversed;
pub mod stats;
pub mod store;
pub mod transact;
pub mod util;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

#[cfg(feature = "debug_events")]
pub mod debug_events;
