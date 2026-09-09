//! Keyline: Keyhive's convergent authority graph.
//!
//! A flat namespace of Ed25519 verifying keys ([`id::Id`]) and a set of signed
//! certificates over them: [`delegation::Delegation`]s that grant an [`access::Access`] level over
//! a subject, and [`revocation::Revocation`]s that withdraw a delegation by hash. Authority
//! is reachability over that graph, attenuated to the minimum along a route and
//! combined as the maximum over routes. Evaluation is a pure function of the
//! set, so every replica holding the same certificates computes the same
//! answer regardless of the order it received them.
//!
//! The model is specified in `design/keyline/README.md`; this crate's shape in
//! `design/keyline/implementation.md`; rejected alternatives in
//! `design/keyline/alternatives.md`.
//!
//! # Naming
//!
//! _Keyline_ is the design, `keyline` is the crate, [`keyline::Keyline`] is the trait.
//!
//! # What this crate does not do
//!
//! It does not verify signatures (`Keyline::insert` takes a [`signed::Verified`]
//! witness), does not know about prekeys, CGKA, documents, or groups, and is
//! synchronous: concurrency is the wrapper's job. `keyhive_core` holds an
//! implementation behind a `RwLock` and converts its typed handles to [`id::Id`]s
//! at the boundary.
//!
//! # `no_std` support
//!
//! `no_std` with `alloc`. The `std` feature (default) enables `HashMap`-backed
//! collections, `thiserror`, and `tracing`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod access;
pub mod certificate;
pub mod collections;
pub mod delegation;
pub mod graph;
pub mod id;
pub mod keyline;
pub mod revocation;
pub mod signed;

#[cfg(feature = "test_utils")]
pub mod conformance;
