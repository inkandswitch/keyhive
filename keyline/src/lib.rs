//! Keyline: Keyhive's convergent authority graph.
//!
//! A flat namespace of Ed25519 verifying keys ([`id::Id`]) and a set of signed
//! certificates over them: [`delegation::Delegation`]s that grant a [`power::Power`] level over
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
//! _Keyline_ is the design, `keyline` is the crate, [`contract::Keyline`] is the trait.
//!
//! # What this crate does not do
//!
//! A backend never checks signatures: [`contract::Keyline::insert`] takes a
//! [`certificate::VerifiedCertificate`], which outside the `test_utils` feature
//! only [`certificate::Certificate::verify`] can make.
//! The crate knows nothing of prekeys, CGKA, documents, or groups, and is
//! synchronous: concurrency is the wrapper's job. A wrapper holds an
//! implementation behind a lock and converts its typed handles to [`id::Id`]s at
//! the boundary.
//!
//! # `no_std` support
//!
//! `no_std` with `alloc`. The `std` feature (default) switches the collections to
//! `HashMap`/`HashSet` and enables the `std` features of `tracing` and `thiserror`;
//! both crates are used in every configuration.
//!
//! Builds for `wasm32-unknown-unknown` with `--no-default-features`, which
//! `ci-no-std` checks. Bare-metal targets without atomic compare-and-swap
//! (e.g. `thumbv6m-none-eabi`) do not build, because `tracing-core` needs it.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod certificate;
mod collections;
pub mod contract;
pub mod delegation;
pub mod id;
pub mod memory;
pub mod power;
pub mod revocation;
pub mod signed;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
