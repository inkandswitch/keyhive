//! BeeKEM: a concurrent variant of TreeKEM for Continuous Group Key Agreement.
//!
//! This crate provides the core CGKA (Continuous Group Key Agreement) state machine
//! used by Keyhive. It manages encryption group membership, key rotation, and
//! derivation of per-content application secrets.
//!
//! # `no_std` support
//!
//! This crate is `no_std`-compatible with `alloc`. The `std` feature (enabled by
//! default) gates `HashMap`/`HashSet` usage; in `no_std` mode the crate falls back
//! to `BTreeMap`/`BTreeSet`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod cgka;
pub mod collections;
pub mod content_addressed_map;
pub mod encrypted;
pub mod error;
pub mod id;
pub mod keys;
pub mod operation;
pub mod pcs_key;
pub mod secret_store;
pub mod topsort;
pub mod transact;
pub mod tree;
pub mod treemath;
