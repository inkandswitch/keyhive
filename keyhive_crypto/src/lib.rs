//! Shared cryptographic primitives for Keyhive.
//!
//! This crate provides the core cryptographic building blocks used across the Keyhive ecosystem:
//! typed digests, signatures, key exchange, symmetric encryption, and domain separation.
//!
//! # `no_std` support
//!
//! This crate is `no_std`-compatible. The `std` feature (enabled by default) gates
//! functionality that depends on `dupe` and `thiserror`. In `no_std` mode
//! the crate requires `alloc`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bytes;
pub mod content;
pub mod context;
pub mod digest;
pub mod hex;
pub mod identifier;
pub mod read_capability;
pub mod share_key;
pub mod signable;
pub mod signer;
pub mod siv;
pub mod symmetric_key;
pub mod verifiable;
pub mod verified;
