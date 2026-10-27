//! Keyhive's encrypted content: the chunked ciphertext format, the
//! application secrets derived from a CGKA group secret, the causal
//! envelopes that include ancestors' keys, and the ciphertext store that
//! causal decryption reads from.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_debug_implementations,
    future_incompatible,
    let_underscore,
    rust_2021_compatibility,
    nonstandard_style
)]
#![deny(unreachable_pub)]
#![allow(clippy::type_complexity)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod application_secret;
pub mod encrypted;
#[cfg(feature = "std")]
pub mod envelope;
#[cfg(feature = "std")]
pub mod store;
