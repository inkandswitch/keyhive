//! Encoding traits and the [`encoded::Encoded<T>`] byte container shared by Keyhive crates.
//!
//! This crate holds only the parts every Keyhive crate needs to agree on: the [`traits::Encode`] and [`traits::Decode`] traits and
//! the [`encoded::Encoded<T>`] type that carries a value's bytes tagged with the type they
//! encode. It depends only on `alloc`, `bijoux` and `thiserror` (plus optional `serde`)
//! and contains no cryptography; hashing an `Encoded<T>` is `keyhive_crypto`'s job.
//!
//! # Laws
//!
//! Every implementation of the two traits satisfies two laws:
//!
//! 1. _Round trip:_ `decode(encode(x)) == x`.
//! 2. _Canonicality:_ `encode(decode(b)) == b` for every `b` that `decode` accepts.
//!
//! The second law is a security requirement. Certificates travel as
//! `Encoded<T>`, and a receiver verifies signatures and computes digests over
//! the bytes it received. If a format admitted two byte forms for one value, a
//! peer could ship the same certificate twice with two digests, and a
//! revocation naming one would miss the other. So `decode` rejects
//! non-canonical input.
//!
//! A [`traits::StreamDecode`] type is also prefix-free: one value can be read
//! off the front of a longer input with `decode_next`, which returns the rest.
//! Composite types write such fields back to back without framing them.
//! Fixed-size byte arrays and the bijou-encoded integers are prefix-free.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod encoded;
pub mod error;
pub mod traits;
