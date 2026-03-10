//! Keyhive-core-specific cryptographic types.
//!
//! Shared primitives (digests, signatures, keys, etc.) live in [`keyhive_crypto`].
//! This module contains types that depend on keyhive_core domain concepts.

pub mod digest;
pub mod envelope;
pub mod signed_ext;
