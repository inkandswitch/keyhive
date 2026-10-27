//! Keyhive-core-specific cryptographic types.
//!
//! Shared primitives (digests, signatures, keys, etc.) live in [`keyhive_crypto`].
//! This module contains types that depend on keyhive_core domain concepts.
//! `envelope` is re-exported from `keyhive_content`.

pub mod digest;
pub use keyhive_content::envelope;
