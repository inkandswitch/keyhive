//! Domain separation for key derivation and encryption. Signatures and
//! content addresses are separated by [`signable`](crate::signable).

/// The domain separator string for the keyhive: `/keyhive/`.
pub const SEPARATOR_STR: &str = "/keyhive/";

/// The same separator as in [`SEPARATOR_STR`], represented as bytes.
pub const SEPARATOR: &[u8] = SEPARATOR_STR.as_bytes();
