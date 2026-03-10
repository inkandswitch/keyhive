//! Constants for domain separation

/// The domain separator string for the keyhive: `/keyhive/`.
pub const SEPARATOR_STR: &str = "/keyhive/";

/// The same separator as in [`SEPARATOR_STR`], represented as bytes.
pub const SEPARATOR: &[u8] = SEPARATOR_STR.as_bytes();
