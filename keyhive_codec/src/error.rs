//! Decoding errors.

use core::fmt;

/// Why a byte string is not the canonical encoding of the expected type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input was shorter than the format requires.
    UnexpectedEnd,

    /// The input had bytes beyond the end of the encoding.
    TrailingBytes,

    /// A tag or enum discriminant was out of range.
    InvalidTag(u8),

    /// A field's bytes were not a valid value of its type (e.g. not a curve point).
    InvalidField(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "unexpected end of input"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes after encoding"),
            DecodeError::InvalidTag(t) => write!(f, "invalid tag {t}"),
            DecodeError::InvalidField(name) => write!(f, "invalid value for field `{name}`"),
        }
    }
}

impl core::error::Error for DecodeError {}
