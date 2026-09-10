//! Decoding errors.

/// Why a byte string is not the canonical encoding of the expected type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input was shorter than the format requires.
    #[error("unexpected end of input")]
    UnexpectedEnd,

    /// The input had bytes beyond the end of the encoding.
    #[error("trailing bytes after encoding")]
    TrailingBytes,

    /// A tag or enum discriminant was out of range.
    #[error("invalid tag {0}")]
    InvalidTag(u8),

    /// A field's bytes were not a valid value of its type (e.g. not a curve point).
    #[error("invalid value for field `{0}`")]
    InvalidField(&'static str),
}
