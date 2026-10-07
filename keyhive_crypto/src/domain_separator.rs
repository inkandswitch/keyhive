//! Domain separation: a global separator for key derivation and encryption,
//! and per-type contexts for signed and content-addressed encodings.

use alloc::vec::Vec;

/// The domain separator string for the keyhive: `/keyhive/`.
pub const SEPARATOR_STR: &str = "/keyhive/";

/// The same separator as in [`SEPARATOR_STR`], represented as bytes.
pub const SEPARATOR: &[u8] = SEPARATOR_STR.as_bytes();

/// A type whose encodings are signed and hashed under a context of their own.
///
/// One key may sign payloads for more than one protocol. If one byte string
/// were valid in two formats, one signature would be valid in both. Prefixing
/// every signed or hashed encoding with a context that names the protocol, its
/// version, and the type rules that out by construction, rather than by the
/// formats happening to differ. Contexts contain no NUL byte and a NUL ends
/// each one, so no prefixed string is a prefix of another.
///
/// [`Digest::of`](crate::digest::Digest::of) hashes exactly the bytes
/// [`Domain::message`] returns, so a signature and a digest cover the same
/// prefixed bytes.
pub trait Domain {
    /// `<protocol>/<version>/<type>`, with no NUL byte.
    const CONTEXT: &'static str;

    /// The context, a NUL byte, then `bytes`: what a signature over an
    /// encoding of `Self` covers.
    fn message(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::CONTEXT.len() + 1 + bytes.len());
        out.extend_from_slice(Self::CONTEXT.as_bytes());
        out.push(0);
        out.extend_from_slice(bytes);
        out
    }
}
