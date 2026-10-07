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
/// were valid in two formats, one signature would be valid in both. Each
/// signed or hashed encoding is therefore prefixed with a context naming the
/// protocol, its version, and the type, then a NUL byte. Contexts contain no
/// NUL (checked when a type is first signed or hashed, as a
/// post-monomorphization error), so the context can be read back off any
/// message, and two different contexts never produce the same message.
///
/// This separates every type that implements `Domain` from every other.
/// Separation from a protocol that signs unprefixed bytes, such as
/// `keyhive_core`'s serde payloads today, still relies on its formats.
///
/// [`Digest::of`](crate::digest::Digest::of) hashes exactly the bytes
/// [`message`] returns, so a signature and a digest cover the same prefixed
/// bytes. `message` is a free function rather than a trait method so that no
/// implementation can override it and make the two diverge.
pub trait Domain {
    /// `<protocol>/<version>/<type>`, with no NUL byte.
    const CONTEXT: &'static str;
}

/// `T`'s context, a NUL byte, then `bytes`: what a signature over an encoding
/// of `T` covers, and what its digest hashes.
pub fn message<T: Domain>(bytes: &[u8]) -> Vec<u8> {
    const { assert!(nul_free(T::CONTEXT), "a Domain context contains NUL") };
    let mut out = Vec::with_capacity(T::CONTEXT.len() + 1 + bytes.len());
    out.extend_from_slice(T::CONTEXT.as_bytes());
    out.push(0);
    out.extend_from_slice(bytes);
    out
}

/// Whether `s` contains no NUL byte; usable in `const` assertions.
pub(crate) const fn nul_free(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0 {
            return false;
        }
        i += 1;
    }
    true
}
