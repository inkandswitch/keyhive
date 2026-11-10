//! Holding and writing secret bytes so that they can be wiped.
//!
//! A wipe only reaches the memory a value is in when it is dropped. Two
//! things leave copies elsewhere: moving a value copies its bytes, and a `Vec`
//! that grows copies its contents to a new allocation and frees the old one
//! unwiped. So a key's bytes live in their own allocation, which a move or a
//! map's resize does not copy, and secret material is encoded into a
//! [`SecretBuf`], which is allocated once at its final length and cannot grow.
//!
//! A layout that holds secrets is written once, against [`Sink`]: into a
//! `Vec<u8>` for its [`Encode`](keyhive_codec::traits::Encode) impl, and into
//! a [`SecretBuf`] to store it.

use alloc::{boxed::Box, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Where an encoding's bytes go.
pub trait Sink {
    /// Append `bytes`.
    fn put(&mut self, bytes: &[u8]);
}

/// Grows as needed. For encodings that are not stored as secrets.
impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// A buffer of fixed length that is wiped when dropped, for encoding secret
/// material. It never reallocates, so it never leaves a copy of what it holds
/// behind.
pub struct SecretBuf {
    buf: Zeroizing<Vec<u8>>,

    /// The most it may hold: the length asked for. The allocation's capacity
    /// is at least this, and may be more, so checking against `limit`, not
    /// the capacity, both keeps the buffer from reallocating and catches
    /// every overrun.
    limit: usize,
}

impl core::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "<SecretBuf>".fmt(f)
    }
}

impl SecretBuf {
    fn with_limit(limit: usize) -> Self {
        SecretBuf {
            buf: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    /// How many more bytes fit.
    pub fn remaining(&self) -> usize {
        self.limit - self.buf.len()
    }
}

impl Sink for SecretBuf {
    /// # Panics
    ///
    /// If `bytes` does not fit. The check comes before the write, so the
    /// buffer is never reallocated and no copy is left: a misjudged length
    /// fails rather than leaks.
    fn put(&mut self, bytes: &[u8]) {
        assert!(
            bytes.len() <= self.remaining(),
            "a secret encoding would overrun its length"
        );
        self.buf.extend_from_slice(bytes);
    }
}

/// Encode secret material with `write` into a [`SecretBuf`] of `len` bytes,
/// returned as a buffer that is wiped when dropped.
///
/// `len` must be the exact length `write` writes. The buffer cannot grow, so
/// it leaves no copy behind.
///
/// # Panics
///
/// If `write` writes more than `len` bytes, before the byte that would not
/// fit is written.
///
/// # Example
///
/// ```
/// # use keyhive_crypto::secret::{write_secret, Sink};
/// let secret = [7u8; 32];
/// let bytes = write_secret(33, |out| {
///     out.put(&[1]);
///     out.put(&secret);
/// });
/// assert_eq!(bytes.len(), 33);
/// ```
pub fn write_secret<F: FnOnce(&mut SecretBuf)>(len: usize, write: F) -> Zeroizing<Vec<u8>> {
    let mut out = SecretBuf::with_limit(len);
    write(&mut out);
    debug_assert_eq!(
        out.buf.len(),
        len,
        "a secret encoding wrote less than its length"
    );
    out.buf
}

/// A BLAKE3 hasher that absorbs secrets: in its own allocation, so moving it
/// copies only a pointer and what it buffers stays put, and wiped when
/// dropped.
///
/// This wipes the hasher, not everything BLAKE3 touches. Each compression
/// works on stack copies of the 64-byte block and of the chaining value (for
/// a keyed hasher, the key's), or on vector registers that may spill to the
/// stack, and a keyed hasher's key passes through a stack array as it is
/// built. `blake3` wipes none of these, and nothing outside it can.
pub(crate) struct ZeroizingHasher(Box<blake3::Hasher>);

impl ZeroizingHasher {
    pub(crate) fn new(hasher: blake3::Hasher) -> Self {
        ZeroizingHasher(Box::new(hasher))
    }
}

impl core::ops::Deref for ZeroizingHasher {
    type Target = blake3::Hasher;

    fn deref(&self) -> &blake3::Hasher {
        &self.0
    }
}

impl core::ops::DerefMut for ZeroizingHasher {
    fn deref_mut(&mut self) -> &mut blake3::Hasher {
        &mut self.0
    }
}

impl Drop for ZeroizingHasher {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.0);
    }
}

/// A 32-byte secret in its own allocation, copied from `bytes` without a
/// copy on the stack.
pub(crate) fn boxed(bytes: &[u8; 32]) -> Box<[u8; 32]> {
    let mut boxed = Box::new([0; 32]);
    boxed.copy_from_slice(bytes);
    boxed
}

/// Equality in time that does not depend on where `a` and `b` differ.
pub(crate) fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// A buffer of the exact length holds what a `Vec` would, and is full.
    #[test]
    fn a_secret_buffer_of_the_exact_length_holds_what_a_vec_would() {
        bolero::check!()
            .with_type::<Vec<Vec<u8>>>()
            .for_each(|parts| {
                let mut plain = Vec::new();
                parts.iter().for_each(|p| plain.put(p));
                let wiped = write_secret(plain.len(), |out| {
                    parts.iter().for_each(|p| out.put(p));
                    assert_eq!(out.remaining(), 0);
                });
                assert_eq!(wiped.as_slice(), plain.as_slice());
            });
    }

    /// `put` enforces the length asked for, not the allocation's capacity,
    /// which may be larger: writes are accepted exactly while they fit the
    /// limit, the first that does not is refused, and the buffer never moves.
    /// A check against the capacity fails this whenever there is spare room.
    #[cfg(feature = "std")]
    #[test]
    fn put_enforces_the_limit_not_the_capacity() {
        bolero::check!()
            .with_type::<(Vec<Vec<u8>>, u8, u8)>()
            .for_each(|(parts, limit, spare)| {
                let limit = usize::from(*limit);
                let mut buf = SecretBuf {
                    buf: Zeroizing::new(Vec::with_capacity(limit + usize::from(*spare))),
                    limit,
                };
                let start = buf.buf.as_ptr();
                let mut accepted = Vec::new();
                for part in parts {
                    let put = catch_unwind(AssertUnwindSafe(|| buf.put(part)));
                    if accepted.len() + part.len() <= limit {
                        assert!(put.is_ok(), "a write that fits was refused");
                        accepted.extend_from_slice(part);
                    } else {
                        assert!(put.is_err(), "a write past the limit was accepted");
                        break;
                    }
                }
                assert_eq!(buf.buf.as_slice(), accepted.as_slice());
                assert_eq!(buf.buf.as_ptr(), start, "the buffer moved");
            });
    }

    /// Writing past the length fails before the buffer would grow.
    #[test]
    #[should_panic(expected = "would overrun its length")]
    fn writing_past_the_length_panics() {
        write_secret(4, |out| out.put(&[0; 5]));
    }

    /// The overrun is refused before any of it is written: the buffer keeps
    /// what it held and stays where it was.
    #[cfg(feature = "std")]
    #[test]
    fn an_overrun_is_refused_before_it_is_written() {
        let mut buf = SecretBuf::with_limit(4);
        buf.put(&[1, 2]);
        let start = buf.buf.as_ptr();
        let overrun = catch_unwind(AssertUnwindSafe(|| buf.put(&[3, 4, 5])));
        assert!(overrun.is_err(), "the overrun was accepted");
        assert_eq!(buf.buf.as_slice(), &[1, 2]);
        assert_eq!(buf.buf.as_ptr(), start, "the buffer moved");
    }
}
