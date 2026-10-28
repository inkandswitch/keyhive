//! Holding and writing secret bytes so that they can be wiped.
//!
//! A wipe only reaches the memory a value is in when it is dropped. Two
//! things leave copies elsewhere: moving a value copies its bytes, and a `Vec`
//! that grows copies its contents to a new allocation and frees the old one
//! unwiped. So a key's bytes live in their own allocation, which a move or a
//! map's resize does not copy, and secret material is encoded into a buffer
//! allocated once at its final length.

use alloc::{boxed::Box, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Encode secret material with `write` into a buffer that is wiped when
/// dropped.
///
/// `len` must be the exact length `write` writes. The buffer is allocated
/// once at that length, so it never grows and leaves no copy behind.
///
/// # Example
///
/// ```
/// # use keyhive_crypto::secret::write_secret;
/// let secret = [7u8; 32];
/// let bytes = write_secret(33, |out| {
///     out.push(1);
///     out.extend_from_slice(&secret);
/// });
/// assert_eq!(bytes.len(), 33);
/// ```
pub fn write_secret<F: FnOnce(&mut Vec<u8>)>(len: usize, write: F) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    write(&mut out);
    debug_assert_eq!(out.len(), len, "a secret encoding's length was misjudged");
    out
}

/// A 32-byte secret in its own allocation, copied from `bytes` without a
/// copy on the stack. `None` unless `bytes` is 32 bytes long.
pub(crate) fn boxed_from_slice(bytes: &[u8]) -> Option<Box<[u8; 32]>> {
    let bytes = <&[u8; 32]>::try_from(bytes).ok()?;
    let mut boxed = Box::new([0; 32]);
    boxed.copy_from_slice(bytes);
    Some(boxed)
}

/// Equality in time that does not depend on where `a` and `b` differ.
pub(crate) fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}
