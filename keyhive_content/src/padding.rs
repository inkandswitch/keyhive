//! Padding a block's envelope into its body, so the ciphertext's length shows
//! little of the envelope's.
//!
//! A block's length is visible to anyone who stores or forwards it, such as a
//! relay. The envelope is padded to the next of a fixed set of lengths before
//! it is encrypted, so that length shows little about the edit inside:
//!
//! ```text
//! body = envelope ‖ 0x80 ‖ 0x00*        len(body) = padded_len(len(envelope))
//! ```
//!
//! The lengths are [PADMÉ]'s (Nikitin et al., 2019), with a floor of
//! [`MIN_PADDED_LEN`]. For a length whose top bit is bit E, PADMÉ zeroes the
//! low E − S bits, where S = ⌊log₂ E⌋ + 1, rounding up: only the leading bit
//! and the S bits after it can be set. So a padded length shows O(log log n)
//! bits about the envelope instead of O(log n). Above the floor the padding
//! adds at most a sixteenth of the envelope's length, falling to a 32nd from
//! 64 KiB.
//!
//! The padding is inside the AEAD, so it is hidden and authenticated, and
//! zeros are as good as random bytes. The marker makes it self-describing: a
//! reader strips the last nonzero byte, which must be `0x80`, and everything
//! after it, without knowing the rule the lengths come from. Every writer must
//! still use [`padded_len`]: a body of any other length stands out, which
//! tells an observer which client wrote it and leaves it among fewer blocks of
//! the same length. Changing the rule is a change every writer has to make
//! together.
//!
//! Padding is not a defence against compression oracles; see
//! T10 in `design/threat_model.md`.
//!
//! [PADMÉ]: https://petsymposium.org/popets/2019/popets-2019-0056.pdf

use alloc::vec::Vec;
use core::fmt;
use keyhive_crypto::secret::{write_secret, Sink};
use zeroize::Zeroizing;

/// The byte that ends an envelope and starts its padding.
pub(crate) const MARKER: u8 = 0x80;

/// The length every envelope of at most `MIN_PADDED_LEN - 1` bytes pads to,
/// marker included.
///
/// Most edits to a document are small (a few characters, a formatting
/// change), and below this they all look alike.
pub const MIN_PADDED_LEN: usize = 256;

/// A block's body: an encoded envelope, padded to [`padded_len`].
///
/// [`PaddedBody::pad`] is the only way to build one, so an unpadded envelope
/// never reaches
/// [`EncryptedContent::encrypt`](crate::encrypted::EncryptedContent::encrypt).
/// Its readers would refuse one, or, if it happened to end in `0x80` and
/// zeros, cut those bytes off its payload.
///
/// A body holds its envelope's ancestor keys, so it is kept in a buffer that
/// is wiped when dropped and allocated once at its padded length: it never
/// grows, so it leaves no copy of a key behind. It is neither `Clone` nor
/// comparable, and its bytes are not exposed outside this crate.
pub struct PaddedBody(Zeroizing<Vec<u8>>);

impl PaddedBody {
    /// Pad `envelope` into a new body: the envelope, the marker, then zeros
    /// up to [`padded_len`]`(envelope.len())`. `envelope` is copied, not
    /// taken, and is the caller's to wipe.
    ///
    /// # Example
    ///
    /// ```
    /// # use keyhive_content::padding::PaddedBody;
    /// let body = PaddedBody::pad(b"hi");
    /// assert_eq!(format!("{body:?}"), "PaddedBody { len: 256 }");
    /// ```
    pub fn pad(envelope: &[u8]) -> Self {
        Self::write(envelope)
    }

    /// Write `envelope`, then its padding, into one buffer allocated at the
    /// padded length. Every body is built here: [`PaddedBody::pad`] for an
    /// envelope already written, and
    /// [`encode_body`](crate::encrypted::encode_body) to write one in place.
    /// The envelope's length is counted by running the same writer, so the
    /// padding is sized from exactly what is written.
    pub(crate) fn write<E: Unpadded + ?Sized>(envelope: &E) -> Self {
        let envelope_len = written_len(envelope);
        let len = padded_len(envelope_len);
        PaddedBody(write_secret(len, |out| {
            envelope.write_to(out);
            debug_assert_eq!(out.remaining(), len - envelope_len);
            out.put(&[MARKER]);
            while out.remaining() > 0 {
                out.put(&ZEROS[..out.remaining().min(ZEROS.len())]);
            }
        }))
    }

    /// The body's bytes: the envelope, the marker, then zeros.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Take `bytes` as a body as they are, for tests of the chunk layer,
    /// which encrypts any bytes.
    #[cfg(test)]
    pub(crate) fn unchecked(bytes: &[u8]) -> Self {
        PaddedBody(Zeroizing::new(bytes.to_vec()))
    }
}

/// A body holds its envelope's ancestor keys, so only its length is shown.
impl fmt::Debug for PaddedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaddedBody")
            .field("len", &self.0.len())
            .finish()
    }
}

/// An envelope to pad, as how to write it.
pub(crate) trait Unpadded {
    /// Write the envelope.
    fn write_to<S: Sink>(&self, out: &mut S);
}

/// How many bytes `envelope` writes, counted by running its writer, so the
/// length cannot drift from the layout.
pub(crate) fn written_len<E: Unpadded + ?Sized>(envelope: &E) -> usize {
    let mut count = Count(0);
    envelope.write_to(&mut count);
    count.0
}

/// A sink that only counts what it is given.
struct Count(usize);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

impl Unpadded for [u8] {
    fn write_to<S: Sink>(&self, out: &mut S) {
        out.put(self);
    }
}

/// The source of the padding's zeros, so writing them allocates nothing.
const ZEROS: [u8; 256] = [0; 256];

/// The length an envelope of `len` bytes is padded to, marker included: the
/// PADMÉ length of `len + 1`, or [`MIN_PADDED_LEN`] if that is longer.
///
/// # Example
///
/// ```
/// # use keyhive_content::padding::{padded_len, MIN_PADDED_LEN};
/// assert_eq!(padded_len(0), MIN_PADDED_LEN);
/// assert_eq!(padded_len(MIN_PADDED_LEN - 1), MIN_PADDED_LEN);
/// assert_eq!(padded_len(1000), 1024);
/// assert_eq!(padded_len(9000), 9216);
/// ```
///
/// # Panics
///
/// If the padded length would not fit in a `usize`, which only a length near
/// `usize::MAX` reaches: no buffer is that long.
pub fn padded_len(len: usize) -> usize {
    let with_marker = len
        .checked_add(1)
        .expect("an envelope's length fits in a usize");
    padme(with_marker).max(MIN_PADDED_LEN)
}

/// The length of the envelope in `body`: everything before its last nonzero
/// byte, which must be the marker.
///
/// Refuses `body` if it has no nonzero byte, or its last nonzero byte is not
/// the marker: no writer pads that way.
pub(crate) fn unpadded_len(body: &[u8]) -> Result<usize, MalformedPadding> {
    match body.iter().rposition(|&byte| byte != 0) {
        Some(marker) if body[marker] == MARKER => Ok(marker),
        _ => Err(MalformedPadding),
    }
}

/// PADMÉ (Algorithm 1 of the paper): with E = ⌊log₂ len⌋ and
/// S = ⌊log₂ E⌋ + 1, round `len` up to a multiple of 2^(E − S). Lengths below
/// 2 are their own.
fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = len.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1 << (e - s)) - 1;
    len.checked_add(mask)
        .expect("a padded length fits in a usize")
        & !mask
}

/// A decrypted body whose last nonzero byte is not the marker, or that has
/// none. Only a writer with the block's key can produce one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the body's padding is malformed")]
pub struct MalformedPadding;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Every length pads to at least itself plus the marker, to at least the
    /// floor, and above the floor by at most PADMÉ's bound.
    #[test]
    fn an_envelope_pads_to_at_least_its_length_and_little_more() {
        bolero::check!().with_type::<u32>().for_each(|len| {
            let len = *len as usize;
            let padded = padded_len(len);
            assert!(padded > len, "the marker fits");
            assert!(padded >= MIN_PADDED_LEN);
            if padded > MIN_PADDED_LEN {
                // PADMÉ rounds up by less than 2^(E - S) ≤ 2^E / 2^S. Above
                // the floor E ≥ 8, so S ≥ 4: less than a sixteenth.
                assert!((padded - (len + 1)) * 16 <= len + 1, "{len} → {padded}");
            }
            if len + 1 >= 1 << 16 {
                // From 64 KiB, E ≥ 16, so S ≥ 5: less than a 32nd.
                assert!((padded - (len + 1)) * 32 <= len + 1, "{len} → {padded}");
            }
        });
    }

    /// Longer envelopes never pad shorter, and every padded length is a
    /// bucket: an envelope one byte shorter than it pads to it again.
    #[test]
    fn padded_lengths_are_monotonic_buckets() {
        bolero::check!()
            .with_type::<(u32, u32)>()
            .for_each(|(a, b)| {
                let (short, long) = (*a.min(b) as usize, *a.max(b) as usize);
                assert!(padded_len(short) <= padded_len(long));
                let bucket = padded_len(short);
                assert_eq!(padded_len(bucket - 1), bucket);
            });
    }

    /// PADMÉ rounds every length up to the smallest one Algorithm 1 allows:
    /// from 2^k to 2^(k+1), the multiples of 2^(k - S), with
    /// S = ⌊log₂ k⌋ + 1.
    #[test]
    fn padme_rounds_up_to_the_smallest_allowed_length() {
        for k in 1..20u32 {
            let s = k.ilog2() + 1;
            let step = 1usize << (k - s);
            let start = 1usize << k;
            let allowed: Vec<usize> = (0..=(1usize << s)).map(|i| start + i * step).collect();
            for len in start..start << 1 {
                let smallest = *allowed
                    .iter()
                    .find(|&&allowed| allowed >= len)
                    .expect("2^(k+1) is allowed");
                assert_eq!(padme(len), smallest, "padme({len})");
            }
        }
    }

    /// Lengths from Algorithm 1, at both sides of the floor and at bucket
    /// edges.
    #[test]
    fn known_padded_lengths() {
        for (len, padded) in [
            (0, 256),
            (255, 256),
            (256, 272),
            (300, 304),
            (1023, 1024),
            (1024, 1088),
            (9000, 9216),
            (65_536, 67_584),
        ] {
            assert_eq!(padded_len(len), padded, "padded_len({len})");
        }
    }

    /// Pins the padding's bytes: the envelope, `0x80`, then zeros up to the
    /// 256-byte floor.
    #[test]
    fn the_padding_is_the_marker_then_zeros() {
        let body = PaddedBody::pad(b"hi");
        assert_eq!(body.as_slice(), [&b"hi"[..], &[0x80], &[0; 253]].concat());
    }

    fn assert_pads_and_strips(envelope: &[u8]) {
        let body = PaddedBody::pad(envelope);
        let bytes = body.as_slice();
        assert_eq!(bytes.len(), padded_len(envelope.len()));
        assert_eq!(&bytes[..envelope.len()], envelope);
        assert_eq!(bytes[envelope.len()], MARKER);
        assert!(bytes[envelope.len() + 1..].iter().all(|&byte| byte == 0));
        assert_eq!(unpadded_len(bytes), Ok(envelope.len()));
    }

    /// Padding an envelope and stripping it gives the envelope back, at any
    /// length up to 64 KiB, whatever it ends with: zeros, the marker, or
    /// anything else.
    #[test]
    fn padding_round_trips() {
        bolero::check!()
            .with_type::<(u16, u8)>()
            .for_each(|(len, last)| {
                let mut envelope = vec![0xAA; usize::from(*len)];
                if let Some(end) = envelope.last_mut() {
                    *end = *last;
                }
                assert_pads_and_strips(&envelope);
            });
    }

    /// At the lengths where the marker is the body's last byte, and around
    /// them, for each kind of last byte.
    #[test]
    fn padding_round_trips_where_the_marker_ends_the_body() {
        for len in [0, 1, 254, 255, 256, 1022, 1023, 1024, 65_535, 65_536] {
            for last in [0x00, MARKER, 0xAA] {
                let mut envelope = vec![0xAA; len];
                if let Some(end) = envelope.last_mut() {
                    *end = last;
                }
                assert_pads_and_strips(&envelope);
            }
        }
        for len in [255, 1023, 65_535] {
            let body = PaddedBody::pad(&vec![0xAA; len]);
            assert_eq!(body.as_slice().len(), len + 1, "{len} fills its bucket");
            assert_eq!(body.as_slice().last(), Some(&MARKER), "{len}");
        }
    }

    /// No marker, or anything but the marker before the trailing zeros, is
    /// refused.
    #[test]
    fn padding_without_its_marker_is_refused() {
        let refused = Err(MalformedPadding);
        assert_eq!(unpadded_len(&[]), refused);
        assert_eq!(unpadded_len(&[0; 300]), refused);
        assert_eq!(unpadded_len(&[1, 2, 0x81, 0, 0]), refused);
        assert_eq!(unpadded_len(&[1, 2, MARKER, 0, 7]), refused);
    }
}
