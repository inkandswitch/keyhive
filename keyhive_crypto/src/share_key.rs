//! Newtype around [ECDH] "sharing" public keys.
//!
//! [ECDH]: https://wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

use super::{separable::Separable, symmetric_key::SymmetricKey};
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "std")]
use dupe::Dupe;
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Newtype around [x25519_dalek::PublicKey].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKey(x25519_dalek::PublicKey);

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ShareKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(ShareSecretKey::arbitrary(u)?.share_key())
    }
}

impl ShareKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(x25519_dalek::PublicKey::from(
            &x25519_dalek::EphemeralSecret::random_from_rng(csprng),
        ))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

#[cfg(feature = "std")]
impl Dupe for ShareKey {
    fn dupe(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::LowerHex for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

impl fmt::Display for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl PartialOrd for ShareKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ShareKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<ShareKey> for x25519_dalek::PublicKey {
    fn from(key: ShareKey) -> Self {
        key.0
    }
}

impl From<x25519_dalek::PublicKey> for ShareKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        ShareKey(key)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct ShareSecretKey([u8; 32]);

impl ShareSecretKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        x25519_dalek::StaticSecret::random_from_rng(csprng).into()
    }

    pub fn share_key(&self) -> ShareKey {
        ShareKey(x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(*self),
        ))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[instrument]
    pub fn derive_new_secret_key(&self, other: &ShareKey) -> Self {
        let bytes: [u8; 32] = x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .to_bytes();

        Self::derive_from_bytes(bytes.as_slice())
    }

    #[instrument]
    pub fn derive_symmetric_key(&self, other: &ShareKey) -> SymmetricKey {
        let secret = x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .to_bytes();

        Self::derive_from_bytes(secret.as_slice()).0.into()
    }

    #[instrument]
    pub fn ratchet_forward(&self) -> Self {
        let bytes = self.to_bytes();
        Self::derive_from_bytes(bytes.as_slice())
    }

    pub fn ratchet_n_forward(&self, n: usize) -> Self {
        (0..n).fold(*self, |acc, _| acc.ratchet_forward())
    }

    pub fn force_from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ShareSecretKey> for x25519_dalek::StaticSecret {
    fn from(secret: ShareSecretKey) -> Self {
        x25519_dalek::StaticSecret::from(secret.0)
    }
}

impl From<x25519_dalek::StaticSecret> for ShareSecretKey {
    fn from(secret: x25519_dalek::StaticSecret) -> Self {
        Self(secret.to_bytes())
    }
}

impl From<&ShareSecretKey> for Vec<u8> {
    fn from(secret: &ShareSecretKey) -> Self {
        secret.0.to_vec()
    }
}

impl Separable for ShareSecretKey {
    fn directly_from_32_bytes(bytes: [u8; 32]) -> Self {
        ShareSecretKey(bytes)
    }
}

impl fmt::LowerHex for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::hex::bytes_as_hex(self.0.iter(), f)
    }
}

impl fmt::Display for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareSecretKey(SECRET)")
    }
}

/// A share key encodes as its 32-byte Montgomery u-coordinate in canonical
/// form: below p = 2^255 − 19, so the top bit is clear.
///
/// Decoding refuses two kinds of input, as
/// [`Identifier`](crate::identifier::Identifier) does for signing keys:
///
/// - _Other forms of a key._ X25519 accepts other byte strings for the same
///   key (RFC 7748 masks the top bit and reduces mod p). Refusing them gives
///   one key one encoding and one digest.
/// - _Small-order points._ A Diffie-Hellman exchange with one gives the same
///   shared secret whatever the other side's secret, so a key agreement
///   update to such a key would encrypt to a secret anyone can compute.
///
/// Keys from [`ShareKey::generate`] and [`ShareSecretKey::share_key`] are
/// canonical and of large order.
impl Encode for ShareKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for ShareKey {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for ShareKey {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (u, rest) = <[u8; 32]>::decode_next(bytes)?;
        if is_canonical_u(&u) && !has_small_order(&u) {
            Ok((ShareKey(x25519_dalek::PublicKey::from(u)), rest))
        } else {
            Err(DecodeError::InvalidField("share_key"))
        }
    }
}

/// The secret's 32 bytes. Every 32 bytes are a secret (X25519 clamps them
/// when it uses them), so decoding refuses only the wrong length.
impl Encode for ShareSecretKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for ShareSecretKey {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for ShareSecretKey {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (secret, rest) = <[u8; 32]>::decode_next(bytes)?;
        Ok((ShareSecretKey(secret), rest))
    }
}

/// Whether little-endian `u` is below p = 2^255 − 19 (`ed ff … ff 7f`).
fn is_canonical_u(u: &[u8; 32]) -> bool {
    let top_clear = u[31] & 0x80 == 0;
    let at_least_p = u[31] == 0x7f && u[1..31].iter().all(|&b| b == 0xff) && u[0] >= 0xed;
    top_clear && !at_least_p
}

/// Whether `u` has order dividing 8, on the curve or its twist.
///
/// X25519 clamps every scalar to a multiple of 8, so such a point maps to the
/// identity, which encodes as zero, and no point of large order does.
fn has_small_order(u: &[u8; 32]) -> bool {
    x25519_dalek::x25519([1; 32], *u) == [0; 32]
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// A u-coordinate near p, little-endian: `low` first, `top` last, 0xff
    /// between.
    fn near_p(low: u8, top: u8) -> [u8; 32] {
        let mut u = [0xff; 32];
        u[0] = low;
        u[31] = top;
        u
    }

    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<ShareKey>();
        keyhive_codec::laws::canonical_near::<ShareKey>();
        keyhive_codec::laws::stream::<ShareKey>();
    }

    #[test]
    fn accepts_keys_of_large_order() {
        let mut base = [0; 32];
        base[0] = 9;
        let generated = ShareKey::generate(&mut rand::thread_rng()).to_bytes();
        for u in [base, generated] {
            assert_eq!(ShareKey::decode(&u).map(|k| k.to_bytes()), Ok(u));
        }
    }

    /// The eight small-order points of the curve, in Montgomery form (the
    /// identity is u = 0), and u = 1, of order 4.
    #[test]
    fn refuses_small_order_points() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let mut one = [0; 32];
        one[0] = 1;
        for u in EIGHT_TORSION
            .iter()
            .map(|p| p.to_montgomery().to_bytes())
            .chain([one])
        {
            assert_eq!(
                ShareKey::decode(&u),
                Err(DecodeError::InvalidField("share_key"))
            );
        }
    }

    /// The canonical range ends just below p: with the top byte at 0x7f, a
    /// u-coordinate is p or more only when every byte between is 0xff and
    /// the low byte is at least 0xed.
    #[test]
    fn canonical_u_ends_just_below_p() {
        assert!(is_canonical_u(&near_p(0xec, 0x7f)), "p - 1");
        assert!(!is_canonical_u(&near_p(0xed, 0x7f)), "p");
        assert!(!is_canonical_u(&near_p(0xff, 0x7f)), "p + 18");
        let mut between = near_p(0xff, 0x7f);
        between[1] = 0xfe;
        assert!(is_canonical_u(&between), "a byte between below 0xff");
        assert!(!is_canonical_u(&near_p(0x00, 0x80)), "the top bit set");
    }

    #[test]
    fn refuses_other_forms_of_a_key() {
        let mut high = [9; 32];
        high[31] |= 0x80;
        for u in [near_p(0xed, 0x7f), near_p(0xff, 0x7f), high, [0xff; 32]] {
            assert_eq!(
                ShareKey::decode(&u),
                Err(DecodeError::InvalidField("share_key"))
            );
        }
    }
}
