//! Helpers for working with hashes.

use crate::{
    identifier::Identifier,
    signable::{head, Kinded, TAG},
};
use alloc::vec::Vec;
use core::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};

/// A [`blake3::Hash`] tagged with which type it is a hash of.
///
/// This makes it easy to trace the origin type of hash identifiers flowing through the system.
///
/// # Examples
///
/// ```
/// # use keyhive_crypto::digest::Digest;
/// #
/// let digest: Digest<Vec<u8>> = Digest::from(blake3::hash(&[42, 99]));
/// assert_eq!(digest.as_slice().len(), 32);
/// ```
pub struct Digest<T> {
    /// The underlying, unparameterized [`blake3::Hash`].
    pub raw: blake3::Hash,

    /// A phantom parameter to retain the type of the preimage.
    pub _phantom: PhantomData<T>,
}

impl<T: Kinded> Digest<T> {
    /// The identity of a signed statement: BLAKE3 over
    /// [`message`](crate::signable::message), the same bytes its signature
    /// covers, hashed incrementally.
    pub fn of(issuer: &Identifier, encoded: &Encoded<T>) -> Self {
        let payload = encoded.as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&head::<T>(issuer, payload.len()));
        hasher.update(payload);
        Self::from(hasher.finalize())
    }

    /// The digest of a kind that is only hashed, never signed, such as a set
    /// of certificate identities: BLAKE3 over
    /// `"KH" ‖ kind ‖ version ‖ bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&TAG);
        hasher.update(&[T::KIND.to_u8(), T::VERSION]);
        hasher.update(bytes);
        Self::from(hasher.finalize())
    }
}

impl<T> Digest<T> {
    /// Length of a digest, in bytes.
    pub const LEN: usize = blake3::OUT_LEN;

    /// Get the hash as a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let digest: Digest<()> = Digest::from([7; 32]);
    /// assert_eq!(digest.as_slice(), &[7; 32]);
    /// ```
    pub fn as_slice(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    /// Returns the number of trailing zero _bits_ in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let mut bytes = [0xFF; 32];
    /// bytes[31] = 0b1000;
    /// assert_eq!(Digest::<()>::from(bytes).trailing_zeros(), 3);
    ///
    /// bytes[31] = 0;
    /// bytes[30] = 0b10_0000;
    /// assert_eq!(Digest::<()>::from(bytes).trailing_zeros(), 13);
    /// ```
    pub fn trailing_zeros(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().iter().rev() {
            let zeros = byte.trailing_zeros() as u8;
            count += zeros;

            if zeros != 8 {
                break;
            }
        }

        count
    }

    /// Returns the number of trailing zero _bytes_ in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let mut bytes = [0xFF; 32];
    /// assert_eq!(Digest::<()>::from(bytes).trailing_zero_bytes(), 0);
    ///
    /// bytes[30..].fill(0);
    /// assert_eq!(Digest::<()>::from(bytes).trailing_zero_bytes(), 2);
    /// ```
    pub fn trailing_zero_bytes(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().iter().rev() {
            if *byte == 0 {
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// Coerce a `Digest<T>` into a `Digest<U>`, preserving the underlying hash.
    ///
    /// This is useful for implementing `From` conversions between digest types
    /// that are considered equivalent (e.g. static/dynamic variants of the same type).
    pub fn coerce<U>(&self) -> Digest<U> {
        Digest {
            raw: self.raw,
            _phantom: PhantomData,
        }
    }
}

/// Arbitrary bytes: a digest names its preimage, but tests need only distinct
/// names.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T> arbitrary::Arbitrary<'a> for Digest<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Digest::from(<[u8; 32]>::arbitrary(u)?))
    }
}

impl<T> fmt::Debug for Digest<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not `{self}`: `Display` already wraps in `Digest(..)`, which would
        // nest as `Digest<T>(Digest(..))`.
        write!(
            f,
            "Digest<{}>({})",
            core::any::type_name::<T>(),
            self.raw.to_hex()
        )
    }
}

impl<T> fmt::Display for Digest<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Digest({})", self.raw.to_hex())
    }
}

impl<T> Copy for Digest<T> {}

impl<T> Clone for Digest<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for Digest<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw.as_bytes() == other.raw.as_bytes()
    }
}

impl<T> Eq for Digest<T> {}

impl<T> PartialOrd for Digest<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Digest<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.as_bytes().cmp(other.raw.as_bytes())
    }
}

impl<T> Hash for Digest<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state)
    }
}

impl<T> From<blake3::Hash> for Digest<T> {
    fn from(hash: blake3::Hash) -> Self {
        Self {
            raw: hash,
            _phantom: PhantomData,
        }
    }
}

impl<T> From<[u8; 32]> for Digest<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            raw: blake3::Hash::from(bytes),
            _phantom: PhantomData,
        }
    }
}

impl<T> From<Digest<T>> for blake3::Hash {
    fn from(hash: Digest<T>) -> Self {
        hash.raw
    }
}

impl<T> From<Digest<T>> for [u8; 32] {
    fn from(hash: Digest<T>) -> [u8; 32] {
        hash.raw.into()
    }
}

impl<T> From<Digest<T>> for Vec<u8> {
    fn from(hash: Digest<T>) -> Vec<u8> {
        hash.raw.as_bytes().to_vec()
    }
}

/// A digest encodes as its 32 bytes. Every byte string of that length is a
/// digest, so the encoding is canonical and prefix-free.
impl<T> Encode for Digest<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.raw.as_bytes());
    }
}

impl<T> Decode for Digest<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T> StreamDecode for Digest<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (raw, rest) = <[u8; 32]>::decode_next(bytes)?;
        Ok((Digest::from(raw), rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signable::{message, Kind};

    struct Example;

    impl Kinded for Example {
        const KIND: Kind = Kind::CERTIFICATE_SET;
        const VERSION: u8 = 7;
    }

    fn issuer() -> Identifier {
        Identifier::from(&ed25519_dalek::SigningKey::from([1u8; 32]))
    }

    #[test]
    fn message_is_prefix_then_frame_without_signature() {
        let mut expected = b"KHS\x07".to_vec();
        expected.extend_from_slice(issuer().as_bytes());
        expected.extend_from_slice(b"\x01x");
        assert_eq!(message::<Example>(&issuer(), b"x"), expected);
    }

    #[test]
    fn a_hash_only_digest_is_prefix_version_kind_bytes() {
        assert_eq!(
            Digest::<Example>::of_bytes(b"x").raw,
            blake3::hash(b"KHS\x07x")
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Digest<Vec<u8>>>();
        keyhive_codec::laws::canonical_near::<Digest<Vec<u8>>>();
        keyhive_codec::laws::stream::<Digest<Vec<u8>>>();
    }

    #[test]
    fn digest_covers_the_signed_message() {
        let encoded = Encoded::<Example>::from_bytes_unchecked(b"payload".to_vec());
        assert_eq!(
            Digest::of(&issuer(), &encoded).raw,
            blake3::hash(&message::<Example>(&issuer(), b"payload"))
        );
    }
}
