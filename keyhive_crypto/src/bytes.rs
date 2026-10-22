//! Bytes an application signs with a Keyhive key.
//!
//! Keyhive gives them no meaning: they are whatever the application chose to
//! vouch for. They are signed under their own kind, [`Kind::BYTES`], so such a
//! signature never verifies as a certificate, a prekey operation or anything
//! else the same key signs. Nothing ties them to one application, so a signed
//! value verifies wherever it is carried.

use crate::signable::{Kind, Kinded};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};

/// Bytes an application signs, encoded as themselves.
///
/// The frame's length delimits them, so the payload needs no framing of its
/// own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes(bytes)
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Bytes(bytes.to_vec())
    }
}

impl Kinded for Bytes {
    const KIND: Kind = Kind::BYTES;
    const VERSION: u8 = 0;
}

impl Encode for Bytes {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Bytes {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Bytes(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identifier::Identifier,
        verified::{Signed, Verified, VerifyError},
    };
    use ed25519_dalek::SigningKey;
    use keyhive_codec::encoded::Encoded;

    /// Stands in for any other kind: its decoder accepts whatever bytes it is
    /// given, so only the signature can tell it apart from [`Bytes`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Other(Vec<u8>);

    impl Kinded for Other {
        const KIND: Kind = Kind::DELEGATION;
        const VERSION: u8 = 0;
    }

    impl Encode for Other {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0);
        }
    }

    impl Decode for Other {
        fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
            Ok(Other(bytes.to_vec()))
        }
    }

    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Bytes>();
        keyhive_codec::laws::canonical_near::<Bytes>();
    }

    #[test]
    fn signed_bytes_verify_and_read_back_from_their_frame() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let verified =
            Verified::sign_sync(&Bytes::from(&b"hello"[..]), &key).expect("a valid key signs");
        assert_eq!(verified.payload().as_slice(), b"hello");

        let frame = verified.signed().encode();
        let read = Signed::<Bytes>::decode(frame.as_bytes())
            .expect("a frame decodes")
            .verify()
            .expect("and verifies");
        assert_eq!(read.payload(), verified.payload());
        assert_eq!(read.issuer(), Identifier::from(&key));
    }

    /// The same issuer, payload bytes and signature, presented as any other
    /// kind, fail: the kind is part of what is signed.
    #[test]
    fn a_signature_over_bytes_verifies_as_no_other_kind() {
        bolero::check!()
            .with_arbitrary::<Vec<u8>>()
            .for_each(|payload| {
                let key = SigningKey::from_bytes(&[2; 32]);
                let signed = Verified::sign_sync(&Bytes::from(payload.clone()), &key)
                    .expect("a valid key signs")
                    .signed()
                    .as_ref()
                    .clone();

                let as_other = Signed::<Other>::new(
                    signed.issuer(),
                    Encoded::from_bytes_unchecked(payload.clone()),
                    *signed.signature(),
                );
                assert_eq!(as_other.verify().err(), Some(VerifyError::BadSignature));
            });
    }
}
