//! Serializable version of [`Event`][super::Event].

use crate::{
    content::heads::ContentHeads,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use derive_more::{From, TryInto};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_content::reference::ContentRef;
use keyhive_crypto::{
    digest::Digest,
    signable::Kind,
    verified::{self, header},
};
use keyline::{delegation::Delegation, revocation::Revocation};

/// Serailizable version of [`Event`][super::Event].
///
/// This is useful for sending over a network or storing to disk.
/// However the references contained in `StaticEvent`s may be missing
/// dependencies, unlike [`Event`][super::Event]s.
#[derive(Debug, Clone, PartialEq, Eq, From, Hash, TryInto)]
pub enum StaticEvent<T: ContentRef> {
    /// Prekeys were expanded, as received: verified on receipt.
    PrekeysExpanded(verified::Signed<AddKeyOp>),

    /// A prekey was rotated, as received: verified on receipt.
    PrekeyRotated(verified::Signed<RotateKeyOp>),

    /// A CGKA operation, as received: verified on receipt.
    CgkaOperation(Box<verified::Signed<CgkaOperation>>),

    /// A Keyline delegation, as received: verified on receipt.
    Delegated(verified::Signed<Delegation>),

    /// A Keyline revocation, as received: verified on receipt.
    Revoked(verified::Signed<Revocation<ContentHeads<T>>>),
}

impl<T: ContentRef> StaticEvent<T> {
    /// The event's identity: the digest of the statement it carries, its
    /// frame without the signature. The same statement signed twice is one
    /// event, and kinds keep different statements' digests apart.
    pub fn digest(&self) -> Digest<StaticEvent<T>> {
        match self {
            StaticEvent::PrekeysExpanded(signed) => signed.digest().coerce(),
            StaticEvent::PrekeyRotated(signed) => signed.digest().coerce(),
            StaticEvent::CgkaOperation(signed) => signed.digest().coerce(),
            StaticEvent::Delegated(signed) => signed.digest().coerce(),
            StaticEvent::Revoked(signed) => signed.digest().coerce(),
        }
    }
}

/// The signed statement's own frame,
/// `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature`, whose
/// kind says which event it is. Frames are self-delimiting, so events can be
/// read back to back. Decoding checks the framing only; receiving an event
/// verifies it.
impl<T: ContentRef> Encode for StaticEvent<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            StaticEvent::PrekeysExpanded(signed) => signed.encode_into(out),
            StaticEvent::PrekeyRotated(signed) => signed.encode_into(out),
            StaticEvent::CgkaOperation(signed) => signed.encode_into(out),
            StaticEvent::Delegated(signed) => signed.encode_into(out),
            StaticEvent::Revoked(signed) => signed.encode_into(out),
        }
    }
}

impl<T: ContentRef> Decode for StaticEvent<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: ContentRef> StreamDecode for StaticEvent<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (kind, _) = header(bytes)?;
        match Kind::from_u8(kind) {
            Some(Kind::ADD_KEY) => {
                let (signed, rest) = verified::Signed::decode_next(bytes)?;
                Ok((StaticEvent::PrekeysExpanded(signed), rest))
            }
            Some(Kind::ROTATE_KEY) => {
                let (signed, rest) = verified::Signed::decode_next(bytes)?;
                Ok((StaticEvent::PrekeyRotated(signed), rest))
            }
            Some(Kind::CGKA_OPERATION) => {
                let (signed, rest) = verified::Signed::decode_next(bytes)?;
                Ok((StaticEvent::CgkaOperation(Box::new(signed)), rest))
            }
            Some(Kind::DELEGATION) => {
                let (signed, rest) = verified::Signed::decode_next(bytes)?;
                Ok((StaticEvent::Delegated(signed), rest))
            }
            Some(Kind::REVOCATION) => {
                let (signed, rest) = verified::Signed::decode_next(bytes)?;
                Ok((StaticEvent::Revoked(signed), rest))
            }
            _ => Err(DecodeError::UnexpectedKind(kind)),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Signatures are junk: these exercise encoding, not verification.
        fn junk<'a, V: arbitrary::Arbitrary<'a> + keyhive_codec::traits::Encode>(
            u: &mut arbitrary::Unstructured<'a>,
        ) -> arbitrary::Result<verified::Signed<V>> {
            Ok(verified::Signed::new(
                u.arbitrary()?,
                keyhive_codec::traits::Encode::encode(&V::arbitrary(u)?),
                ed25519_dalek::Signature::from_bytes(&u.arbitrary()?),
            ))
        }

        let variant = u.int_in_range(0..=3)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(junk::<AddKeyOp>(u)?)),
            1 => Ok(Self::PrekeyRotated(junk::<RotateKeyOp>(u)?)),
            2 => Ok(Self::CgkaOperation(Box::new(junk::<CgkaOperation>(u)?))),
            // Delegations only: a revocation's watermark type has no
            // `Arbitrary`.
            3 => Ok(Self::Delegated(junk::<Delegation>(u)?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use dupe::Dupe;
    use keyhive_crypto::{
        bytes::Bytes, share_key::ShareKey, signer::memory::MemorySigner, verified::Verified,
    };

    type Event32 = StaticEvent<[u8; 32]>;

    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Event32>();
        keyhive_codec::laws::canonical_near::<Event32>();
        keyhive_codec::laws::stream::<Event32>();
    }

    fn prekeys_expanded(signer: &MemorySigner) -> Verified<AddKeyOp> {
        let op = AddKeyOp {
            share_key: ShareKey::generate(&mut rand::rngs::OsRng),
        };
        Verified::sign_sync(&op, signer).expect("signs")
    }

    /// An event's bytes are its statement's frame, and decode as the variant
    /// that frame's kind names.
    #[test]
    fn an_event_is_its_statements_frame() {
        let signed = prekeys_expanded(&MemorySigner::generate(&mut rand::rngs::OsRng));
        let event = Event32::PrekeysExpanded(signed.signed().as_ref().clone());
        assert_eq!(
            event.encode().as_bytes(),
            signed.signed().encode().as_bytes()
        );
        assert_eq!(Event32::decode(event.encode().as_bytes()), Ok(event));
    }

    /// A frame of a kind no event carries, such as signed application bytes,
    /// is not an event.
    #[test]
    fn a_frame_no_event_carries_is_refused() {
        let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
        let bytes = Verified::sign_sync(&Bytes::from(vec![1, 2, 3]), &signer)
            .expect("signs")
            .signed()
            .encode();
        assert_eq!(
            Event32::decode(bytes.as_bytes()),
            Err(DecodeError::UnexpectedKind(Kind::BYTES.to_u8()))
        );
    }

    /// An event's identity is its statement's: the same for its in-memory and
    /// wire forms, and unchanged by the signature it carries.
    #[test]
    fn an_events_digest_is_its_statements() {
        let signed = prekeys_expanded(&MemorySigner::generate(&mut rand::rngs::OsRng));
        let event: Event<[u8; 32]> = Event::PrekeysExpanded(signed.signed().dupe());
        let wire = Event32::from(event.clone());
        let resigned = Event32::PrekeysExpanded(verified::Signed::new(
            signed.issuer(),
            signed.signed().encoded().clone(),
            ed25519_dalek::Signature::from_bytes(&[7; 64]),
        ));

        assert_eq!(event.digest().raw, signed.digest().raw);
        assert_eq!(wire.digest().raw, signed.digest().raw);
        assert_eq!(resigned.digest(), wire.digest());
    }
}
