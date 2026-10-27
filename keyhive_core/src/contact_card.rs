use crate::principal::individual::{
    id::IndividualId,
    op::{KeyOp, SignedKeyOp},
    IndividualState,
};
use derive_more::{From, Into};
use ed25519_dalek::{Signature, VerifyingKey};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{
    hex::{self, ToHexString},
    share_key::ShareKey,
    verifiable::Verifiable,
    verified::VerifyError,
};
use std::fmt;
use thiserror::Error;

/// An individual's introduction: one of its prekey operations, verified.
/// Deserializing one checks its signature.
#[derive(Debug, Clone, PartialEq, Eq, From, Into, Hash)]
pub struct ContactCard(pub(crate) KeyOp);

impl ContactCard {
    pub fn id(&self) -> IndividualId {
        IndividualId::from(self.0.issuer())
    }

    pub fn share_key(&self) -> &ShareKey {
        self.0.new_key()
    }

    pub fn signature(&self) -> &Signature {
        self.0.signature()
    }

    pub fn op(&self) -> &KeyOp {
        &self.0
    }

    /// The prekey operation's `KH` frame.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.signed().encode().into_bytes()
    }

    /// Read a card from [`ContactCard::to_bytes`], checking its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContactCardError> {
        Ok(ContactCard(SignedKeyOp::decode(bytes)?.verify()?))
    }
}

/// The hex of [`ContactCard::to_bytes`].
impl ToHexString for ContactCard {
    fn to_hex_string(&self) -> String {
        hex::bytes_to_hex_string(&self.to_bytes())
    }
}

impl fmt::Display for ContactCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContactCard for ",)?;
        hex::bytes_as_hex(self.0.issuer().as_bytes().iter(), f)
    }
}

impl From<&ContactCard> for IndividualState {
    fn from(contact_card: &ContactCard) -> IndividualState {
        IndividualState::new(contact_card.0.clone())
    }
}

impl From<ContactCard> for IndividualState {
    fn from(contact_card: ContactCard) -> IndividualState {
        IndividualState::new(contact_card.0)
    }
}

impl Verifiable for ContactCard {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

/// Why bytes are not a contact card.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContactCardError {
    /// The bytes are not a prekey operation's frame.
    #[error(transparent)]
    Decode(#[from] DecodeError),

    /// The operation's signature does not verify against its issuer.
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::individual::op::rotate_key::RotateKeyOp;
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verified::Verified,
    };

    fn card() -> ContactCard {
        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(csprng);
        let mut key = || ShareSecretKey::generate(csprng).share_key();
        let rotate = RotateKeyOp {
            old: key(),
            new: key(),
        };
        ContactCard::from(KeyOp::Rotate(
            Verified::sign_sync(&rotate, &signer).expect("signs"),
        ))
    }

    #[test]
    fn a_card_round_trips_through_its_bytes() {
        let card = card();
        let bytes = card.to_bytes();
        assert_eq!(&bytes[..4], b"KHT\x00", "a rotation's frame");
        assert_eq!(ContactCard::from_bytes(&bytes), Ok(card.clone()));
        assert_eq!(card.to_hex_string(), hex::bytes_to_hex_string(&bytes));
    }

    #[test]
    fn a_card_whose_signature_does_not_verify_is_refused() {
        let mut bytes = card().to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            ContactCard::from_bytes(&bytes),
            Err(ContactCardError::Verify(VerifyError::BadSignature))
        );
    }

    #[test]
    fn bytes_that_are_not_a_prekey_operation_are_refused() {
        let mut bytes = card().to_bytes();
        bytes[2] = b'D';
        assert_eq!(
            ContactCard::from_bytes(&bytes),
            Err(ContactCardError::Decode(DecodeError::UnexpectedKind(b'D')))
        );
    }
}
