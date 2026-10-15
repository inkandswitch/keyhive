//! The universally unique identifier of a principal.

use dupe::Dupe;
use keyhive_crypto::{
    id::{Id, InvalidId},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
#[cfg(any(feature = "test_utils", test))]
use tracing::instrument;

/// A unique identifier for a principal: an individual, group, or document.
///
/// This is a newtype for a [`VerifyingKey`](ed25519_dalek::VerifyingKey). Since a
/// signing key is held by one principal and never shared, this identifier is
/// provably unique.
#[derive(Copy, Serialize, Deserialize)]
pub struct Identifier(pub VerifyingKey);

impl Identifier {
    #[cfg(any(feature = "test_utils", test))]
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        SigningKey::generate(csprng).verifying_key().into()
    }

    /// Lower the [`Identifier`] to an owned binary representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Lower the [`Identifier`] to a borrowed binary representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the underlying bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for Identifier {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).unwrap();
        let key = SigningKey::from_bytes(&arr);
        Ok(key.verifying_key().into())
    }
}

impl Clone for Identifier {
    fn clone(&self) -> Self {
        *self
    }
}

impl Dupe for Identifier {
    fn dupe(&self) -> Self {
        *self
    }
}

impl Hash for Identifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        keyhive_crypto::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Identifier({})", self)
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Identifier {}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Verifiable for Identifier {
    fn verifying_key(&self) -> VerifyingKey {
        self.0
    }
}

impl From<VerifyingKey> for Identifier {
    fn from(verifying_key: VerifyingKey) -> Self {
        Self(verifying_key)
    }
}

impl From<&VerifyingKey> for Identifier {
    fn from(verifying_key: &VerifyingKey) -> Self {
        Self(*verifying_key)
    }
}

impl From<Identifier> for VerifyingKey {
    fn from(identifier: Identifier) -> Self {
        identifier.0
    }
}

impl From<SigningKey> for Identifier {
    fn from(sk: SigningKey) -> Self {
        sk.verifying_key().into()
    }
}

/// Into Keyline: fallible, because Keyline's [`Id`] rejects keys that are not
/// canonical encodings of prime-order points. A signing key never produces
/// one, but a peer could send one, and it is refused here.
impl TryFrom<Identifier> for Id {
    type Error = InvalidId;

    fn try_from(id: Identifier) -> Result<Id, InvalidId> {
        Id::try_from(id.0)
    }
}

impl From<Id> for Identifier {
    fn from(id: Id) -> Self {
        Identifier(id.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::{
        document::id::DocumentId, group::id::GroupId, individual::id::IndividualId,
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};

    /// Every identifier a signing key produces converts to a Keyline [`Id`]
    /// and back unchanged, whichever typed identifier carries it.
    #[test]
    fn signing_keys_round_trip_through_keyline() {
        bolero::check!().with_type::<[u8; 32]>().for_each(|seed| {
            let id: Identifier = SigningKey::from_bytes(seed).verifying_key().into();
            let keyline = Id::try_from(id).expect("a signing key's identifier is a valid Id");
            assert_eq!(Identifier::from(keyline), id);
            assert_eq!(keyline.as_bytes(), id.as_bytes());

            assert_eq!(Id::try_from(IndividualId::from(id)), Ok(keyline));
            assert_eq!(Id::try_from(GroupId::from(id)), Ok(keyline));
            assert_eq!(Id::try_from(DocumentId::from(id)), Ok(keyline));
            assert_eq!(Identifier::from(IndividualId::from(keyline)), id);
            assert_eq!(Identifier::from(GroupId::from(keyline)), id);
            assert_eq!(Identifier::from(DocumentId::from(keyline)), id);
        });
    }

    /// The identity point decompresses, so `ed25519_dalek` accepts it as a
    /// verifying key, but it has small order: Keyline refuses it.
    #[test]
    fn small_order_keys_are_refused_by_keyline() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).expect("the identity point decompresses");
        assert_eq!(Id::try_from(Identifier(weak)), Err(InvalidId::SmallOrder));
        assert_eq!(
            Id::try_from(GroupId::from(Identifier(weak))),
            Err(InvalidId::SmallOrder)
        );
    }
}
