use beekem::id::MemberId;
use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_crypto::{
    identifier::{Identifier, InvalidIdentifier},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct IndividualId(pub Identifier);

impl IndividualId {
    pub fn new(id: Identifier) -> Self {
        Self(id)
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self::from(&SigningKey::generate(csprng))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The whole key, `0x`-prefixed.
impl fmt::Display for IndividualId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Dupe for IndividualId {}

impl From<Identifier> for IndividualId {
    fn from(id: Identifier) -> Self {
        IndividualId(id)
    }
}

impl From<IndividualId> for Identifier {
    fn from(id: IndividualId) -> Self {
        id.0
    }
}

impl From<&SigningKey> for IndividualId {
    fn from(key: &SigningKey) -> Self {
        IndividualId(Identifier::from(key))
    }
}

impl TryFrom<VerifyingKey> for IndividualId {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::try_from(key).map(IndividualId)
    }
}

impl From<MemberId> for IndividualId {
    fn from(member: MemberId) -> Self {
        IndividualId(member.id())
    }
}

impl From<IndividualId> for MemberId {
    fn from(id: IndividualId) -> Self {
        MemberId::from(id.0)
    }
}

impl Verifiable for IndividualId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

/// Its identifier's 32 bytes.
impl keyhive_codec::traits::Encode for IndividualId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl keyhive_codec::traits::Decode for IndividualId {
    fn decode(bytes: &[u8]) -> Result<Self, keyhive_codec::error::DecodeError> {
        keyhive_codec::traits::decode_exact(bytes)
    }
}

impl keyhive_codec::traits::StreamDecode for IndividualId {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), keyhive_codec::error::DecodeError> {
        let (id, rest) = Identifier::decode_next(bytes)?;
        Ok((IndividualId(id), rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::{document::id::DocumentId, group::id::GroupId};

    /// The identity point decompresses, so `ed25519_dalek` accepts it as a
    /// verifying key, but it has small order: no principal can be named by it.
    #[test]
    fn small_order_keys_name_no_principal() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).expect("the identity point decompresses");
        assert_eq!(
            IndividualId::try_from(weak),
            Err(InvalidIdentifier::SmallOrder)
        );
        assert_eq!(
            DocumentId::try_from(weak),
            Err(InvalidIdentifier::SmallOrder)
        );
        assert_eq!(GroupId::try_from(weak), Err(InvalidIdentifier::SmallOrder));
    }

    /// A typed id is its key: its bytes, slice and verifying key all come back
    /// as the key went in.
    #[test]
    fn typed_ids_are_their_keys() {
        bolero::check!().with_type::<[u8; 32]>().for_each(|seed| {
            let key = SigningKey::from_bytes(seed);
            let (vk, bytes) = (key.verifying_key(), key.verifying_key().to_bytes());

            let individual = IndividualId::from(&key);
            assert_eq!(
                (
                    individual.as_slice(),
                    individual.as_bytes(),
                    individual.to_bytes()
                ),
                (&bytes[..], &bytes, bytes)
            );
            assert_eq!(individual.verifying_key(), vk);

            let document = DocumentId::from(&key);
            assert_eq!(
                (
                    document.as_slice(),
                    document.as_bytes(),
                    document.to_bytes()
                ),
                (&bytes[..], &bytes, bytes)
            );
            assert_eq!(document.verifying_key(), vk);

            let group = GroupId::from(&key);
            assert_eq!(
                (group.as_slice(), group.as_bytes(), group.to_bytes()),
                (&bytes[..], &bytes, bytes)
            );
            assert_eq!(group.verifying_key(), vk);
        });
    }

    /// JS `toString` and its callers' map keys read the whole key.
    #[test]
    fn principals_display_as_the_whole_key() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let hex: String = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected = format!("0x{hex}");
        assert_eq!(IndividualId::from(&key).to_string(), expected);
        assert_eq!(DocumentId::from(&key).to_string(), expected);
        assert_eq!(GroupId::from(&key).to_string(), expected);
    }
}
