use crate::{
    crypto::{share_key::ShareKey, verifiable::Verifiable},
    principal::individual::{id::IndividualId, op::KeyOp, Individual},
    util::hex::{self, ToHexString},
};
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, From, Into, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct ContactCard(pub(crate) KeyOp);

impl ContactCard {
    pub fn id(&self) -> IndividualId {
        self.0.issuer().into()
    }

    pub fn share_key(&self) -> &ShareKey {
        self.0.new_key()
    }

    pub fn signature(&self) -> &ed25519_dalek::Signature {
        self.0.signature()
    }

    pub fn op(&self) -> &KeyOp {
        &self.0
    }
}

impl ToHexString for ContactCard {
    fn to_hex_string(&self) -> String {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, &self)
            .expect("ContactCard should always serialize successfully");
        hex::bytes_to_hex_string(&buf)
    }
}

impl std::fmt::Display for ContactCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContactCard for ",)?;
        hex::bytes_as_hex(self.0.issuer().as_bytes().iter(), f)
    }
}

impl From<&ContactCard> for Individual {
    fn from(contact_card: &ContactCard) -> Individual {
        Individual::new(contact_card.0.clone())
    }
}

impl From<ContactCard> for Individual {
    fn from(contact_card: ContactCard) -> Individual {
        Individual::new(contact_card.0)
    }
}

impl Verifiable for ContactCard {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
