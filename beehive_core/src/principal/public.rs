use super::{
    active::Active,
    identifier::Identifier,
    individual::{op::KeyOp, state::PrekeyState, Individual},
    verifiable::Verifiable,
};
use crate::crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
};
use dupe::Dupe;
use std::collections::{BTreeMap, HashSet};

/// A well-known agent that can be used by anyone. ⚠ USE WITH CAUTION ⚠
///
/// This is a constant key that is publicly-known.
/// Sharing to this key is equivalent to setting a document to "public" by using a
/// pre-leaked key. We use this so that the visibility of a document can be made
/// temporarily public and later revoked.
#[derive(Debug, Clone, Dupe, Copy)]
pub struct Public;

impl Public {
    pub fn id(&self) -> Identifier {
        self.verifying_key().into()
    }

    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from([0; 32])
    }

    pub fn share_secret_key(&self) -> ShareSecretKey {
        x25519_dalek::StaticSecret::from([0; 32]).into()
    }

    pub fn share_key(&self) -> ShareKey {
        self.share_secret_key().share_key()
    }

    pub fn individual(&self) -> Individual {
        let op = Signed::try_sign(KeyOp::add(self.share_key()), &self.signing_key())
            .expect("signature with well-known key should work");

        Individual {
            id: self.verifying_key().into(),
            prekeys: HashSet::from_iter([self.share_key()]),
            prekey_state: PrekeyState::from_iter([op])
                .expect("well-known prekey op should be valid"),
        }
    }

    pub fn active(&self) -> Active {
        Active {
            signing_key: self.signing_key(),
            prekey_pairs: BTreeMap::from_iter([(self.share_key(), self.share_secret_key())]),
            individual: self.individual(),
        }
    }
}

impl Verifiable for Public {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from(&self.signing_key())
    }
}
