use super::{
    active::Active,
    agent::Agent,
    identifier::Identifier,
    individual::{op::add_key::AddKeyOp, state::PrekeyState, Individual},
    peer::Peer,
};
use crate::{
    content::reference::ContentRef,
    crypto::{
        application_secret::PcsKey,
        digest::Digest,
        share_key::{ShareKey, ShareSecretKey},
        signed::Signed,
        verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, prekey::PrekeyListener},
};
use dupe::Dupe;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

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

    pub fn share_key(&self) -> ShareKey {
        self.share_secret_key().share_key()
    }

    pub fn share_secret_key(&self) -> ShareSecretKey {
        x25519_dalek::StaticSecret::from([0; 32]).into()
    }

    pub fn pcs_key(&self) -> PcsKey {
        self.share_secret_key().into()
    }

    pub fn pcs_key_hash(&self) -> Digest<PcsKey> {
        Digest::hash(&self.pcs_key())
    }

    pub fn individual(&self) -> Individual {
        let op = Rc::new(
            Signed::try_sign(
                AddKeyOp {
                    share_key: self.share_key(),
                },
                &self.signing_key(),
            )
            .expect("signature with well-known key should work"),
        )
        .into();

        dbg!("INNER");

        Individual {
            id: self.verifying_key().into(),
            prekeys: HashSet::from_iter([self.share_key()]),
            prekey_state: PrekeyState::try_from_iter([op])
                .expect("well-known prekey op should be valid"),
        }
    }

    pub fn peer<T: ContentRef, L: MembershipListener<T>>(&self) -> Peer<T, L> {
        Rc::new(RefCell::new(self.individual())).into()
    }

    pub fn agent<T: ContentRef, L: MembershipListener<T>>(&self) -> Agent<T, L> {
        Rc::new(RefCell::new(self.individual())).into()
    }

    pub fn active<L: PrekeyListener>(&self, listener: L) -> Active<L> {
        Active {
            signing_key: self.signing_key(),
            prekey_pairs: BTreeMap::from_iter([(self.share_key(), self.share_secret_key())]),
            individual: self.individual(),
            listener,
        }
    }
}

impl Verifiable for Public {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from(&self.signing_key())
    }
}
