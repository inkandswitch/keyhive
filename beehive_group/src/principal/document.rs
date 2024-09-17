use super::identifier::Identifier;
use super::individual::Individual;
use super::membered::MemberedId;
use super::traits::Verifiable;
use crate::access::Access;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::operation::Operation;
use crate::principal::agent::Agent;
use ed25519_dalek::VerifyingKey;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

// Materialized
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    pub authorizations: BTreeMap<Agent, Access>,
    pub reader_keys: BTreeMap<Agent, ShareKey>, // FIXME May remove if TreeKEM instead of ART
    // NOTE: as expected, separate keys are still safer https://doc.libsodium.org/quickstart#do-i-need-to-add-a-signature-to-encrypted-messages-to-detect-if-they-have-been-tampered-with
    pub state: DocumentState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentState {
    pub id: Identifier,
    pub authority_ops: BTreeSet<Signed<Operation>>,
    pub content_ops: BTreeSet<u8>, // FIXME automerge content
                                   // FIXME just cache view directly on the object?
                                   // FIXME also maybe just reference AM doc heads?
}

impl PartialOrd for Document {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.state.partial_cmp(&other.state)
    }
}

impl Ord for Document {
    fn cmp(&self, other: &Self) -> Ordering {
        self.state.cmp(&other.state)
    }
}

impl Verifiable for Document {
    fn verifying_key(&self) -> VerifyingKey {
        self.state.id.verifying_key
    }
}

impl PartialOrd for DocumentState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.id.as_bytes().partial_cmp(&other.id.as_bytes()) {
            Some(Ordering::Equal) => {
                if self.authority_ops == other.authority_ops
                    && self.content_ops == other.content_ops
                {
                    Some(Ordering::Equal)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Ord for DocumentState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.as_bytes().cmp(&other.id.as_bytes())
    }
}

impl Verifiable for DocumentState {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.verifying_key
    }
}

impl DocumentState {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let id: Identifier = signing_key.verifying_key().into();

        let init = Operation::Delegation(Delegation {
            subject: MemberedId::DocumentId(id),

            from: id.into(), // FIXME would be nice if this was CBC

            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        });

        let signed_init = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id,
            authority_ops: BTreeSet::from_iter([signed_init]),
            content_ops: BTreeSet::new(),
        }
    }
}
