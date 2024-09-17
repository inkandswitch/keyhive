use super::membered::MemberedId;
use super::stateless::Stateless;
use super::traits::Verifiable;
use crate::access::Access;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::operation::Operation;
use crate::principal::agent::Agent;
use ed25519_dalek::VerifyingKey;
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
    pub verifier: VerifyingKey,
    pub authority_ops: BTreeSet<Signed<Operation>>,
    pub content_ops: BTreeSet<u8>, // FIXME automerge content
                                   // FIXME just cache view directly on the object?
                                   // FIXME also maybe just reference AM doc heads?
}

impl PartialOrd for Document {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.state.partial_cmp(&other.state)
    }
}

impl Ord for Document {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.state.cmp(&other.state)
    }
}

impl Verifiable for Document {
    fn verifying_key(&self) -> VerifyingKey {
        self.state.verifier
    }
}

impl PartialOrd for DocumentState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self
            .verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
        {
            Some(std::cmp::Ordering::Equal) => {
                if self.authority_ops == other.authority_ops
                    && self.content_ops == other.content_ops
                {
                    Some(std::cmp::Ordering::Equal)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Ord for DocumentState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

impl Verifiable for DocumentState {
    fn verifying_key(&self) -> VerifyingKey {
        self.verifier
    }
}

impl DocumentState {
    pub fn new(parent: Stateless) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let doc_verifier: VerifyingKey = signing_key.verifying_key();

        let init = Operation::Delegation(Delegation {
            subject: MemberedId::DocumentId(doc_verifier.into()),

            from: doc_verifier.into(),

            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        });

        let signed_init = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            verifier: doc_verifier,
            authority_ops: BTreeSet::from_iter([signed_init]),
            content_ops: BTreeSet::new(),
        }
    }
}
