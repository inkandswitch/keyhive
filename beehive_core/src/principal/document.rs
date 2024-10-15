use super::{identifier::Identifier, verifiable::Verifiable};
use crate::{
    access::Access,
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{
        agent::Agent,
        group::operation::{delegation::Delegation, revocation::Revocation, Operation},
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document<T: Serialize> {
    pub members: BTreeMap<Identifier, Digest<Signed<Delegation<T>>>>,
    pub reader_keys: BTreeMap<Identifier, ShareKey>, // FIXME May remove when BeeKEM, also FIXME Individual ID
    // NOTE: as expected, separate keys are still safer https://doc.libsodium.org/quickstart#do-i-need-to-add-a-signature-to-encrypted-messages-to-detect-if-they-have-been-tampered-with
    pub state: DocumentState<T>,
}

impl<T: Serialize> Document<T> {
    pub fn id(&self) -> &Identifier {
        &self.state.id
    }

    pub fn generate(parents: Vec<&Agent<T>>) -> Self {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let doc_id = doc_signer.verifying_key().into();

        let (delegations, members) = parents.iter().fold(
            (CaMap::new(), BTreeMap::new()),
            |(mut d_acc, mut mem_acc), parent| {
                let del = Signed::sign(
                    Delegation {
                        delegate: *parent,
                        can: Access::Admin,
                        proof: None,
                        after_revocations: vec![],
                        after_content: vec![],
                    },
                    &doc_signer,
                );

                mem_acc.insert(*parent, &del);

                d_acc.insert(del);
                (d_acc, mem_acc)
            },
        );

        Document {
            members,
            state: DocumentState {
                id: doc_id,

                delegation_heads: delegations.keys().collect(),
                delegations,

                revocation_heads: BTreeSet::new(),
                revocations: CaMap::new(),

                content_ops: BTreeSet::new(),
            },
            reader_keys: BTreeMap::new(), // FIXME
        }
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let hash = self.state.delegations.insert(signed_delegation);
        let new_ref = self.state.delegations.get(&hash).unwrap();
        self.members.insert(&new_ref.payload.delegate, &new_ref);
    }

    pub fn materialize(state: DocumentState<T>) -> Self {
        // FIXME oof that's a lot of cloning to get the heads
        let members = Operation::topsort(
            state.delegation_heads.clone().into_iter().collect(),
            &state.delegations,
        )
        .expect("FIXME")
        .iter()
        .fold(BTreeMap::new(), |mut acc, signed| match signed {
            Signed {
                payload: Operation::Delegation(delegation),
                signature,
                verifying_key,
            } => {
                acc.insert(
                    delegation.delegate.clone(),
                    (
                        delegation.can,
                        Signed {
                            payload: delegation.clone(),
                            signature: *signature,
                            verifying_key: *verifying_key,
                        },
                    ),
                );

                acc
            }
            Signed {
                payload: Operation::Revocation(revocation),
                ..
            } =>
            // FIXME allow downgrading instead of straight removal?
            {
                acc.remove(&revocation.revoke.payload.delegate);
                acc
            }
        });

        Document {
            state,
            members,
            reader_keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentState<T: Serialize> {
    pub id: Identifier,

    pub delegation_heads: BTreeSet<Digest<Signed<Delegation<T>>>>,
    pub delegations: CaMap<Signed<Delegation<T>>>,

    pub revocation_heads: BTreeSet<Digest<Revocation<T>>>,
    pub revocations: CaMap<Signed<Revocation<T>>>,

    pub content_ops: BTreeSet<T>,
}

impl<T: Serialize> Verifiable for Document<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.state.verifying_key()
    }
}

impl<T: Serialize> Verifiable for DocumentState<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.0
    }
}

impl<T: Serialize> DocumentState<T> {
    pub fn new(parent: &Agent<T>) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let id: Identifier = signing_key.verifying_key().into();

        let init = Signed::sign(
            Delegation {
                delegate: &parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &signing_key,
        );

        Self {
            id,

            delegation_heads: BTreeSet::from_iter([Digest::hash(&init)]),
            delegations: CaMap::from_iter([init]),

            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),

            content_ops: BTreeSet::new(),
        }
    }

    pub fn delegations_for(&self, agent: &Agent<T>) -> Vec<&Signed<Delegation<T>>> {
        self.delegations // FIXME account for revocations
            .iter()
            .filter(|(_, delegation)| delegation.payload.delegate == agent)
            .collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DocStore<T: Serialize> {
    pub docs: BTreeMap<Identifier, Document<T>>, // FIXME DocID
}

impl<T: Serialize> DocStore<T> {
    pub fn new() -> Self {
        Self {
            docs: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, doc: Document<T>)
    where
        T: Eq,
    {
        self.docs.insert(doc.verifying_key().into(), doc);
    }

    pub fn get(&self, id: &Identifier) -> Option<&Document<T>> {
        self.docs.get(id)
    }

    pub fn generate_document(&mut self, parents: Vec<&Agent<T>>) -> &Document<T> {
        let new_doc: Document<T> = Document::generate(parents);
        let new_doc_id: Identifier = new_doc.verifying_key().into(); // FIXME add helper method
        self.insert(new_doc);
        self.get(&new_doc_id).expect("FIXME")
    }

    // FIXME shoudl be more like this:
    // pub fn transative_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    // FIXME return path as well?
    pub fn transative_members(&self, doc: &Document<T>) -> BTreeMap<Identifier, Access> {
        struct GroupAccess {
            agent: Identifier,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, delegation) in doc.members.iter() {
            explore.push(GroupAccess {
                agent: *k,
                agent_access: delegation.payload.can, // FIXME need to lookup
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<&Agent<T>, Access> = BTreeMap::new();

        while !explore.is_empty() {
            if let Some(GroupAccess {
                agent: member,
                agent_access: access,
                parent_access,
            }) = explore.pop()
            {
                match member {
                    Agent::Individual(_) => {
                        let current_path_access = access.min(parent_access);

                        let best_access = if let Some(prev_found_path_access) = caps.get(&member) {
                            (*prev_found_path_access).max(current_path_access)
                        } else {
                            current_path_access
                        };

                        caps.insert(member, best_access);
                    }
                    _ => {
                        if let Some(group) = self.docs.get(&member.verifying_key().into()) {
                            for (mem, (pow, _proof)) in group.members.clone() {
                                let current_path_access = access.min(pow).min(parent_access);

                                let best_access =
                                    if let Some(prev_found_path_access) = caps.get(&mem) {
                                        (*prev_found_path_access).max(current_path_access)
                                    } else {
                                        current_path_access
                                    };

                                explore.push(GroupAccess {
                                    agent: &mem,
                                    agent_access: best_access,
                                    parent_access,
                                });
                            }
                        }
                    }
                }
            }
        }

        caps
    }
}
