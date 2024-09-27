use super::identifier::Identifier;
use super::individual::Individual;
use super::membered::MemberedId;
use super::traits::Verifiable;
use crate::access::Access;
use crate::crypto::hash::Hash;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::group::operation::delegation::Delegation;
use crate::principal::group::operation::Operation;
use crate::util::content_addressed_map::CaMap;
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

// Materialized
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    pub delegates: BTreeMap<Agent, (Access, Signed<Delegation>)>,
    pub reader_keys: BTreeMap<Individual, ShareKey>, // FIXME May remove if TreeKEM instead of ART
    // NOTE: as expected, separate keys are still safer https://doc.libsodium.org/quickstart#do-i-need-to-add-a-signature-to-encrypted-messages-to-detect-if-they-have-been-tampered-with
    pub state: DocumentState,
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.state.id.as_bytes()))
    }
}

impl Document {
    pub fn create(parents: Vec<&Agent>) -> Self {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let doc_id = doc_signer.verifying_key().into(); // FIXME zero out after

        let (ops, delegates) = parents.iter().fold(
            (CaMap::new(), BTreeMap::new()),
            |(mut op_acc, mut mem_acc), parent| {
                let del = Delegation {
                    subject: MemberedId::DocumentId(doc_id),
                    from: doc_id,
                    to: (*parent).clone(),
                    can: Access::Admin,
                    proof: vec![],
                    after_auth: vec![],
                };

                let signed_op = Signed::sign(del.clone().into(), &doc_signer);
                let signed_del = Signed::sign(del, &doc_signer);

                mem_acc.insert((*parent).clone(), (Access::Admin, signed_del.clone()));

                op_acc.insert(signed_op);
                (op_acc, mem_acc)
            },
        );

        Document {
            delegates,
            state: DocumentState {
                id: doc_id,
                auth_heads: BTreeSet::from_iter(ops.clone().into_keys()),
                authority_ops: ops,
                content_ops: BTreeSet::new(),
            },
            reader_keys: BTreeMap::new(), // FIXME
        }
    }

    pub fn id(&self) -> Identifier {
        self.state.id
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.delegates.insert(
            signed_delegation.payload.to.clone(),
            (signed_delegation.payload.can, signed_delegation.clone()),
        );

        self.state
            .authority_ops
            .insert(signed_delegation.map(|delegation| delegation.into()).into());
    }

    pub fn materialize(state: DocumentState) -> Self {
        // FIXME oof that's a lot of cloning to get the heads
        let delegates = Operation::topsort(
            state.auth_heads.clone().into_iter().collect(),
            &state.authority_ops,
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
                    delegation.to.clone(),
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
                acc.remove(&revocation.revoke.payload.to);
                acc
            }
        });

        Document {
            state,
            delegates,
            reader_keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentState {
    pub id: Identifier,
    pub auth_heads: BTreeSet<Hash<Signed<Operation>>>,
    pub authority_ops: CaMap<Signed<Operation>>,
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

        let signed_init = Signed::sign(init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id,
            auth_heads: BTreeSet::from_iter([Hash::hash(signed_init.clone())]),
            authority_ops: CaMap::from_iter([signed_init]),
            content_ops: BTreeSet::new(),
        }
    }

    pub fn delegations_for(&self, agent: &Agent) -> Vec<Signed<Delegation>> {
        self.authority_ops
            .iter()
            .filter_map(|(_, op)| {
                if let Operation::Delegation(delegation) = &op.payload {
                    if delegation.to == *agent {
                        return Some(op.clone().map(|_| delegation.clone()));
                    }
                }
                None
            })
            .collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct DocStore {
    pub docs: BTreeMap<Identifier, Document>,
}

impl DocStore {
    pub fn insert(&mut self, doc: Document) {
        self.docs.insert(doc.verifying_key().into(), doc);
    }

    pub fn get(&self, id: &Identifier) -> Option<&Document> {
        self.docs.get(id)
    }

    pub fn create_document(&mut self, parents: Vec<&Agent>) -> &Document {
        let new_doc: Document = Document::create(parents);
        let new_doc_id: Identifier = new_doc.verifying_key().into(); // FIXME add helper method
        self.insert(new_doc);
        self.get(&new_doc_id).expect("FIXME")
    }

    // FIXME shoudl be more like this:
    // pub fn transative_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    // FIXME return path as well?
    pub fn transative_members(&self, doc: &Document) -> BTreeMap<Agent, Access> {
        struct GroupAccess {
            agent: Agent,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, (v, _)) in doc.delegates.iter() {
            explore.push(GroupAccess {
                agent: k.clone(),
                agent_access: *v,
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<Agent, Access> = BTreeMap::new();

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
                            for (mem, (pow, _proof)) in group.delegates.clone() {
                                let current_path_access = access.min(pow).min(parent_access);

                                let best_access =
                                    if let Some(prev_found_path_access) = caps.get(&mem) {
                                        (*prev_found_path_access).max(current_path_access)
                                    } else {
                                        current_path_access
                                    };

                                explore.push(GroupAccess {
                                    agent: mem,
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
