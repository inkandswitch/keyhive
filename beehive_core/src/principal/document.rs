use super::{identifier::Identifier, individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{
        agent::{Agent, AgentId},
        group::{
            operation::{delegation::Delegation, revocation::Revocation, Operation},
            Group,
        },
        individual::Individual,
        membered::MemberedId,
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document<'a, T: ContentRef> {
    pub(crate) group: Group<'a, T>,
    pub(crate) reader_keys: HashMap<IndividualId, (&'a Individual, ShareKey)>, // FIXME May remove when BeeKEM, also FIXME Individual ID
    pub(crate) content_state: HashSet<T>,
}

impl<'a, T: ContentRef> Document<'a, T> {
    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Digest<Signed<Delegation<'a, T>>>>> {
        &self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<'a, T>>> {
        &self.group.delegations()
    }

    pub fn get_capabilty(&'a self, member_id: &AgentId) -> Option<&'a Signed<Delegation<'a, T>>> {
        self.members().get(member_id).map(move |hashes| {
            hashes
                .iter()
                .map(|h| self.delegations().get(h).unwrap())
                .into_iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })?
    }

    pub fn get_members(&'a self) -> HashMap<AgentId, Vec<&'a Signed<Delegation<'a, T>>>> {
        self.members()
            .iter()
            .map(|(id, hashes)| {
                (
                    *id,
                    hashes
                        .iter()
                        .map(|h| self.delegations().get(h).unwrap())
                        .collect(),
                )
            })
            .collect()
    }

    pub fn generate(parents: NonEmpty<&'a Agent<T>>) -> Self {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let mut doc = Document {
            group: Group::generate(parents.clone()),
            content_state: HashSet::new(),
            reader_keys: HashMap::new(), // FIXME
        };

        for parent in parents.iter() {
            let dlg = Signed::sign(
                Delegation {
                    delegate: *parent,
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &doc_signer,
            );

            let hash = doc.group.state.delegations.insert(dlg);
            doc.group.state.delegation_heads.insert(hash);

            doc.group.members.insert(parent.agent_id(), vec![hash]);
        }

        doc
    }

    pub fn add_member(&'a mut self, signed_delegation: Signed<Delegation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let hash = self.group.state.delegations.insert(signed_delegation);

        match self.group.members.get_mut(&id) {
            Some(caps) => {
                caps.push(hash);
            }
            None => {
                self.group.members.insert(id, vec![]);
            }
        }
    }

    pub fn materialize(&'a mut self) {
        self.group.materialize();
    }
}

// FIXME test
impl<'a, T: ContentRef> std::hash::Hash for Document<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group.hash(state);

        for key in self.reader_keys.keys() {
            key.hash(state);
        }

        for c in self.content_state.iter() {
            c.hash(state);
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DocStore<'a, T: ContentRef> {
    pub docs: BTreeMap<DocumentId, Document<'a, T>>,
}

impl<'a, T: ContentRef> DocStore<'a, T> {
    pub fn new() -> Self {
        Self {
            docs: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, doc: Document<'a, T>) {
        self.docs.insert(doc.doc_id(), doc);
    }

    pub fn get(&'a self, id: &DocumentId) -> Option<&'a Document<'a, T>> {
        self.docs.get(id)
    }

    pub fn generate_document(
        &'a mut self,
        parents: NonEmpty<&'a Agent<'a, T>>,
    ) -> &'a Document<'a, T> {
        let new_doc = Document::generate(parents);
        let new_doc_id: DocumentId = new_doc.doc_id();
        self.insert(new_doc);
        self.get(&new_doc_id)
            .expect("document that was just added is missing")
    }

    // FIXME shoudl be more like this:
    // pub fn transitive_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    // FIXME return path as well?
    pub fn transitive_members(
        &'a self,
        doc: &'a Document<'a, T>,
    ) -> BTreeMap<AgentId, (&'a Agent<'a, T>, Access)> {
        struct GroupAccess<'a, U: ContentRef> {
            agent: &'a Agent<'a, U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<'a, T>> = vec![];

        for hashes in doc.group.members.values() {
            for hash in hashes {
                let delegation = doc.group.state.delegations.get(hash).unwrap();
                explore.push(GroupAccess {
                    agent: delegation.payload().delegate,
                    agent_access: delegation.payload().can, // FIXME need to lookup
                    parent_access: Access::Admin,
                });
            }
        }

        let mut caps: BTreeMap<AgentId, (&Agent<T>, Access)> = BTreeMap::new();

        while let Some(GroupAccess {
            agent: member,
            agent_access: access,
            parent_access,
        }) = explore.pop()
        {
            match member {
                Agent::Active(_) | Agent::Individual(_) => {
                    let current_path_access = access.min(parent_access);

                    let best_access =
                        if let Some((_, prev_found_path_access)) = caps.get(&member.agent_id()) {
                            (*prev_found_path_access).max(current_path_access)
                        } else {
                            current_path_access
                        };

                    caps.insert(member.agent_id(), (member, best_access));
                }
                Agent::Group(group) => {
                    for (mem, proofs) in group.get_members().iter() {
                        for proof in proofs.iter() {
                            let current_path_access =
                                access.min(proof.payload().can).min(parent_access);

                            let best_access =
                                if let Some((_, prev_found_path_access)) = caps.get(&mem) {
                                    (*prev_found_path_access).max(current_path_access)
                                } else {
                                    current_path_access
                                };

                            explore.push(GroupAccess {
                                agent: &proof.payload().delegate,
                                agent_access: best_access,
                                parent_access,
                            });
                        }
                    }
                }
                Agent::Document(doc) => {
                    for (mem, proof_hashes) in doc.group.members.iter() {
                        for proof_hash in proof_hashes.iter() {
                            let proof = doc.group.state.delegations.get(proof_hash).unwrap();
                            let current_path_access =
                                access.min(proof.payload().can).min(parent_access);

                            let best_access =
                                if let Some((_, prev_found_path_access)) = caps.get(&mem) {
                                    (*prev_found_path_access).max(current_path_access)
                                } else {
                                    current_path_access
                                };

                            explore.push(GroupAccess {
                                agent: &proof.payload().delegate,
                                agent_access: best_access,
                                parent_access,
                            });
                        }
                    }
                }
            }
        }

        caps
    }
}

impl<'a, T: ContentRef> Verifiable for Document<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DocumentId(pub Identifier);

impl DocumentId {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<DocumentId> for Identifier {
    fn from(id: DocumentId) -> Identifier {
        id.0
    }
}

impl From<DocumentId> for MemberedId {
    fn from(id: DocumentId) -> MemberedId {
        MemberedId::DocumentId(id.into())
    }
}

impl Verifiable for DocumentId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.into()
    }
}

impl Display for DocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
