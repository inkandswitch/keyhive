use super::{identifier::Identifier, individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{
        agent::{Agent, AgentId},
        group::operation::{delegation::Delegation, revocation::Revocation, Operation},
        individual::Individual,
        membered::MemberedId,
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document<'a, T: ContentRef> {
    pub members: HashMap<AgentId, Vec<Digest<Signed<Delegation<'a, T>>>>>,
    pub reader_keys: HashMap<IndividualId, (&'a Individual, ShareKey)>, // FIXME May remove when BeeKEM, also FIXME Individual ID
    pub state: DocumentState<'a, T>,
    pub op_heads: Vec<(Digest<Operation<'a, T>>, Operation<'a, T>)>,
}

impl<'a, T: ContentRef> Document<'a, T> {
    pub fn doc_id(&self) -> DocumentId {
        self.state.id
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn get_capabilty(&'a self, member_id: &AgentId) -> Option<&'a Signed<Delegation<'a, T>>> {
        self.members.get(member_id).map(move |hashes| {
            hashes
                .iter()
                .map(|h| self.state.delegations.get(h).unwrap())
                .into_iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })?
    }

    pub fn get_members(&'a self) -> HashMap<AgentId, Vec<&'a Signed<Delegation<'a, T>>>> {
        self.members
            .iter()
            .map(|(id, hashes)| {
                (
                    *id,
                    hashes
                        .iter()
                        .map(|h| self.state.delegations.get(h).unwrap())
                        .collect(),
                )
            })
            .collect()
    }

    pub fn generate(parents: Vec<&'a Agent<T>>) -> Self {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let doc_id = DocumentId(doc_signer.verifying_key().into());

        let mut doc = Document {
            members: HashMap::new(),
            op_heads: vec![], // FIXME
            state: DocumentState {
                id: doc_id,

                delegation_heads: HashSet::new(),
                delegations: CaMap::new(),

                revocation_heads: HashSet::new(),
                revocations: CaMap::new(),

                content_refs: HashSet::new(),
            },
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

            let hash = doc.state.delegations.insert(dlg);
            doc.state.delegation_heads.insert(hash);

            doc.members.insert(parent.agent_id(), vec![hash]);
        }

        doc
    }

    pub fn add_member(&'a mut self, signed_delegation: Signed<Delegation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let hash = self.state.delegations.insert(signed_delegation);

        match self.members.get_mut(&id) {
            Some(caps) => {
                caps.push(hash);
            }
            None => {
                self.members.insert(id, vec![]);
            }
        }
    }

    pub fn materialize(&'a mut self) {
        // pub fn materialize(&mut self state: DocumentState<'a, T>) -> Self {
        // FIXME oof that's a lot of cloning to get the heads
        self.op_heads = self
            .state
            .delegations
            .iter()
            .map(|(h, d)| (h.coerce(), Operation::Delegation(d)))
            .chain(
                self.state
                    .revocations
                    .iter()
                    .map(|(h, r)| (h.coerce(), Operation::Revocation(r))),
            )
            .collect();

        for (digest, op) in Operation::topsort(&self.op_heads).expect("FIXME").iter() {
            match op {
                Operation::Delegation(d) => {
                    self.members
                        .insert(d.payload().delegate.agent_id(), vec![digest.coerce()]);
                }
                Operation::Revocation(r) => {
                    self.members
                        .remove(&r.payload().revoke.payload().delegate.agent_id());
                }
            };
        }
    }
}

// FIXME test
impl<'a, T: ContentRef> std::hash::Hash for Document<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for m in self.members.iter() {
            m.hash(state);
        }

        for r in self.reader_keys.iter() {
            r.hash(state);
        }

        self.state.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentState<'a, T: ContentRef> {
    pub id: DocumentId,

    pub delegation_heads: HashSet<Digest<Signed<Delegation<'a, T>>>>,
    pub delegations: CaMap<Signed<Delegation<'a, T>>>,

    pub revocation_heads: HashSet<Digest<Revocation<'a, T>>>,
    pub revocations: CaMap<Signed<Revocation<'a, T>>>,

    pub content_refs: HashSet<T>,
}

// FIXME test
impl<'a, T: ContentRef> std::hash::Hash for DocumentState<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);

        for dh in self.delegation_heads.iter() {
            dh.hash(state);
        }

        self.delegations.hash(state);

        for rh in self.revocation_heads.iter() {
            rh.hash(state);
        }

        self.revocations.hash(state);

        for c in self.content_refs.iter() {
            c.hash(state);
        }
    }
}

impl<'a, T: ContentRef> Verifiable for Document<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.state.verifying_key()
    }
}

impl<'a, T: ContentRef> Verifiable for DocumentState<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.0.into()
    }
}

impl<'a, T: ContentRef> DocumentState<'a, T> {
    pub fn new(parent: &'a Agent<'a, T>) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let id = DocumentId(signing_key.verifying_key().into());

        let init = Signed::sign(
            Delegation {
                delegate: &parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            },
            &signing_key,
        );

        let mut delegations = CaMap::new();
        let hash = delegations.insert(init);

        Self {
            id,

            delegation_heads: HashSet::from_iter([hash]),
            delegations,

            revocation_heads: HashSet::new(),
            revocations: CaMap::new(),

            content_refs: HashSet::new(),
        }
    }

    pub fn delegations_for(
        &'a self,
        agent: &'a Agent<'a, T>,
    ) -> Vec<&'a Signed<Delegation<'a, T>>> {
        self.delegations // FIXME account for revocations
            .iter()
            .filter_map(|(_, delegation)| {
                if delegation.payload().delegate == agent {
                    Some(delegation)
                } else {
                    None
                }
            })
            .collect()
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

    pub fn generate_document(&'a mut self, parents: Vec<&'a Agent<'a, T>>) -> &'a Document<'a, T> {
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

        for hashes in doc.members.values() {
            for hash in hashes {
                let delegation = doc.state.delegations.get(hash).unwrap();
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
                    for (mem, proof_hashes) in doc.members.iter() {
                        for proof_hash in proof_hashes.iter() {
                            let proof = doc.state.delegations.get(proof_hash).unwrap();
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
