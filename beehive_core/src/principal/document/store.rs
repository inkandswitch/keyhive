use super::{id::DocumentId, Document};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::{
        agent::{id::AgentId, Agent},
        group::operation::{
            delegation::{Delegation, DelegationError},
            revocation::Revocation,
        },
    },
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use nonempty::NonEmpty;
use std::{
    cell::{RefCell, RefMut},
    collections::BTreeMap,
    rc::Rc,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DocumentStore<T: ContentRef> {
    pub docs: BTreeMap<DocumentId, Rc<RefCell<Document<T>>>>,
}

impl<T: ContentRef> DocumentStore<T> {
    pub fn new() -> Self {
        Self {
            docs: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, doc: Rc<RefCell<Document<T>>>) {
        self.docs.insert(doc.clone().borrow().doc_id(), doc);
    }

    pub fn get(&self, id: &DocumentId) -> Option<Rc<RefCell<Document<T>>>> {
        self.docs.get(id).cloned()
    }

    pub fn get_mut(&self, id: &DocumentId) -> Option<RefMut<Document<T>>> {
        self.docs.get(id).map(|d| d.borrow_mut())
    }

    pub fn contains_key(&self, id: &DocumentId) -> bool {
        self.docs.contains_key(id)
    }

    pub fn generate_document<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        parents: NonEmpty<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
        csprng: &mut R,
    ) -> Result<Rc<RefCell<Document<T>>>, DelegationError> {
        let new_doc = Document::generate(parents, delegations, revocations, csprng)?;
        let rc_ref = Rc::new(RefCell::new(new_doc));
        self.insert(rc_ref.dupe());
        Ok(rc_ref)
    }

    pub fn transitive_members(&self, doc: &Document<T>) -> BTreeMap<AgentId, (Agent<T>, Access)> {
        struct GroupAccess<U: ContentRef> {
            agent: Agent<U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<T>> = vec![];

        for member in doc.members().keys() {
            let dlg = doc
                .group
                .get_capability(member)
                .expect("members have capabilities by defintion");

            explore.push(GroupAccess {
                agent: dlg.payload().delegate.clone(),
                agent_access: dlg.payload().can,
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<AgentId, (Agent<T>, Access)> = BTreeMap::new();

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
                    for (mem, proofs) in group.borrow().members().iter() {
                        for proof in proofs.iter() {
                            let current_path_access =
                                access.min(proof.payload().can).min(parent_access);

                            let best_access =
                                if let Some((_, prev_found_path_access)) = caps.get(mem) {
                                    (*prev_found_path_access).max(current_path_access)
                                } else {
                                    current_path_access
                                };

                            explore.push(GroupAccess {
                                agent: proof.payload().delegate.clone(),
                                agent_access: best_access,
                                parent_access,
                            });
                        }
                    }
                }
                Agent::Document(doc) => {
                    for (mem, proof_hashes) in doc.borrow().group.members.iter() {
                        for proof in proof_hashes.iter() {
                            let current_path_access =
                                access.min(proof.payload().can).min(parent_access);

                            let best_access =
                                if let Some((_, prev_found_path_access)) = caps.get(mem) {
                                    (*prev_found_path_access).max(current_path_access)
                                } else {
                                    current_path_access
                                };

                            explore.push(GroupAccess {
                                agent: proof.payload().delegate.clone(),
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
