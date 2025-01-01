use super::{id::DocumentId, Document};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signer::ed_signer::EdSigner,
    principal::{
        agent::{Agent, AgentId},
        group::operation::delegation::DelegationError,
    },
};
use dupe::Dupe;
use nonempty::NonEmpty;
use std::{
    cell::{RefCell, RefMut},
    collections::BTreeMap,
    rc::Rc,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DocumentStore<T: ContentRef, S: EdSigner> {
    pub docs: BTreeMap<DocumentId, Rc<RefCell<Document<T, S>>>>,
}

impl<T: ContentRef, S: EdSigner> DocumentStore<T, S> {
    pub fn new() -> Self {
        Self {
            docs: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, doc: Rc<RefCell<Document<T, S>>>) {
        self.docs.insert(doc.clone().borrow().doc_id(), doc);
    }

    pub fn get(&self, id: &DocumentId) -> Option<Rc<RefCell<Document<T, S>>>> {
        self.docs.get(id).cloned()
    }

    pub fn get_mut(&self, id: &DocumentId) -> Option<RefMut<Document<T, S>>> {
        self.docs.get(id).map(|d| d.borrow_mut())
    }

    pub fn generate_document<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        parents: NonEmpty<Agent<T, S>>,
        csprng: &mut R,
    ) -> Result<DocumentId, DelegationError> {
        let new_doc = Document::generate(parents, csprng)?;
        let new_doc_id: DocumentId = new_doc.doc_id();
        self.insert(Rc::new(RefCell::new(new_doc)));
        Ok(new_doc_id)
    }

    pub fn transitive_members(
        &self,
        doc: &Document<T, S>,
    ) -> BTreeMap<AgentId, (Agent<T, S>, Access)> {
        struct GroupAccess<U: ContentRef, Z: EdSigner> {
            agent: Agent<U, Z>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<T, S>> = vec![];

        for dlgs in doc.group.members.values() {
            for delegation in dlgs {
                explore.push(GroupAccess {
                    agent: delegation.payload().delegate.dupe(),
                    agent_access: delegation.payload().can, // FIXME need to lookup
                    parent_access: Access::Admin,
                });
            }
        }

        let mut caps: BTreeMap<AgentId, (Agent<T, S>, Access)> = BTreeMap::new();

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
