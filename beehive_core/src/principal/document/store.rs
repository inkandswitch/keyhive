use super::{id::DocumentId, Document};
use crate::{
    access::Access,
    content::reference::ContentRef,
    principal::agent::{Agent, AgentId},
};
use nonempty::NonEmpty;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DocumentStore<'a, T: ContentRef> {
    pub docs: BTreeMap<DocumentId, Document<'a, T>>,
}

impl<'a, T: ContentRef> DocumentStore<'a, T> {
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

    pub fn generate_document(&'a mut self, parents: NonEmpty<Agent<'a, T>>) -> DocumentId {
        let new_doc = Document::generate(parents);
        let new_doc_id: DocumentId = new_doc.doc_id();
        self.insert(new_doc);
        new_doc_id
    }

    pub fn transitive_members(
        &'a self,
        doc: &'a Document<'a, T>,
    ) -> BTreeMap<AgentId, (Agent<'a, T>, Access)> {
        struct GroupAccess<'a, U: ContentRef> {
            agent: Agent<'a, U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<'a, T>> = vec![];

        for hashes in doc.group.members.values() {
            for hash in hashes {
                let delegation = doc.group.state.delegations.get(hash).unwrap();
                explore.push(GroupAccess {
                    agent: delegation.payload().delegate.clone(),
                    agent_access: delegation.payload().can, // FIXME need to lookup
                    parent_access: Access::Admin,
                });
            }
        }

        let mut caps: BTreeMap<AgentId, (Agent<'a, T>, Access)> = BTreeMap::new();

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
                    for (mem, proofs) in group.get_member_refs().iter() {
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
                                agent: proof.payload().delegate.clone(),
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
