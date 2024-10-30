use super::id::GroupId;
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::SigningError,
    principal::{
        agent::{Agent, AgentId},
        group::Group,
        verifiable::Verifiable,
    },
};
use base64::prelude::*;
use dupe::{Dupe, IterDupedExt, OptionDupedExt};
use nonempty::NonEmpty;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupStore<T: ContentRef>(BTreeMap<GroupId, Rc<RefCell<Group<T>>>>);

impl<T: ContentRef> GroupStore<T> {
    pub fn new() -> Self {
        GroupStore(BTreeMap::new())
    }

    pub fn pretty_print_direct_pks(&self) -> Vec<String> {
        self.0
            .values()
            .map(|pk| BASE64_STANDARD.encode(pk.borrow().verifying_key()))
            .collect()
    }

    pub fn insert(&mut self, group: Rc<RefCell<Group<T>>>) {
        let id = group.borrow().group_id();
        self.0.insert(id, group);
    }

    pub fn generate_group(
        &mut self,
        parents: NonEmpty<Agent<T>>,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        let new_group: Group<T> = Group::generate(parents)?;
        let rc = Rc::new(RefCell::new(new_group));
        self.insert(rc.dupe());
        Ok(rc)
    }

    pub fn get(&self, id: &GroupId) -> Option<Rc<RefCell<Group<T>>>> {
        self.0.get(id).duped()
    }

    pub fn values(&self) -> Vec<Rc<RefCell<Group<T>>>> {
        self.0.values().duped().collect()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<GroupId, Rc<RefCell<Group<T>>>> {
        self.0.iter()
    }

    pub fn transitive_members(&self, group: &Group<T>) -> BTreeMap<AgentId, (Agent<T>, Access)> {
        struct GroupAccess<U: ContentRef> {
            agent: Agent<U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<T>> = vec![];

        for member in group.members.keys() {
            let dlg = group.get_capability(member).unwrap();

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
                        for proof in proof_hashes.iter() {
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
