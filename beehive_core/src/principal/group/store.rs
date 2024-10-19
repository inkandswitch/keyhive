use super::id::GroupId;
use crate::{
    access::Access,
    content::reference::ContentRef,
    principal::{
        agent::{Agent, AgentId},
        group::Group,
        verifiable::Verifiable,
    },
};
use base64::prelude::*;
use nonempty::NonEmpty;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, PartialEq, Hash, Eq, Serialize)]
pub struct GroupStore<'a, T: ContentRef>(pub BTreeMap<GroupId, Group<'a, T>>);

impl<'a, T: ContentRef> GroupStore<'a, T> {
    pub fn new() -> Self {
        GroupStore(BTreeMap::new())
    }

    pub fn pretty_print_direct_pks(&self) -> Vec<String> {
        self.0
            .values()
            .map(|pk| BASE64_STANDARD.encode(pk.verifying_key()))
            .collect()
    }

    pub fn insert(&mut self, group: Group<'a, T>) {
        self.0.insert(group.group_id(), group);
    }

    pub fn generate_group(&mut self, parents: NonEmpty<&'a Agent<'a, T>>) -> &Group<'a, T> {
        let new_group: Group<'a, T> = Group::generate(parents);
        let new_group_id: GroupId = new_group.group_id();
        self.insert(new_group);
        self.get(&new_group_id).expect(
            "Group should be inserted in store because it was just placed there a moment ago",
        )
    }

    pub fn get(&self, id: &GroupId) -> Option<&Group<'a, T>> {
        self.0.get(id)
    }

    pub fn get_mut(&mut self, id: &GroupId) -> Option<&mut Group<'a, T>> {
        self.0.get_mut(id)
    }

    pub fn values(&self) -> Vec<&Group<'a, T>> {
        self.0.values().collect()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<GroupId, Group<'a, T>> {
        self.0.iter()
    }

    pub fn transitive_members(
        &self,
        group: &'a Group<'a, T>,
    ) -> BTreeMap<AgentId, (&'a Agent<'a, T>, Access)> {
        struct GroupAccess<'b, U: ContentRef> {
            agent: &'b Agent<'b, U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<'a, T>> = vec![];

        for member in group.members.keys() {
            let dlg = group.get_capability(member).unwrap();

            explore.push(GroupAccess {
                agent: dlg.payload().delegate,
                agent_access: dlg.payload().can,
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<AgentId, (&'a Agent<'a, T>, Access)> = BTreeMap::new();

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

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_test() {
        todo!()
    }
}
