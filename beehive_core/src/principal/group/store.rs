use super::id::GroupId;
use crate::{
    access::Access,
    content::reference::ContentRef,
    principal::{agent::Agent, group::Group, identifier::Identifier, verifiable::Verifiable},
};
use base64::prelude::*;
use nonempty::NonEmpty;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Serialize)]
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
        self.0.insert(group.id(), group);
    }

    pub fn generate_group(&mut self, parents: NonEmpty<&'a Agent<'a, T>>) -> &Group<'a, T> {
        let new_group: Group<'a, T> = Group::generate(parents);
        let new_group_id: GroupId = new_group.id();
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

    pub fn iter(&self) -> std::collections::btree_map::Iter<Identifier, Group<'a, T>> {
        self.0.iter()
    }

    // FIXME shoudl be more like this:
    // pub fn transative_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    // FIXME return path as well?
    pub fn transative_members(&self, group: &Group<'a, T>) -> BTreeMap<Identifier, Access> {
        struct GroupAccess {
            agent: AgentId,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, v) in group.members.iter() {
            explore.push(GroupAccess {
                agent: *k,
                agent_access: *v,
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<Identifier, Access> = BTreeMap::new();

        while let Some(GroupAccess {
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
                    if let Some(group) = self.0.get(&GroupId(member.into())) {
                        for (agent, proof) in group.members {
                            let current_path_access =
                                access.min(proof.payload.can).min(parent_access);

                            let best_access =
                                if let Some(prev_found_path_access) = caps.get(&agent.into()) {
                                    (*prev_found_path_access).max(current_path_access)
                                } else {
                                    current_path_access
                                };

                            explore.push(GroupAccess {
                                agent: agent.into(),
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
