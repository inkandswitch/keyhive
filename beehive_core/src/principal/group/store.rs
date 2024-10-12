use crate::{
    access::Access,
    principal::{agent::Agent, group::Group, identifier::Identifier, traits::Verifiable},
};
use base64::prelude::*;
use nonempty::NonEmpty;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupStore {
    pub groups: BTreeMap<Identifier, Group>,
}

impl GroupStore {
    pub fn new() -> Self {
        GroupStore {
            groups: BTreeMap::new(),
        }
    }

    pub fn pretty_print_direct_pks(&self) -> Vec<String> {
        self.groups
            .values()
            .map(|pk| BASE64_STANDARD.encode(pk.verifying_key()))
            .collect()
    }

    pub fn insert(&mut self, group: Group) {
        self.groups.insert(group.id(), group);
    }

    pub fn generate_group(&mut self, parents: NonEmpty<&Agent>) -> &Group {
        let new_group: Group = Group::generate(parents);
        let new_group_id: Identifier = new_group.verifying_key().into(); // FIXME add helper method
        self.insert(new_group);
        self.get(&new_group_id).expect("FIXME")
    }

    pub fn get(&self, id: &Identifier) -> Option<&Group> {
        self.groups.get(id)
    }

    pub fn ids(&self) -> BTreeSet<&Identifier> {
        self.groups.keys().collect()
    }

    // FIXME shoudl be more like this:
    // pub fn transative_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    // FIXME return path as well?
    pub fn transative_members(&self, group: &Group) -> BTreeMap<Agent, Access> {
        struct GroupAccess {
            agent: Agent,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, (v, _)) in group.members.iter() {
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
                        if let Some(group) = self.groups.get(&member.verifying_key().into()) {
                            for (mem, (pow, _proof)) in group.members.clone() {
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

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_test() {
        todo!()
    }
}
