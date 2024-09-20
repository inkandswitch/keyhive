use crate::access::Access;
use crate::crypto::{encrypted::Encrypted, hash::Hash, share_key::ShareKey, signed::Signed};
use crate::principal::agent::Agent;
use crate::principal::group::Group;
use crate::principal::individual::Individual;
use crate::principal::membered::Membered;
use crate::principal::traits::Verifiable;
use chacha20poly1305::AeadInPlace;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupStore {
    pub groups: BTreeMap<Individual, Membered>,
}

impl GroupStore {
    pub fn new() -> Self {
        GroupStore {
            groups: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, membered: Membered) {
        self.groups
            .insert(membered.verifying_key().clone().into(), membered);
    }

    pub fn get(&self, id: &Individual) -> Option<&Membered> {
        self.groups.get(id)
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

        for (k, (v, _)) in group.delegates.iter() {
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
                            for (mem, (pow, _proof)) in group.members() {
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
    use super::*;

    #[test]
    fn test_test() {
        assert_eq!(1, 1);
    }
}
