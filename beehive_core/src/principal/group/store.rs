use super::id::GroupId;
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::{Signed, SigningError},
    principal::{
        agent::{id::AgentId, Agent},
        group::{
            operation::{delegation::Delegation, revocation::Revocation},
            Group,
        },
        membered::Membered,
    },
    util::content_addressed_map::CaMap,
};
use dupe::{Dupe, IterDupedExt, OptionDupedExt};
use nonempty::NonEmpty;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupStore<T: ContentRef>(BTreeMap<GroupId, Rc<RefCell<Group<T>>>>);

impl<T: ContentRef> GroupStore<T> {
    pub fn new() -> Self {
        GroupStore(BTreeMap::new())
    }

    pub fn insert(&mut self, group: Rc<RefCell<Group<T>>>) {
        let id = group.borrow().group_id();
        self.0.insert(id, group);
    }

    pub fn generate_group<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        parents: NonEmpty<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
        csprng: &mut R,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        let new_group: Group<T> = Group::generate(parents, delegations, revocations, csprng)?;
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

    // FIXME uses self anywhere? move to group/membered directly?
    pub fn transitive_members(&self, group: &Group<T>) -> HashMap<AgentId, (Agent<T>, Access)> {
        struct GroupAccess<U: ContentRef> {
            agent: Agent<U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<T>> = vec![];
        // FIXME do these do the same thing?
        let mut seen: HashSet<[u8; 64]> = HashSet::new();
        let mut visited: HashSet<(AgentId, Access)> =
            HashSet::from_iter([((group.agent_id(), Access::Admin))]);

        for member in group.members.keys() {
            let dlg = group
                .get_capability(member)
                .expect("members have capabilities by defintion");

            explore.push(GroupAccess {
                agent: dlg.payload().delegate.clone(),
                agent_access: dlg.payload().can,
                parent_access: Access::Admin,
            });
        }

        let mut caps: HashMap<AgentId, (Agent<T>, Access)> = HashMap::new();

        while let Some(GroupAccess {
            agent: member,
            agent_access: access,
            parent_access,
        }) = explore.pop()
        {
            let agent_id = member.agent_id();

            if agent_id == group.agent_id() {
                continue;
            }

            if visited.contains(&(agent_id, parent_access)) {
                continue;
            } else {
                visited.insert((agent_id, parent_access));
            }

            let current_path_access = access.min(parent_access);

            let best_access = if let Some((_, prev_found_path_access)) = caps.get(&agent_id) {
                (*prev_found_path_access).max(current_path_access)
            } else {
                current_path_access
            };

            caps.insert(agent_id, (member.dupe(), best_access));

            match member.dupe() {
                Agent::Group(inner_group) => Some(inner_group.into()),
                Agent::Document(doc) => Some(doc.into()),
                _ => None,
            }
            .map(|membered: Membered<T>| {
                // Recurse
                for (mem_id, dlgs) in membered.members().iter() {
                    if mem_id == &group.agent_id() {
                        continue;
                    }

                    for dlg in dlgs.iter() {
                        let bytes: [u8; 64] = dlg.signature.to_bytes();
                        if seen.contains(&bytes) {
                            continue;
                        }
                        seen.insert(bytes);

                        explore.push(GroupAccess {
                            agent: dlg.payload().delegate.clone(),
                            agent_access: dlg.payload().can.min(current_path_access),
                            parent_access,
                        });
                    }
                }
            });
        }

        caps
    }
}
