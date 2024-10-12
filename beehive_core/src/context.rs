//! The primary API for the library.

use crate::{
    access::Access,
    crypto::signed::Signed,
    principal::{
        active::Active,
        agent::Agent,
        document::{DocStore, Document},
        group::{operation::revocation::Revocation, store::GroupStore, Group},
        identifier::Identifier,
        individual::Individual,
        membered::{Membered, MemberedId},
        traits::Verifiable,
    },
};
use nonempty::NonEmpty;
use std::collections::{BTreeMap, BTreeSet};

/// The main object for a user agent & top-level owned stores.
#[derive(Clone)]
pub struct Context<'a, T: std::hash::Hash + Clone> {
    /// The [`Active`] user agent.
    pub active: Active,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeSet<Individual>,

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<'a, T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocStore<'a, T>,
}

impl<'a, T: std::hash::Hash + Clone> Context<'a, T> {
    pub fn generate() -> Self {
        Self {
            active: Active::generate(),
            individuals: Default::default(),
            groups: GroupStore::new(),
            docs: DocStore::new(),
        }
    }

    pub fn generate_group(&mut self, coparents: Vec<&Agent<'a, T>>) -> &Group<'a, T> {
        self.groups.generate_group(NonEmpty {
            head: &self.active.clone().into(),
            tail: coparents.clone(),
        })
    }

    pub fn generate_doc(&mut self, coparents: Vec<&Agent<'a, T>>) -> &Document<'a, T> {
        let mut parents = coparents.clone();
        let self_agent = self.active.clone().into();
        parents.push(&self_agent);
        self.docs.generate_document(parents)
    }

    pub fn sign<U>(&self, data: U) -> Signed<U>
    where
        U: Clone + std::hash::Hash,
        Vec<u8>: From<U>,
    {
        self.active.sign(data)
    }

    // pub fn encrypt(
    //     &self,
    //     data: Vec<u8>,
    //     public_keys: BTreeSet<&ShareKey>,
    // ) -> (
    //     Encrypted<Vec<u8>>,
    //     Encrypted<chacha20poly1305::XChaChaPoly1305>,
    // ) {
    //     let symmetric_key: [u8; 32] = rand::thread_rng();
    //     dcgka_2m_broadcast(key, data, public_keys)
    // }

    pub fn revoke(&mut self, to_revoke: &Agent<'a, T>, from: &mut Membered<'a, T>)
    where
        T: Ord + Clone,
    {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        //
        match from {
            Membered::Group(og_group) => {
                // let mut owned_group = group.clone();
                let group = self.groups.get_mut(&og_group.state.id).expect("FIXME");

                group.members.remove(to_revoke);

                // FIXME
                if let Some(revoke) = group.state.delegations_for(to_revoke).pop() {
                    let proof = group
                        .state
                        .delegations_for(&self.active.clone().into())
                        .pop()
                        .expect("FIXME");

                    group
                        .state
                        .revocations
                        .insert(self.sign(Revocation { revoke, proof }));
                }
            }
            Membered::Document(og_doc) => {
                // let mut doc = d.clone();
                let doc = self.docs.docs.get_mut(&og_doc.state.id).expect("FIXME");
                let revoke = doc.state.delegations_for(to_revoke).pop().expect("FIXME");
                let proof = doc
                    .state
                    .delegations_for(&self.active.clone().into())
                    .pop()
                    .expect("FIXME");

                doc.members.remove(to_revoke);
                doc.state.revocations.insert(Signed::sign(
                    Revocation { revoke, proof },
                    &self.active.signer,
                ));
            }
        }
    }

    pub fn transitive_docs(&self) -> BTreeMap<&'a Document<'a, T>, Access>
    where
        T: Ord,
    {
        let mut explore: Vec<(Membered<'a, T>, Access)> = vec![];
        let mut caps: BTreeMap<&Document<'a, T>, Access> = BTreeMap::new();
        let mut seen: BTreeSet<Identifier> = BTreeSet::new();

        for doc in self.docs.docs.values() {
            seen.insert(doc.state.id);

            if let Some((access, _proof)) = doc.members.get(&self.active.clone().into()) {
                caps.insert(doc, access.clone());
            }
        }

        for group in self.groups.values() {
            seen.insert(group.state.id);

            if let Some((access, _proof)) = group.get(&self.active.into()) {
                explore.push((group.into(), access.clone()));
            }
        }

        while !explore.is_empty() {
            if let Some((group, _access)) = explore.pop() {
                for doc in self.docs.docs.values() {
                    if seen.contains(&doc.state.id) {
                        continue;
                    }

                    if let Some((access, _proof)) = doc.members.get(&self.active.clone().into()) {
                        caps.insert(doc, access.clone());
                    }
                }

                for (id, focus_group) in self.groups.iter() {
                    if seen.contains(&focus_group.state.id) {
                        continue;
                    }

                    if group.member_id() == MemberedId::GroupId(*id) {
                        continue;
                    }

                    if let Some((access, _proof)) = focus_group.get(&self.active.clone().into()) {
                        explore.push((focus_group.into(), access.clone()));
                    }
                }
            }
        }

        caps
    }

    // FIXME
    pub fn transitive_members(&self, doc: &Document<'a, T>) -> BTreeMap<Agent<'a, T>, Access>
    where
        T: Ord,
    {
        struct GroupAccess<'b, U: std::hash::Hash + Clone> {
            agent: Agent<'b, U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<'a, T>> = vec![];

        for (k, (v, _)) in doc.members.iter() {
            explore.push(GroupAccess {
                agent: k.clone(),
                agent_access: *v,
                parent_access: Access::Admin,
            });
        }

        let mut merged_store = self.groups.iter().fold(BTreeMap::new(), |mut acc, (k, v)| {
            acc.insert(k.clone(), &Membered::Group(v));
            acc
        });

        for (k, v) in self.docs.docs.iter() {
            merged_store.insert(k.clone(), &Membered::Document(v));
        }

        let mut caps: BTreeMap<Agent<'a, T>, Access> = BTreeMap::new();

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
                        if let Some(membered) = merged_store.get(&member.verifying_key().into()) {
                            for (mem, (pow, _proof)) in membered.members().clone() {
                                let current_path_access = access.min(pow).min(parent_access);

                                let best_access =
                                    if let Some(prev_found_path_access) = caps.get(&mem) {
                                        (*prev_found_path_access).max(current_path_access)
                                    } else {
                                        current_path_access
                                    };

                                explore.push(GroupAccess {
                                    agent: mem.clone(),
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

impl<'a, T: std::hash::Hash + Clone> Verifiable for Context<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Context<'a, T>> for Agent<'a, T> {
    fn from(context: Context<'a, T>) -> Self {
        context.active.into()
    }
}
