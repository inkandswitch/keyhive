//! The primary API for the library.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::{
        active::Active,
        agent::{Agent, AgentId},
        document::{DocStore, Document},
        group::{operation::revocation::Revocation, store::GroupStore, Group},
        identifier::Identifier,
        individual::Individual,
        membered::{Membered, MemberedId},
        verifiable::Verifiable,
    },
};
use nonempty::NonEmpty;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

/// The main object for a user agent & top-level owned stores.
#[derive(Clone)]
pub struct Context<'a, T: ContentRef> {
    /// The [`Active`] user agent.
    pub active: Active,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeMap<Identifier, Individual>, // FIXME ID

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<'a, T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocStore<'a, T>,
}

impl<'a, T: ContentRef> Context<'a, T> {
    pub fn generate() -> Self {
        Self {
            active: Active::generate(),
            individuals: Default::default(),
            groups: GroupStore::new(),
            docs: DocStore::new(),
        }
    }

    pub fn generate_group(&'a mut self, coparents: Vec<&'a Agent<'a, T>>) -> &Group<'a, T> {
        self.groups.generate_group(NonEmpty {
            head: self.active.into(),
            tail: coparents,
        })
    }

    pub fn generate_doc(&'a mut self, coparents: Vec<&'a Agent<'a, T>>) -> &Document<'a, T> {
        let mut parents = coparents;
        let self_agent = self.active.into();
        parents.push(&self_agent);
        self.docs.generate_document(parents)
    }

    pub fn id(&self) -> Identifier {
        self.active.id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.agent_id()
    }

    pub fn sign<U: Serialize>(&self, data: U) -> Signed<U> {
        self.active.sign(data)
    }

    // pub fn encrypt(
    //     &self,
    //     data: Vec<u8>,
    //     public_keys: HashSet<&ShareKey>,
    // ) -> (
    //     Encrypted<Vec<u8>>,
    //     Encrypted<chacha20poly1305::XChaChaPoly1305>,
    // ) {
    //     let symmetric_key: [u8; 32] = rand::thread_rng();
    //     dcgka_2m_broadcast(key, data, public_keys)
    // }

    pub fn revoke(
        &mut self,
        to_revoke: &Agent<T>,
        from: &mut Membered<T>,
        after_content: BTreeMap<&Document<T>, Vec<&T>>,
    ) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        //
        match from {
            Membered::Group(og_group) => {
                let group = self.groups.get_mut(&og_group.state.id).expect("FIXME");

                group.members.remove(&to_revoke.id());

                // FIXME
                if let Some(revoke) = group.state.delegations_for(to_revoke).pop() {
                    let proof = group
                        .state
                        .delegations_for(&self.active.into())
                        .pop()
                        .expect("FIXME");

                    group.state.revocations.insert(self.sign(Revocation {
                        revoke,
                        proof,
                        after_content,
                    }));
                }
            }
            Membered::Document(og_doc) => {
                // let mut doc = d.clone();
                let doc = self.docs.docs.get_mut(&og_doc.id()).expect("FIXME");
                let revoke = doc.state.delegations_for(to_revoke).pop().expect("FIXME");
                let proof = doc
                    .state
                    .delegations_for(self.active.as_agent())
                    .pop()
                    .expect("FIXME");

                doc.members.remove(&to_revoke.id().into());
                doc.state.revocations.insert(Box::new(Signed::sign(
                    Revocation {
                        revoke,
                        proof,
                        after_content,
                    },
                    &self.active.signer,
                )));
            }
        }
    }

    pub fn transitive_docs(&self) -> BTreeMap<&Document<T>, Access> {
        let mut explore: Vec<(Membered<T>, Access)> = vec![];
        let mut caps: BTreeMap<&Document<T>, Access> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        let agent_id = self.active.agent_id();

        for doc in self.docs.docs.values() {
            seen.insert(doc.agent_id());

            if let Some(proof) = doc.members.get(&agent_id) {
                caps.insert(doc, proof.payload.can);
            }
        }

        for group in self.groups.values() {
            seen.insert(group.agent_id());

            if let Some(proof) = group.get(&agent_id) {
                explore.push(((*group).into(), proof.payload.can));
            }
        }

        while !explore.is_empty() {
            if let Some((group, _access)) = explore.pop() {
                for doc in self.docs.docs.values() {
                    if seen.contains(&doc.agent_id()) {
                        continue;
                    }

                    if let Some(proof) = doc.members.get(&agent_id) {
                        // FIXME more than one Access? Highest access?
                        caps.insert(doc, proof.payload.can);
                    }
                }

                for (id, focus_group) in self.groups.iter() {
                    if seen.contains(&focus_group.agent_id()) {
                        continue;
                    }

                    if group.member_id() == MemberedId::GroupId(*id) {
                        continue;
                    }

                    if let Some(proof) = focus_group.get(&agent_id) {
                        explore.push((focus_group.into(), proof.payload.can));
                    }
                }
            }
        }

        caps
    }

    // FIXME
    pub fn transitive_members(&self, doc: &Document<T>) -> BTreeMap<&Agent<T>, Access> {
        struct GroupAccess<'a, U: ContentRef> {
            agent: &'a Agent<'a, U>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<'a, T>> = vec![];

        for (k, delegation) in doc.members.iter() {
            explore.push(GroupAccess {
                agent: *k,
                agent_access: delegation.payload.can,
                parent_access: Access::Admin, // FIXME?
            });
        }

        let mut merged_store = self.groups.iter().fold(BTreeMap::new(), |mut acc, (k, v)| {
            acc.insert(k.into(), (*v).into());
            acc
        });

        for (k, v) in self.docs.docs.iter() {
            merged_store.insert(k.into(), (*v).into());
        }

        let mut caps: BTreeMap<&Agent<'_, T>, Access> = BTreeMap::new();

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

                    caps.insert(&member, best_access);
                }
                _ => {
                    if let Some(membered) = merged_store.get(&member.verifying_key().into()) {
                        for (mem, proof) in membered.members() {
                            let current_path_access =
                                access.min(proof.payload.can).min(parent_access);

                            let best_access = if let Some(prev_found_path_access) = caps.get(&mem) {
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

        caps
    }
}

impl<'a, T: ContentRef> Verifiable for Context<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

impl<'a, T: ContentRef> From<Context<'a, T>> for Agent<'a, T> {
    fn from(context: Context<T>) -> Self {
        context.active.into()
    }
}
