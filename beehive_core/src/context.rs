use crate::access::Access;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::principal::active::Active;
use crate::principal::agent::Agent;
use crate::principal::document::DocStore;
use crate::principal::document::Document;
use crate::principal::group::operation::revocation::Revocation;
use crate::principal::group::store::GroupStore;
use crate::principal::group::Group;
use crate::principal::identifier::Identifier;
use crate::principal::individual::Individual;
use crate::principal::membered::{Membered, MemberedId};
use crate::principal::traits::Verifiable;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub struct Context {
    pub active: Active,
    pub individuals: BTreeSet<Individual>,
    pub groups: GroupStore,
    pub docs: DocStore,
    pub prekeys: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,
}

impl Context {
    pub fn generate() -> Self {
        Self {
            active: Active::generate(),
            individuals: Default::default(),
            groups: Default::default(),
            docs: Default::default(),
            prekeys: Default::default(),
        }
    }

    pub fn generate_group(&mut self, coparents: Vec<&Agent>) -> &Group {
        let mut parents = coparents.clone();
        let self_agent = self.active.clone().into();
        parents.push(&self_agent);
        self.groups.generate_group(parents)
    }

    pub fn generate_doc(&mut self, coparents: Vec<&Agent>) -> &Document {
        let mut parents = coparents.clone();
        let self_agent = self.active.clone().into();
        parents.push(&self_agent);
        self.docs.generate_document(parents)
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

    pub fn revoke(&mut self, to_revoke: &Agent, from: &mut Membered) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        //
        match from {
            Membered::Group(og_group) => {
                // let mut owned_group = group.clone();
                let group = self
                    .groups
                    .groups
                    .get_mut(&og_group.state.id)
                    .expect("FIXME");

                group.members.remove(to_revoke);

                // FIXME
                if let Some(revoke) = group.state.delegations_for(to_revoke).pop() {
                    let proof = group
                        .state
                        .delegations_for(&self.active.clone().into())
                        .pop()
                        .expect("FIXME");

                    group.state.ops.insert(Signed::sign(
                        Revocation {
                            subject: MemberedId::GroupId(group.state.id.into()),
                            revoker: self.active.clone().into(),
                            revoke,
                            proof,
                        }
                        .into(),
                        &self.active.signer,
                    ));
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
                doc.state.authority_ops.insert(Signed::sign(
                    Revocation {
                        subject: MemberedId::DocumentId(doc.state.id.into()),
                        revoker: self.active.clone().into(),
                        revoke,
                        proof,
                    }
                    .into(),
                    &self.active.signer,
                ));
            }
        }
    }

    pub fn transitive_docs(&self) -> BTreeMap<Document, Access> {
        let mut explore: Vec<(Membered, Access)> = vec![];
        let mut caps: BTreeMap<Document, Access> = BTreeMap::new();
        let mut seen: BTreeSet<Identifier> = BTreeSet::new();

        for doc in self.docs.docs.values() {
            seen.insert(doc.state.id);

            if let Some((access, _proof)) = doc.members.get(&self.active.clone().into()) {
                caps.insert(doc.clone(), access.clone());
            }
        }

        for group in self.groups.groups.values() {
            seen.insert(group.state.id);

            if let Some((access, _proof)) = group.members.get(&self.active.clone().into()) {
                explore.push((group.clone().into(), access.clone()));
            }
        }

        while !explore.is_empty() {
            if let Some((group, _access)) = explore.pop() {
                for doc in self.docs.docs.values() {
                    if seen.contains(&doc.state.id) {
                        continue;
                    }

                    if let Some((access, _proof)) = doc.members.get(&self.active.clone().into()) {
                        caps.insert(doc.clone(), access.clone());
                    }
                }

                for (id, focus_group) in self.groups.groups.iter() {
                    if seen.contains(&focus_group.state.id) {
                        continue;
                    }

                    if group.member_id() == MemberedId::GroupId(*id) {
                        continue;
                    }

                    if let Some((access, _proof)) =
                        focus_group.members.get(&self.active.clone().into())
                    {
                        explore.push((focus_group.clone().into(), access.clone()));
                    }
                }
            }
        }

        caps
    }

    // FIXME
    pub fn transitive_members(&self, doc: &Document) -> BTreeMap<Agent, Access> {
        struct GroupAccess {
            agent: Agent,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, (v, _)) in doc.members.iter() {
            explore.push(GroupAccess {
                agent: k.clone(),
                agent_access: *v,
                parent_access: Access::Admin,
            });
        }

        let mut merged_store =
            self.groups
                .groups
                .iter()
                .fold(BTreeMap::new(), |mut acc, (k, v)| {
                    acc.insert(k.clone(), Membered::Group(v.clone()));
                    acc
                });

        for (k, v) in self.docs.docs.iter() {
            merged_store.insert(k.clone(), Membered::Document(v.clone()));
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

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prekey_ids = self.prekeys.keys().collect::<Vec<&ShareKey>>();

        write!(
            f,
            "Context {{ active: {:?}, individuals: {:?}, groups: {:?}, docs: {:?}, prekeys: {:?} }}",
            self.active, self.individuals, self.groups, self.docs, prekey_ids
        )
    }
}

impl Verifiable for Context {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

impl From<Context> for Agent {
    fn from(context: Context) -> Self {
        context.active.into()
    }
}
