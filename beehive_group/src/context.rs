use crate::access::Access;
use crate::crypto::encrypted::Encrypted;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::operation::revocation::Revocation;
use crate::operation::Operation;
use crate::principal::active::Active;
use crate::principal::agent::Agent;
use crate::principal::document::DocStore;
use crate::principal::document::Document;
use crate::principal::document::DocumentState;
use crate::principal::group::store::GroupStore;
use crate::principal::group::Group;
use crate::principal::identifier::Identifier;
use crate::principal::individual::Individual;
use crate::principal::membered::{Membered, MemberedId};
use crate::principal::traits::Verifiable;
use crate::scratch::dcgka_2m_broadcast;
use chacha20poly1305::AeadInPlace;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Context {
    pub active: Active,
    pub individuals: BTreeSet<Individual>,
    pub groups: GroupStore,
    pub docs: DocStore,
}

impl From<Context> for Agent {
    fn from(context: Context) -> Self {
        context.active.into()
    }
}

impl Context {
    pub fn new() -> Self {
        Self {
            active: Active::generate(),
            individuals: Default::default(),
            groups: Default::default(),
            docs: Default::default(),
        }
    }

    pub fn id(&self) -> Identifier {
        self.active.id()
    }

    pub fn create_group(&mut self, coparents: Vec<&Agent>) -> &Group {
        let mut parents = coparents.clone();
        let self_agent = self.active.clone().into();
        parents.push(&self_agent);
        self.groups.create_group(parents)
    }

    pub fn create_doc(&mut self, coparents: Vec<&Agent>) -> &Document {
        let mut parents = coparents.clone();
        let self_agent = self.active.clone().into();
        parents.push(&self_agent);
        self.docs.create_document(parents)
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

                group.delegates.remove(to_revoke);

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

                doc.delegates.remove(to_revoke);
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

            if let Some((access, _proof)) = doc.delegates.get(&self.active.clone().into()) {
                caps.insert(doc.clone(), access.clone());
            }
        }

        for group in self.groups.groups.values() {
            seen.insert(group.state.id);

            if let Some((access, _proof)) = group.delegates.get(&self.active.clone().into()) {
                explore.push((group.clone().into(), access.clone()));
            }
        }

        while !explore.is_empty() {
            if let Some((group, _access)) = explore.pop() {
                for doc in self.docs.docs.values() {
                    if seen.contains(&doc.state.id) {
                        continue;
                    }

                    if let Some((access, _proof)) = doc.delegates.get(&self.active.clone().into()) {
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
                        focus_group.delegates.get(&self.active.clone().into())
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

        for (k, (v, _)) in doc.delegates.iter() {
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

pub fn demo() -> Context {
    // ┌──────────┐
    // │   Hive   │▒
    // │ Context  │▒
    // │  ("Me")  │▒
    // └──────────┘▒
    //  ▒▒▒▒▒▒▒▒▒▒▒▒
    let mut hive = Context::new();

    // Some remote users
    //          ┏━━━━━━━━━━┓
    //          ┃  Alice   ┃
    //  ┌───────┃          ┃─ ─ ─ ─ ─ ─ ─ ┐
    //  │       ┗━━━━━━━━━━┛              │
    //  │             │                   ▼
    //  │             │              ┌──────────┐
    //  │             │              │   Hive   │▒
    //  ▼             ▼              │ Context  │▒
    // ┌──────────┐  ┌──────────┐    │  ("Me")  │▒
    // │ Alice's  │  │ Alice's  │    └──────────┘▒
    // │  Phone   │  │  Laptop  │     ▒▒▒▒▒▒▒▒▒▒▒▒
    // └──────────┘  └──────────┘

    println!("Setting up Alice's device group");
    let alice_phone = Individual::generate().into();
    println!("...Alice's phone {}", alice_phone);

    let alice_laptop = Individual::generate().into();
    println!("...Alice's laptop {}", alice_laptop);

    let alice_ref = hive.create_group(vec![&alice_phone, &alice_laptop]);
    let alice: Agent = alice_ref.clone().into();
    println!("...Attach to Alice device group");
    println!("");

    println!("Setting up Bob's device group");
    let bob_phone = Individual::generate().into();
    println!("...Bob's phone {}", bob_phone);

    let bob_tablet = Individual::generate().into();
    println!("...Bob's tablet {}", bob_tablet);

    let bob_ref = hive.create_group(vec![&bob_tablet, &bob_phone]);
    let bob = bob_ref.clone().into();
    println!("...Attach to Bob's device group");
    println!("");

    // Setup Teams
    //                 ┏━━━━━━━━━━┓
    //                 ┃  Ink &   ┃
    //       ┌─────────┃  Switch  ┃───────────┐
    //       ▼         ┗━━━━━━━━━━┛           ▼
    // ┏━━━━━━━━━━┓          │          ┏━━━━━━━━━━┓
    // ┃  Alice   ┃          │          ┃   Bob    ┃
    // ┃          ┃─ ─ ─ ─   │   ┌ ─ ─ ─┃          ┃
    // ┗━━━━━━━━━━┛       │  │          ┗━━━━━━━━━━┛
    //                       │   │
    //                    ▼  ▼   ▼
    //                 ┌──────────┐
    //                 │   Hive   │▒
    //                 │ Context  │▒
    //                 │  ("Me")  │▒
    //                 └──────────┘▒
    //                  ▒▒▒▒▒▒▒▒▒▒▒▒
    let inkandswitch_ref = hive.create_group(vec![&alice, &bob]);
    let inkandswitch: Agent = inkandswitch_ref.clone().into();
    println!("Setting up Ink & Switch group {}", inkandswitch);

    let beehive_team_ref = hive.create_group(vec![&inkandswitch.clone().into()]);
    let beehive_team: Agent = beehive_team_ref.clone().into();
    println!("Setting up Beehive Team group {}", beehive_team);

    // ╔══════════╗
    // ║   Team   ║
    // ║  Travel  ║
    // ║ Details  ║
    // ╚══════════╝
    //       │
    //       ▼
    // ┏━━━━━━━━━━┓
    // ┃  Ink &   ┃
    // ┃  Switch  ┃
    // ┗━━━━━━━━━━┛
    let team_travel_doc_ref = hive.create_doc(vec![&inkandswitch.clone().into()]);
    let team_travel_doc: Agent = team_travel_doc_ref.clone().into();
    println!("Setting up Team Travel doc {}", team_travel_doc.clone());

    let lab_note_doc_ref = hive.create_doc(vec![&beehive_team.clone().into(), &team_travel_doc]);
    let lnid = lab_note_doc_ref.clone();
    let lab_note_doc: Agent = lab_note_doc_ref.clone().into();
    println!("Setting up Lab Note doc {}", lab_note_doc);

    // let group_pks = hive.groups.pretty_print_direct_pks();
    // for pk in group_pks.iter() {
    //     println!("{}", pk);
    // }

    let all_mems = hive.transitive_members(&lnid);
    let lab_note_mems: Vec<&Agent> = all_mems.keys().collect();
    for mem in lab_note_mems.clone().into_iter() {
        println!("Member: {}", mem);
    }

    hive
}
