//! Model a collection of agents with no associated content.

pub mod id;
pub mod operation;
pub mod state;
pub mod store;

use super::{
    agent::{Agent, AgentId},
    document::Document,
    identifier::Identifier,
    verifiable::Verifiable,
};
use crate::{
    access::Access, content::reference::ContentRef, crypto::signed::Signed,
    util::content_addressed_map::CaMap,
};
use id::GroupId;
use nonempty::NonEmpty;
use operation::{delegation::Delegation, revocation::Revocation, Operation};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};

/// A collection of agents with no associated content.
///
/// Groups are stateful agents. It is possible the delegate control over them,
/// and they can be delegated to. This produces transitives lines of authority
/// through the network of [`Agent`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group<'a, T: ContentRef> {
    /// The current view of members of a group.
    pub(crate) members: HashMap<AgentId, Vec<Rc<Signed<Delegation<'a, T>>>>>,

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: state::GroupState<'a, T>,
}

impl<'a, T: ContentRef> Group<'a, T> {
    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub fn generate(parents: NonEmpty<Agent<'a, T>>) -> Group<'a, T> {
        let group_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group_id = GroupId(group_signer.verifying_key().into());

        let mut delegations = CaMap::new();
        let mut delegation_heads = HashSet::new();
        let mut members = HashMap::new();

        for parent in parents.iter() {
            let dlg = Signed::sign(
                Delegation {
                    delegate: *parent,
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &group_signer,
            );

            let rc = Rc::new(dlg);
            delegations.insert(rc.clone());
            delegation_heads.insert(rc.clone());
            members.insert((*parent).agent_id(), vec![rc]);
        }

        Group {
            members,
            state: state::GroupState {
                id: group_id,

                delegation_heads,
                delegations,
                delegation_quarantine: CaMap::new(),

                revocation_heads: HashSet::new(),
                revocations: CaMap::new(),
                revocation_quarantine: CaMap::new(),
            },
        }
    }

    pub fn id(&self) -> Identifier {
        self.group_id().into()
    }

    pub fn group_id(&self) -> GroupId {
        self.state.group_id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.group_id().into()
    }

    pub fn as_agent(&'a self) -> Agent<'a, T> {
        self.into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<'a, T>>>>> {
        &self.members
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<'a, T>>> {
        &self.state.delegations
    }

    pub fn get_capability(&'a self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<'a, T>>>> {
        self.members.get(member_id).and_then(|delegations| {
            delegations
                .iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })
    }

    // FIXME rename
    pub fn add_member(&'a mut self, signed_delegation: Signed<Delegation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized

        let id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);
        self.state.delegations.insert(rc.clone());

        match self.members.get_mut(&id) {
            Some(caps) => {
                caps.push(rc);
            }
            None => {
                self.members.insert(id, vec![rc]);
            }
        }
    }

    pub fn revoke_member(
        &'a mut self,
        member_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&'a Document<'a, T>],
    ) {
        let revocations = &mut self.state.revocations;

        if let Some(revoke_dlgs) = self.members.remove(member_id) {
            for dlg in revoke_dlgs.iter() {
                let revocation = Signed::sign(
                    Revocation {
                        revoke: dlg.clone(),
                        proof: None, // FIXME
                        after_content: relevant_docs
                            .iter()
                            .map(|d| {
                                (
                                    d.doc_id(),
                                    (*d, d.content_heads.iter().map(|c| (*c).clone()).collect()),
                                )
                            })
                            .collect(),
                    },
                    &signing_key,
                );

                revocations.insert(Rc::new(revocation));
            }
        }

        // FIXME check that you can actually do this with tiebreaking, seniroity etc etc
    }

    pub fn materialize(&'a mut self) {
        for (_, op) in
            Operation::topsort(&self.state.delegation_heads, &self.state.revocation_heads)
                .expect("FIXME")
                .iter()
        {
            match op {
                Operation::Delegation(d) => {
                    if let Some(mut_dlgs) = self.members.get_mut(&d.payload().delegate.agent_id()) {
                        mut_dlgs.push(d.clone());
                    } else {
                        self.members
                            .insert(d.payload().delegate.agent_id(), vec![d.clone()]);
                    }
                }
                Operation::Revocation(r) => {
                    if let Some(mut_dlgs) = self
                        .members
                        .get_mut(&r.payload().revoke.payload().delegate.agent_id())
                    {
                        // FIXME maintain this as a CaMap for easier removals, too
                        mut_dlgs.retain(|d| *d != r.payload().revoke);
                    }
                }
            }
        }
    }

    pub fn revoke(&'a mut self, signed_revocation: Signed<Revocation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.members.remove(
            &signed_revocation
                .payload()
                .revoke
                .payload()
                .delegate
                .agent_id(),
        );

        self.state.add_revocation(signed_revocation);
    }

    // pub fn add_member(&mut self, delegation: Signed<Delegation>) {
    //     FIXME check subject, signature, find dependencies or quarantine
    //     ...look at the quarantine and see if any of them depend on this one
    //     ...etc etc
    //     self.state.delegations.insert(delegation.into());
    //     todo!() // rebuild, later do IVM
    // }

    // pub fn revoke(&mut self, revocation: Signed<Revocation>) {
    //     self.state.revocations.insert(revocation.into());
    //     todo!() // rebuild, later do IVM
    // }
}

impl<'a, T: ContentRef> Verifiable for Group<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.state.verifying_key()
    }
}

impl<'a, T: ContentRef> std::hash::Hash for Group<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for m in self.members.iter() {
            m.hash(state);
        }
        self.state.hash(state);
    }
}

impl<'a, T: ContentRef> Serialize for Group<'a, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let members = self
            .members
            .iter()
            .map(|(k, v)| (k, v.len()))
            .collect::<HashMap<_, _>>();

        let mut state = serializer.serialize_struct("Group", 2)?;
        state.serialize_field("members", &members)?;
        state.serialize_field("state", &self.state)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::{operation::delegation::Delegation, store::GroupStore};
    use crate::principal::{active::Active, individual::Individual};
    use nonempty::nonempty;

    fn setup_user() -> Individual {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into()
    }

    fn setup_groups<'a, T: ContentRef>(
        store: &'a mut Box<GroupStore<'a, T>>,
        alice: &'a Individual,
        bob: &'a Individual,
    ) -> [GroupId; 4] {
        /*              ┌───────────┐        ┌───────────┐
                        │           │        │           │
        ╔══════════════▶│   Alice   │        │    Bob    │
        ║               │           │        │           │
        ║               └─────▲─────┘        └───────────┘
        ║                     │                    ▲
        ║                     │                    ║
        ║               ┌───────────┐              ║
        ║               │           │              ║
        ║        ┌─────▶│  Group 0  │◀─────┐       ║
        ║        │      │           │      │       ║
        ║        │      └───────────┘      │       ║
        ║  ┌───────────┐             ┌───────────┐ ║
        ║  │           │             │           │ ║
        ╚══│  Group 1  │             │  Group 2  │═╝
           │           │             │           │
           └─────▲─────┘             └─────▲─────┘
                 │      ┌───────────┐      │
                 │      │           │      │
                 └──────│  Group 3  │──────┘
                        │           │
                        └───────────┘ */

        let alice_agent = alice.into();
        let bob_agent = bob.into();

        let g0 = store.generate_group(nonempty![alice_agent]);
        let g0_ref = store.get(&g0).unwrap();
        let g1 = store.generate_group(nonempty![alice_agent, g0_ref.as_agent()]);
        let g2 = store.generate_group(nonempty![bob_agent]);
        let g3 = store.generate_group(nonempty![bob_agent]);

        [g0, g1, g2, g3]
    }

    fn setup_store<'a, T: ContentRef>(gs: [&'a mut Group<'a, T>; 4]) -> [&'a mut Group<'a, T>; 4] {
        let [g0, g1, g2, g3] = gs;
        g1.add_member(todo!());
        g2.add_member(todo!());
        g3.add_member(todo!());
    }

    fn setup_cyclic_store<'a, T: ContentRef>(
        alice: &'a Individual,
        bob: &'a Individual,
    ) -> (GroupStore<'a, T>, [Group<'a, T>; 10]) {
        let alice_agent: Agent<'a, T> = alice.into();
        let bob_agent: Agent<'a, T> = bob.into();

        let group0 = Group::generate(nonempty![alice_agent]);

        let group1 = Group::generate(nonempty![bob_agent]);
        let group1_agent = group1.as_agent();

        let group2 = Group::generate(nonempty![group1_agent]);
        let group2_agent = group2.as_agent();

        let group3 = Group::generate(nonempty![group2_agent, group2_agent]);
        let group3_agent = group3.as_agent();

        let group4 = Group::generate(nonempty![group3_agent, group2_agent]);
        let group4_agent = group4.as_agent();

        let group5 = Group::generate(nonempty![group4_agent, group2_agent]);
        let group5_agent = group5.as_agent();

        let group6 = Group::generate(nonempty![group5_agent, group2_agent]);
        let group6_agent = group6.as_agent();

        let group7 = Group::generate(nonempty![group6_agent, group2_agent]);
        let group7_agent = group7.as_agent();

        let group8 = Group::generate(nonempty![group7_agent, group2_agent]);
        let group8_agent = group8.as_agent();

        let mut group9 = Group::generate(nonempty![group8_agent, alice_agent]);

        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Active::generate(signer);

        group9.add_member(Signed::sign(
            Delegation {
                delegate: alice.into(),
                can: Access::Admin,
                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            },
            &active.signer,
        ));

        let mut gs = GroupStore::new();

        gs.insert(group0.clone());
        gs.insert(group1.clone());
        gs.insert(group2.clone());
        gs.insert(group3.clone());
        gs.insert(group4.clone());
        gs.insert(group5.clone());
        gs.insert(group6.clone());
        gs.insert(group7.clone());
        gs.insert(group8.clone());
        gs.insert(group9.clone());

        (
            gs,
            [
                group0, group1, group2, group3, group4, group5, group6, group7, group8, group9,
            ],
        )
    }

    #[test]
    fn test_transitive_self() {
        let alice = setup_user();
        let alice_agent: Agent<'_, String> = alice.clone().into();

        let bob = setup_user();

        let (gs, [g0, _g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g0_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transitive_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_one() {
        let alice = setup_user();
        let alice_agent: Agent<'_, String> = alice.clone().into();

        let bob = setup_user();

        let (gs, [_g0, g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g1_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transitive_members(&g1);

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_two() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, _g1, g2, _g3]) = setup_store(&alice, &bob);
        let g2_mems: BTreeMap<&Agent<'_, String>, Access> = gs.transitive_members(&g2);

        assert_eq!(
            g2_mems,
            BTreeMap::from_iter([
                (&alice.clone().into(), Access::Admin),
                (&bob.clone().into(), Access::Admin)
            ])
        );
    }

    #[test]
    fn test_transitive_tree() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, _g1, _g2, g3]) = setup_store(&alice, &bob);
        let g3_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g3);

        assert_eq!(
            g3_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (bob.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_cycles() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_, _, _, _, _, _, _, _, _, g9]) = setup_cyclic_store(&alice, &bob);
        let g9_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g9);

        assert_eq!(
            g9_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (bob.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_add_member() {
        let alice = setup_user();
        let bob = setup_user();
        let carol = setup_user();

        let alice_agent: Agent<'_, _> = alice.into();
        let carol_agent: Agent<'_, _> = carol.into();

        let (mut gs, [mut g0, _, _, _]) = setup_store(&alice, &bob);

        let active = Active::generate();

        g0.add_member(Signed::sign(
            Delegation {
                delegate: &carol_agent,
                can: Access::Admin,
                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &active.signer,
        ));

        gs.insert(g0.clone().into());

        let g0_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transitive_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin), (&carol_agent, Access::Admin)])
        );
    }
}
