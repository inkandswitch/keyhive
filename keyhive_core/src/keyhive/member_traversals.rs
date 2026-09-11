//! Memoize member traversals.

use crate::{
    access::Access,
    listener::membership::MembershipListener,
    principal::{agent::Agent, identifier::Identifier, membered::Membered},
};
use dupe::{Dupe, IterDupedExt};
use future_form::FutureForm;
use keyhive_crypto::{content::reference::ContentRef, signer::async_signer::AsyncSigner};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub(super) type MemberAgents<F, S, T, L> = HashMap<Identifier, Agent<F, S, T, L>>;

fn member_agents_only<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    members: HashMap<Identifier, (Agent<F, S, T, L>, Access)>,
) -> MemberAgents<F, S, T, L> {
    members
        .into_iter()
        .map(|(id, (agent, _))| (id, agent))
        .collect()
}

/// How an agent is reached when building the traversal queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// Reached by a revocation. If it is a group, we may not have traversed its
    /// members yet.
    ByRevocation,
    /// Reached by a traversal. If it is a group, we do not need to transitively
    /// traverse its members again.
    ByTraversal,
}

/// The membership lookups performed so far, keyed by the agent they were about.
pub(super) struct MemberTraversals<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
> {
    members: HashMap<Identifier, Arc<MemberAgents<F, S, T, L>>>,
    revocations: HashMap<Identifier, Arc<MemberAgents<F, S, T, L>>>,
    delegated: HashMap<Identifier, Arc<MemberAgents<F, S, T, L>>>,
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    MemberTraversals<F, S, T, L>
{
    pub(super) fn new() -> Self {
        MemberTraversals {
            members: HashMap::new(),
            revocations: HashMap::new(),
            delegated: HashMap::new(),
        }
    }

    /// The members no longer reachable through `membered`:
    /// everyone `membered` has revoked, everyone revoked by a group or document in
    /// `transitive_members`, and everything transitively inside a revoked group.
    pub(super) async fn no_longer_reachable(
        &mut self,
        membered: &Membered<F, S, T, L>,
        transitive_members: &HashMap<Identifier, (Agent<F, S, T, L>, Access)>,
    ) -> MemberAgents<F, S, T, L> {
        let mut revoked = self
            .no_longer_members_of(membered, transitive_members)
            .await;
        for (member, _) in transitive_members.values() {
            if let Some(member) = member.as_membered() {
                revoked.extend(self.no_longer_members_of(&member, transitive_members).await);
            }
        }

        // Traverse the revoked groups. `seen` contains what is already accounted
        // for so a member found inside a revoked group that is still reachable
        // another way is not added here.
        let mut seen: HashSet<Identifier> = revoked.keys().copied().collect();
        seen.extend(transitive_members.keys());
        let mut queue: Vec<(Agent<F, S, T, L>, Reached)> = revoked
            .values()
            .map(|agent| (agent.dupe(), Reached::ByRevocation))
            .collect();
        while let Some((member, reached)) = queue.pop() {
            let Some(member) = member.as_membered() else {
                continue;
            };

            for (id, agent) in self.no_longer_members_of(&member, transitive_members).await {
                if seen.insert(id) {
                    queue.push((agent.dupe(), Reached::ByRevocation));
                    revoked.insert(id, agent);
                }
            }

            // A traversal would have already explored its transitive members.
            if reached == Reached::ByTraversal {
                continue;
            }
            for (id, agent) in self.members_of(&member).await.iter() {
                if seen.insert(*id) {
                    queue.push((agent.dupe(), Reached::ByTraversal));
                    revoked.insert(*id, agent.dupe());
                }
            }
        }

        revoked
    }

    async fn members_of(&mut self, of: &Membered<F, S, T, L>) -> Arc<MemberAgents<F, S, T, L>> {
        let id = of.agent_id().into();
        if let Some(traversed) = self.members.get(&id) {
            return traversed.dupe();
        }

        let members = Arc::new(member_agents_only(of.transitive_members().await));
        self.members.insert(id, members.dupe());
        members
    }

    /// Everyone `membered` no longer contains. This includes revoked members
    /// and members one of `membered`'s delegations references who are not in
    /// `transitive_members`.
    async fn no_longer_members_of(
        &mut self,
        membered: &Membered<F, S, T, L>,
        transitive_members: &HashMap<Identifier, (Agent<F, S, T, L>, Access)>,
    ) -> MemberAgents<F, S, T, L> {
        let mut departed = (*self.cached_revocations_for(membered).await).clone();
        for (id, agent) in self.delegated_by(membered).await.iter() {
            if !transitive_members.contains_key(id) {
                departed.insert(*id, agent.dupe());
            }
        }
        departed
    }

    /// Every agent referenced by a delegation in `membered`'s operations.
    async fn delegated_by(
        &mut self,
        membered: &Membered<F, S, T, L>,
    ) -> Arc<MemberAgents<F, S, T, L>> {
        let id = membered.agent_id().into();
        if let Some(named) = self.delegated.get(&id) {
            return named.dupe();
        }

        let mut named = MemberAgents::new();
        let mut seen: HashSet<[u8; 64]> = HashSet::new();
        let mut queue: Vec<_> = membered.delegation_heads().await.values().duped().collect();
        while let Some(dlg) = queue.pop() {
            if !seen.insert(dlg.signature.to_bytes()) {
                continue;
            }
            named.insert(dlg.payload.delegate.id(), dlg.payload.delegate.dupe());
            if let Some(proof) = &dlg.payload.proof {
                queue.push(proof.dupe());
            }
        }

        let named = Arc::new(named);
        self.delegated.insert(id, named.dupe());
        named
    }

    async fn cached_revocations_for(
        &mut self,
        membered: &Membered<F, S, T, L>,
    ) -> Arc<MemberAgents<F, S, T, L>> {
        let id = membered.agent_id().into();
        if let Some(cached) = self.revocations.get(&id) {
            return cached.dupe();
        }

        let revoked = Arc::new(member_agents_only(membered.revoked_members().await));
        self.revocations.insert(id, revoked.dupe());
        revoked
    }
}
