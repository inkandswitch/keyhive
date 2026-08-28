//! Every event each agent can reach, gathered once and deduplicated.

use crate::{
    event::Event,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::identifier::Identifier,
};
use derive_where::derive_where;
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, digest::Digest, signer::async_signer::AsyncSigner,
};
use std::collections::{HashMap, HashSet};

/// The digest an event is known by when it is sent.
pub type EventDigest<F, S, T, L> = Digest<Event<F, S, T, L>>;

/// Which events each agent can reach, and one copy of each.
///
/// The three kinds are kept apart because a source contributes to only one of them. A
/// caller that already holds a source's events can skip it without walking the rest.
#[derive_where(Debug; T)]
pub struct AllAgentEvents<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    /// Every distinct event, keyed by the digest it is sent under.
    pub events: HashMap<EventDigest<F, S, T, L>, Event<F, S, T, L>>,

    /// Per group, document or agent, the membership events it contributes.
    pub membership_sources: HashMap<Identifier, Vec<EventDigest<F, S, T, L>>>,

    /// Per identifier, the prekey events it contributes.
    pub prekey_sources: HashMap<Identifier, Vec<EventDigest<F, S, T, L>>>,

    /// Per document, the key agreement events it contributes.
    pub cgka_sources: HashMap<Identifier, Vec<EventDigest<F, S, T, L>>>,

    /// For each agent, the membership sources it reaches.
    pub membership_index: HashMap<Identifier, HashSet<Identifier>>,

    /// For each agent, the prekey sources it reaches.
    pub prekey_index: HashMap<Identifier, HashSet<Identifier>>,

    /// For each agent, the key agreement sources it reaches.
    pub cgka_index: HashMap<Identifier, HashSet<Identifier>>,
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    AllAgentEvents<F, S, T, L>
{
    /// Every event `agent` can reach, across all three kinds.
    ///
    /// Empty for an agent this instance has never heard of.
    pub fn digests_for(&self, agent: Identifier) -> HashSet<EventDigest<F, S, T, L>> {
        let mut out = HashSet::new();
        for (index, sources) in [
            (&self.membership_index, &self.membership_sources),
            (&self.prekey_index, &self.prekey_sources),
            (&self.cgka_index, &self.cgka_sources),
        ] {
            for source_id in index.get(&agent).into_iter().flatten() {
                out.extend(sources.get(source_id).into_iter().flatten().copied());
            }
        }
        out
    }

    /// How many distinct events this holds.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Every agent that reaches at least one event.
    pub fn agents(&self) -> HashSet<Identifier> {
        self.membership_index
            .keys()
            .chain(self.prekey_index.keys())
            .chain(self.cgka_index.keys())
            .copied()
            .collect()
    }
}
