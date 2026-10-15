//! Every event each principal can reach, gathered once and deduplicated.

use crate::{event::Event, principal::identifier::Identifier};
use keyhive_crypto::{content::reference::ContentRef, digest::Digest};
use std::collections::{HashMap, HashSet};

/// The digest an event is known by when it is sent.
pub type EventDigest<T> = Digest<Event<T>>;

/// Which events each principal can reach, and one copy of each.
///
/// The three kinds are kept apart because a source contributes to only one of them. A
/// caller that already holds a source's events can skip it without walking the rest.
#[derive(Debug)]
pub struct AllAgentEvents<T: ContentRef> {
    /// Every distinct event, keyed by the digest it is sent under.
    pub events: HashMap<EventDigest<T>, Event<T>>,

    /// Per group or document, the Keyline certificates in its closure.
    pub membership_sources: HashMap<Identifier, Vec<EventDigest<T>>>,

    /// Per principal cut off from a group or document it stood over, the
    /// Keyline certificates that explain that, and nothing that came after.
    pub explanations: HashMap<Identifier, Vec<EventDigest<T>>>,

    /// Per identifier, the prekey events it contributes.
    pub prekey_sources: HashMap<Identifier, Vec<EventDigest<T>>>,

    /// Per document, the key agreement events it contributes.
    pub cgka_sources: HashMap<Identifier, Vec<EventDigest<T>>>,

    /// For each principal, the groups and documents it stands over (itself
    /// included), whose certificates it is sent.
    pub membership_index: HashMap<Identifier, HashSet<Identifier>>,

    /// For each principal, the prekey sources it reaches.
    pub prekey_index: HashMap<Identifier, HashSet<Identifier>>,

    /// For each principal, the key agreement sources it reaches.
    pub cgka_index: HashMap<Identifier, HashSet<Identifier>>,
}

impl<T: ContentRef> AllAgentEvents<T> {
    /// Every event `agent` can reach, across all kinds.
    ///
    /// Empty for a principal this instance has never heard of.
    pub fn digests_for(&self, agent: Identifier) -> HashSet<EventDigest<T>> {
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
        out.extend(self.explanations.get(&agent).into_iter().flatten().copied());
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
