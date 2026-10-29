//! The Keyline certificates CGKA operations cite as well as Keyline's answers
//! for the subsets of them that operations and batches define.
//!
//! A CGKA add or remove cites certificates by [`CitationId`]. An operation's
//! predecessor set is everything its causal ancestors cited. Its certificate
//! set adds what it cites itself and its signing set adds only the
//! delegations it cites. CGKA authorization and implicit removal are evaluated
//! over those sets.

use beekem::{cgka::ImplicitRemovesProtocol, id::MemberId, operation::CitationId};
use dupe::Dupe;
use imbl::OrdMap;
use keyhive_crypto::{digest::Digest, identifier::Identifier, verified::Verified};
use keyline::{
    certificate::{CertificateId, VerifiedCertificate},
    contract::{set_digest, CertificateSet},
    delegation::Delegation,
    power::Power,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fmt,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
};

/// The id an operation cites `cert` by.
pub(crate) fn citation_of(cert: CertificateId) -> CitationId {
    CitationId(cert.to_bytes())
}

/// A cited certificate id and, if it's a delegation, the delegation
/// itself.
#[derive(Debug, Clone)]
struct Cited {
    id: CertificateId,
    delegation: Option<Arc<Verified<Delegation>>>,
}

impl<W> From<&VerifiedCertificate<W>> for Cited {
    fn from(cert: &VerifiedCertificate<W>) -> Self {
        let delegation = match cert {
            VerifiedCertificate::Delegation(d) => Some(Arc::clone(d)),
            VerifiedCertificate::Revocation(_) => None,
        };
        Self {
            id: cert.id(),
            delegation,
        }
    }
}

/// Members of a resource, according to Keyline given a set of certificates.
///
/// A persistent map so that [`CitedCertificates::cache`] can build each
/// answer from the previous one and share storage with it.
#[derive(Debug, Clone)]
pub(crate) struct Members(OrdMap<Identifier, Power>);

// A clone of a persistent `OrdMap` shares the original's structure.
impl Dupe for Members {}

impl Deref for Members {
    type Target = OrdMap<Identifier, Power>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Caching key for `Identifier`s membership according to Keyline given the hashed
/// certificate set.
pub(crate) type MembersKey = (Digest<CertificateSet>, Identifier);

/// A digest of an [ImplicitRemovesProtocol] query: the certificate set, resource and CGKA
/// group members for the query.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct QueryHash([u8; 32]);

impl QueryHash {
    fn new((set, resource): MembersKey, cgka_members: &BTreeSet<MemberId>) -> Self {
        let mut query = blake3::Hasher::new();
        query.update(set.as_slice());
        query.update(resource.as_bytes());
        for member in cgka_members {
            query.update(member.as_bytes());
        }
        Self(*query.finalize().as_bytes())
    }
}

/// How many of Keyline's answers about a resource are kept outside a replay.
/// Authorization and writes ask about sets near the current heads, a few at a
/// time.
const ANSWERS_PER_RESOURCE: usize = 8;

/// The certificates CGKA operations cite or may cite, and Keyline's answers
/// over the sets of them that are cited by CGKA operations and their causal
/// predecessors.
///
/// BeeKEM queries its [`ImplicitRemovesProtocol`] synchronously. The protocol
/// implemented here answers from what
/// [`Keyline::members_for_subset`](keyline::contract::Keyline::members_for_subset)
/// answered, cached here.
///
/// A replay asks about every membership batch of a document's CGKA graph.
/// The protocol's verdicts are kept for the keyhive's lifetime and a later replay
/// doesn't require a Keyline answer for a batch it has seen. A verdict is small and
/// usually empty. Keyline's full answers are kept only while a replay of their
/// resource is in progress and otherwise only the most recent few for each
/// resource.
#[derive(Default)]
pub(crate) struct CitedCertificates {
    certificates: HashMap<CitationId, Cited>,
    members: HashMap<MembersKey, Members>,

    /// Each resource's cached answers, oldest first.
    cached: HashMap<Identifier, VecDeque<MembersKey>>,

    /// The last answer cached for each resource, which the next is built from.
    latest: HashMap<Identifier, Members>,

    /// How many replays of each resource are in progress.
    replays: HashMap<Identifier, usize>,

    /// The CGKA group members each certificate set asked about does not
    /// entitle to membership.
    non_members: HashMap<QueryHash, BTreeSet<MemberId>>,
}

impl CitedCertificates {
    /// Record `cert`, for authorizing operations that cite it.
    pub(crate) fn insert<W>(&mut self, cert: &VerifiedCertificate<W>) {
        self.certificates
            .insert(citation_of(cert.id()), Cited::from(cert));
    }

    /// Record each of `certs`.
    pub(crate) fn insert_multiple<W>(&mut self, certs: &[VerifiedCertificate<W>]) {
        for cert in certs {
            self.insert(cert);
        }
    }

    /// Whether `citation` refers to a certificate recorded here.
    pub(crate) fn contains(&self, citation: &CitationId) -> bool {
        self.certificates.contains_key(citation)
    }

    /// The delegation `citation` refers to and its issuer. Returns `None`
    /// if it is not recorded here or is not a delegation.
    pub(crate) fn delegation(&self, citation: &CitationId) -> Option<(Identifier, &Delegation)> {
        let d = self.certificates.get(citation)?.delegation.as_ref()?;
        Some((d.issuer(), d.payload()))
    }

    /// The subset of the Keyline store that `cited` refers to. This is the
    /// set of certificates recorded here as you would pass them to
    /// [`Keyline::members_for_subset`](keyline::contract::Keyline::members_for_subset).
    pub(crate) fn certificate_subset<'a>(
        &self,
        cited: impl IntoIterator<Item = &'a CitationId>,
    ) -> BTreeSet<CertificateId> {
        self.certificate_ids_in(cited).collect()
    }

    /// The caching key for a Keyline membership answer given the certificates
    /// of `cited` currently recorded here for `resource`.
    ///
    /// The key covers only what is recorded. It changes once a cited
    /// certificate arrives.
    pub(crate) fn key<'a>(
        &self,
        cited: impl IntoIterator<Item = &'a CitationId>,
        resource: Identifier,
    ) -> MembersKey {
        (set_digest(self.certificate_ids_in(cited)), resource)
    }

    /// The ids of the certificates in `cited` recorded here.
    fn certificate_ids_in<'s, 'c, I>(
        &'s self,
        cited: I,
    ) -> impl Iterator<Item = CertificateId> + use<'s, 'c, I>
    where
        I: IntoIterator<Item = &'c CitationId>,
    {
        cited
            .into_iter()
            .filter_map(|c| self.certificates.get(c).map(|cert| cert.id))
    }

    /// The cached answer for `key`.
    pub(crate) fn members(&self, key: &MembersKey) -> Option<Members> {
        self.members.get(key).map(Dupe::dupe)
    }

    /// Cache Keyline's `answer` for `key` and return it. It is built from the
    /// last answer cached for the same resource so the two share most of
    /// their storage.
    pub(crate) fn cache(
        &mut self,
        key: MembersKey,
        answer: BTreeMap<Identifier, Power>,
    ) -> Members {
        if let Some(cached) = self.members.get(&key) {
            return cached.dupe();
        }
        let (_, resource) = key;
        let members = match self.latest.get(&resource) {
            Some(base) => changed_to(base, &answer),
            None => Members(answer.into_iter().collect()),
        };
        self.latest.insert(resource, members.dupe());
        self.members.insert(key, members.dupe());
        self.cached.entry(resource).or_default().push_back(key);
        self.evict(resource);
        members
    }

    /// The members of `cgka_members` without `Read` or higher standing in
    /// the answer for `key`. Returns `None` if neither that verdict nor
    /// the answer is cached.
    fn non_members(
        &mut self,
        key: MembersKey,
        cgka_members: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        let query_hash = QueryHash::new(key, cgka_members);
        if let Some(non_members) = self.non_members.get(&query_hash) {
            return Some(non_members.clone());
        }
        let members = self.members.get(&key)?;
        let non_members: BTreeSet<MemberId> = cgka_members
            .iter()
            .filter(|member| !members.get(&member.id()).is_some_and(|p| p.is_reader()))
            .copied()
            .collect();
        self.non_members.insert(query_hash, non_members.clone());
        Some(non_members)
    }

    /// Record that a replay of `resource` began. Its answers are kept until
    /// every replay of it has ended.
    fn begin_replay(&mut self, resource: Identifier) {
        *self.replays.entry(resource).or_default() += 1;
    }

    /// Record that a replay of `resource` ended and evict its answers past
    /// the most recent few if no other replay of it is in progress.
    fn end_replay(&mut self, resource: Identifier) {
        if let Some(count) = self.replays.get_mut(&resource) {
            *count -= 1;
            if *count == 0 {
                self.replays.remove(&resource);
            }
        }
        self.evict(resource);
    }

    /// Evict `resource`'s answers past the most recent
    /// [`ANSWERS_PER_RESOURCE`] unless a replay of it is in progress.
    fn evict(&mut self, resource: Identifier) {
        if self.replays.contains_key(&resource) {
            return;
        }
        let Some(cached) = self.cached.get_mut(&resource) else {
            return;
        };
        let excess = cached.len().saturating_sub(ANSWERS_PER_RESOURCE);
        for key in cached.drain(..excess) {
            self.members.remove(&key);
        }
    }
}

/// `base` with only the entries that differ from `answer` changed. The
/// result normally shares most of its structure with `base`.
fn changed_to(base: &Members, answer: &BTreeMap<Identifier, Power>) -> Members {
    let mut members = base.dupe().0;
    let mut old = base.iter().peekable();
    for (id, power) in answer {
        while let Some((gone, _)) = old.next_if(|(was, _)| *was < id) {
            members.remove(gone);
        }
        if old.next_if(|(was, _)| *was == id).map(|(_, was)| was) != Some(power) {
            members.insert(*id, *power);
        }
    }
    for (gone, _) in old {
        members.remove(gone);
    }
    Members(members)
}

/// [`CitedCertificates`] shared by a keyhive, its forks, and their CGKA
/// groups. A new keyhive starts from the empty default.
#[derive(Clone, Default, Dupe)]
pub(crate) struct SharedCitations(Arc<Mutex<CitedCertificates>>);

impl SharedCitations {
    pub(crate) fn lock(&self) -> MutexGuard<'_, CitedCertificates> {
        self.0.lock().expect("the citations lock is not poisoned")
    }

    /// Keep `resource`'s answers until the returned guard is dropped.
    pub(crate) fn replaying(&self, resource: Identifier) -> Replaying {
        self.lock().begin_replay(resource);
        Replaying {
            citations: self.dupe(),
            resource,
        }
    }
}

/// A replay in progress, returned by [`SharedCitations::replaying`].
pub(crate) struct Replaying {
    citations: SharedCitations,
    resource: Identifier,
}

impl Drop for Replaying {
    fn drop(&mut self) {
        // A poisoned lock means a panic elsewhere. Panicking here as well
        // would abort.
        if let Ok(mut citations) = self.citations.0.lock() {
            citations.end_replay(self.resource);
        }
    }
}

/// The [`ImplicitRemovesProtocol`] for a document's CGKA, as determined by
/// Keyline. Every replica of the CGKA must use it.
///
/// Given a certificate set, it reports which of the CGKA group's members
/// lack `Read` or higher standing over `resource` in that set. BeeKEM asks
/// synchronously so this answers only from verdicts and Keyline answers
/// already cached in `CitedCertificates`. Returns `None` for a set with
/// neither cached.
#[derive(Clone)]
pub(crate) struct KeylineImplicitRemovesProtocol {
    resource: Identifier,
    citations: SharedCitations,
}

impl KeylineImplicitRemovesProtocol {
    pub(crate) fn new(resource: Identifier, citations: SharedCitations) -> Self {
        Self {
            resource,
            citations,
        }
    }
}

impl fmt::Debug for KeylineImplicitRemovesProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeylineImplicitRemovesProtocol")
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

impl ImplicitRemovesProtocol for KeylineImplicitRemovesProtocol {
    fn non_members(
        &self,
        cited: &BTreeSet<CitationId>,
        cgka_members: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        let mut citations = self.citations.lock();
        let key = citations.key(cited, self.resource);
        citations.non_members(key, cgka_members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn id(n: u8) -> Identifier {
        Identifier::from(&SigningKey::from([n; 32]))
    }

    fn key(set: u8) -> MembersKey {
        (Digest::from([set; 32]), id(0))
    }

    #[test]
    fn a_cached_answer_equals_keylines_answer_whatever_it_was_built_from() {
        let mut ids: Vec<Identifier> = (1..=4).map(id).collect();
        ids.sort();
        let [a, b, c, d] = ids[..] else {
            unreachable!("four ids")
        };
        let first = BTreeMap::from([(a, Power::Admin), (b, Power::Read), (c, Power::Edit)]);
        let second = BTreeMap::from([(b, Power::Edit), (d, Power::Read)]);

        let mut cited = CitedCertificates::default();
        for (set, answer) in [(1, &first), (2, &second), (3, &first)] {
            let cached = cited.cache(key(set), answer.clone());
            let cached: BTreeMap<_, _> = cached.iter().map(|(id, power)| (*id, *power)).collect();
            assert_eq!(cached, *answer);
        }
    }

    fn members(ids: &[u8]) -> BTreeSet<MemberId> {
        ids.iter().map(|n| MemberId::from(id(*n))).collect()
    }

    #[test]
    fn a_verdict_outlives_the_answer_it_came_from() {
        let mut cited = CitedCertificates::default();
        cited.cache(
            key(1),
            BTreeMap::from([(id(1), Power::Read), (id(2), Power::Relay)]),
        );
        assert_eq!(
            cited.non_members(key(1), &members(&[1, 2])),
            Some(members(&[2]))
        );

        for set in 2..=u8::try_from(ANSWERS_PER_RESOURCE + 1).expect("small") {
            cited.cache(key(set), BTreeMap::new());
        }
        assert!(cited.members(&key(1)).is_none());
        assert_eq!(
            cited.non_members(key(1), &members(&[1, 2])),
            Some(members(&[2]))
        );
        assert_eq!(cited.non_members(key(1), &members(&[1])), None);
    }

    #[test]
    fn answers_are_kept_while_a_replay_of_their_resource_is_in_progress() {
        let cited = SharedCitations::default();
        let (_, resource) = key(1);
        let first = cited.replaying(resource);
        let second = cited.replaying(resource);
        for set in 1..=u8::try_from(ANSWERS_PER_RESOURCE + 1).expect("small") {
            cited.lock().cache(key(set), BTreeMap::new());
        }
        drop(first);
        assert!(
            cited.lock().members(&key(1)).is_some(),
            "a replay is still in progress"
        );
        drop(second);
        assert!(cited.lock().members(&key(1)).is_none());
    }
}
