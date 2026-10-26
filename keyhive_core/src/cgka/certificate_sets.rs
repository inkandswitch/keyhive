//! The certificate sets of CGKA operations (the certificates each operation
//! and its causal ancestors cite).

use super::Cgka;
use beekem::{
    id::TreeId,
    operation::{CgkaOperation, CitationId},
};
use dupe::Dupe;
use imbl::{ordset::DiffItem, OrdSet};
use keyhive_crypto::{digest::Digest, signed::SerdeSigned};
use std::{
    collections::{HashMap, VecDeque},
    ops::Deref,
};

type OpDigest = Digest<SerdeSigned<CgkaOperation>>;

/// A set of citation ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CitationSet(OrdSet<CitationId>);

// A clone of a persistent `OrdSet` shares the original's structure.
impl Dupe for CitationSet {}

impl Deref for CitationSet {
    type Target = OrdSet<CitationId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Extend<CitationId> for CitationSet {
    fn extend<I: IntoIterator<Item = CitationId>>(&mut self, citations: I) {
        // `OrdSet` copies every node on an insert's path before it finds the
        // key, even when the citation is already present. Skip those so the
        // set keeps sharing its nodes with the sets it was cloned from.
        for citation in citations {
            if !self.0.contains(&citation) {
                self.0.insert(citation);
            }
        }
    }
}

impl FromIterator<CitationId> for CitationSet {
    fn from_iter<I: IntoIterator<Item = CitationId>>(citations: I) -> Self {
        Self(citations.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a CitationSet {
    type Item = &'a CitationId;
    type IntoIter = <&'a OrdSet<CitationId> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// How many of a document's most recently built certificate sets are kept,
/// besides checkpoints.
const RECENT_SETS: usize = 64;

/// One in every this many of a document's sets built, rebuilds included, is
/// kept as a checkpoint, so an evicted set is usually rebuilt from a recent
/// one rather than from the document's first operation.
const CHECKPOINT_EVERY: u64 = 1024;

#[derive(Debug, Clone)]
pub(crate) struct CertificateSets {
    /// Each document's certificate sets.
    docs: HashMap<TreeId, DocumentSets>,

    /// [`RECENT_SETS`] (fewer in tests).
    recent_sets: usize,

    /// [`CHECKPOINT_EVERY`] (fewer in tests).
    checkpoint_every: u64,
}

/// A document's certificate sets.
#[derive(Debug, Clone, Default)]
struct DocumentSets {
    /// Certificate sets (every certificate an operation and its causal
    /// ancestors cite) of the most recently built operations and of
    /// checkpoints. A set is built when it is first requested, together with
    /// those of its ancestors that are not already present.
    sets: HashMap<OpDigest, CitationSet>,

    /// Stored sets that are not checkpoints, oldest first.
    recent: VecDeque<OpDigest>,

    /// How many sets have been built, including rebuilds of evicted ones.
    built: u64,
}

impl CertificateSets {
    pub(crate) fn new() -> Self {
        Self::retaining(RECENT_SETS, CHECKPOINT_EVERY)
    }

    /// A `CertificateSets` that retains each document's `recent_sets` most
    /// recently built sets as well as one in every `checkpoint_every`.
    pub(crate) fn retaining(recent_sets: usize, checkpoint_every: u64) -> Self {
        Self {
            docs: HashMap::new(),
            recent_sets,
            checkpoint_every,
        }
    }

    /// Every certificate the operations at `heads` and their causal ancestors
    /// cite.
    ///
    /// Returns `None` if `cgka` is missing any of them.
    pub(crate) fn predecessor_set<'a>(
        &mut self,
        cgka: &Cgka,
        heads: impl IntoIterator<Item = &'a OpDigest>,
    ) -> Option<CitationSet> {
        let heads: Vec<&OpDigest> = heads.into_iter().collect();
        let Some(first) = heads.first() else {
            return Some(CitationSet::default());
        };
        let doc = *cgka.op(first)?.payload.doc_id();
        let doc_sets = self.docs.entry(doc).or_default();
        let sets: Option<Vec<CitationSet>> = heads
            .iter()
            .map(|head| doc_sets.certificate_set(cgka, **head, self.checkpoint_every))
            .collect();
        // Only evict once every head has been examined. A later one may need sets an
        // earlier one built.
        doc_sets.evict(self.recent_sets);
        Some(union(&sets?.iter().collect::<Vec<_>>()))
    }
}

impl DocumentSets {
    /// Every certificate the operation `digest` and its causal ancestors cite,
    /// from the cache or else from `cgka`. Returns `None` if neither has it.
    fn certificate_set(
        &mut self,
        cgka: &Cgka,
        digest: OpDigest,
        checkpoint_every: u64,
    ) -> Option<CitationSet> {
        // Proceed depth-first, visiting each operation after its predecessors.
        // Each stack entry is an op digest and whether its predecessors were already
        // pushed, in which case they will be visited before it's popped.
        let mut stack = vec![(digest, false)];
        while let Some((next, predecessors_pushed)) = stack.pop() {
            if self.sets.contains_key(&next) {
                continue;
            }
            let op = &cgka.op(&next)?.payload;
            if predecessors_pushed {
                let preds: Vec<&CitationSet> = op
                    .predecessors()
                    .iter()
                    .map(|pred| {
                        self.sets.get(pred).expect(
                            "visited earlier in this traversal. Nothing is evicted until the traversal ends",
                        )
                    })
                    .collect();
                let mut set = union(&preds);
                set.extend(op.citations().iter().copied());
                self.add_set(next, set, checkpoint_every);
            } else {
                stack.push((next, true));
                stack.extend(op.predecessors().into_iter().map(|p| (p, false)));
            }
        }
        self.sets.get(&digest).map(Dupe::dupe)
    }

    /// Record `set` for `digest`, as a checkpoint if one is due.
    fn add_set(&mut self, digest: OpDigest, set: CitationSet, checkpoint_every: u64) {
        self.built += 1;
        if !self.built.is_multiple_of(checkpoint_every) {
            self.recent.push_back(digest);
        }
        self.sets.insert(digest, set);
    }

    /// Evict the sets that are neither checkpoints nor among the
    /// `recent_sets` most recently built.
    fn evict(&mut self, recent_sets: usize) {
        let excess = self.recent.len().saturating_sub(recent_sets);
        for digest in self.recent.drain(..excess) {
            self.sets.remove(&digest);
        }
    }
}

/// The union of `sets`. Starts from the largest set and adds what each other set
/// has beyond it, according to [`OrdSet::diff`], skipping the nodes two sets
/// share. Sets from concurrent branches share everything from before their
/// fork.
fn union(sets: &[&CitationSet]) -> CitationSet {
    let Some(largest) = sets.iter().max_by_key(|set| set.len()) else {
        return CitationSet::default();
    };
    let mut merged = (*largest).dupe();
    for set in sets.iter().filter(|s| !s.ptr_eq(largest)) {
        merged.extend(largest.diff(set).filter_map(|item| match item {
            DiffItem::Add(citation) => Some(*citation),
            DiffItem::Remove(_) => None,
        }));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(range: std::ops::Range<u8>) -> CitationSet {
        range.map(|n| CitationId([n; 32])).collect()
    }

    #[test]
    fn extending_with_present_citations_keeps_the_set_shared() {
        let set = ids(0..100);
        let mut extended = set.dupe();
        extended.extend(ids(0..100).iter().copied());
        assert!(extended.ptr_eq(&set));
    }

    #[test]
    fn only_checkpoints_and_recent_sets_are_retained() {
        let mut sets = DocumentSets::default();
        let digest = |n: u64| OpDigest::from(*blake3::hash(&n.to_le_bytes()).as_bytes());
        let total = CHECKPOINT_EVERY + RECENT_SETS as u64;
        for n in 1..=total {
            sets.add_set(digest(n), CitationSet::default(), CHECKPOINT_EVERY);
        }
        sets.evict(RECENT_SETS);
        assert!(sets.sets.contains_key(&digest(CHECKPOINT_EVERY)));
        assert!(!sets.sets.contains_key(&digest(CHECKPOINT_EVERY - 1)));
        assert!(sets
            .sets
            .contains_key(&digest(total - RECENT_SETS as u64 + 1)));
        assert_eq!(sets.sets.len(), RECENT_SETS + 1);
    }

    #[test]
    fn union_contains_what_each_branch_cited_since_the_fork() {
        let fork = ids(0..100);
        let mut left = fork.dupe();
        left.extend(ids(100..102).iter().copied());
        let mut right = fork.dupe();
        right.extend(ids(102..103).iter().copied());
        assert_eq!(union(&[&left, &right]), ids(0..103));
    }
}
