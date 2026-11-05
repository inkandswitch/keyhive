//! The immediate causal predecessors of a CGKA operation.

use crate::{
    collections::Set,
    error::CgkaError,
    operation::{CgkaOperation, CgkaOperationGraph},
};
use alloc::{
    collections::{binary_heap::PeekMut, BTreeMap, BTreeSet, BinaryHeap},
    vec::Vec,
};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::digest::Digest;

/// The immediate causal predecessors of a CGKA operation.
///
/// Only an add may have none.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct Predecessors(BTreeSet<Digest<CgkaOperation>>);

impl Predecessors {
    /// The predecessors of a new operation on `graph`.
    pub fn heads_of(graph: &CgkaOperationGraph) -> Self {
        graph.cgka_op_heads.iter().copied().collect()
    }

    /// Whether this contains every head in `graph`.
    pub fn contains_heads_of(&self, graph: &CgkaOperationGraph) -> bool {
        self.missing_heads(graph).next().is_none()
    }

    /// The heads of `graph` that are not among these predecessors. A head has
    /// no children so these are exactly the heads outside the causal past of
    /// an operation with these predecessors.
    fn missing_heads<'a>(
        &'a self,
        graph: &'a CgkaOperationGraph,
    ) -> impl Iterator<Item = Digest<CgkaOperation>> + 'a {
        graph
            .cgka_op_heads
            .iter()
            .filter(|head| !self.0.contains(head))
            .copied()
    }

    /// The members of `targets` that an operation with these predecessors has
    /// observed, i.e., the ones in its causal past, including the predecessors
    /// themselves. Every target and predecessor must be in `graph`.
    ///
    /// If these predecessors contain every head of `graph`, every target has
    /// been observed. Otherwise two searches alternate one step at a time. The
    /// first to decide for every target returns the answer:
    ///
    /// 1) Begin from these predecessors and search back through the causal
    ///    past, skipping anything shallower than every undecided target.
    /// 2) Begin from the heads of `graph` missing from these predecessors,
    ///    which are concurrent with the operation, and search back through the
    ///    operations concurrent with it.
    ///
    /// The first search is normally faster when the targets are recent. The
    /// second is normally faster when there is little concurrency with the
    /// operation. Neither has to visit the whole past.
    ///
    /// Returns [`CgkaError::OperationNotFound`] if a target or an operation a
    /// search reaches is not in `graph` and [`CgkaError::DepthNotFound`] if
    /// one has no recorded depth.
    pub(crate) fn filter_in_causal_past(
        &self,
        targets: BTreeSet<Digest<CgkaOperation>>,
        graph: &CgkaOperationGraph,
    ) -> Result<BTreeSet<Digest<CgkaOperation>>, CgkaError> {
        let missing_heads: Vec<_> = self.missing_heads(graph).collect();
        if missing_heads.is_empty() {
            // All targets are ancestors of an operation with these predecessors.
            return Ok(targets);
        }
        let mut found = BTreeSet::new();
        let mut pending = BTreeMap::new();
        for target in targets {
            if self.contains(&target) {
                found.insert(target);
            } else {
                pending.insert(target, graph.depth(&target)?);
            }
        }
        let mut past = PastSearch {
            frontier: self.iter().copied().collect(),
            queued: self.iter().copied().collect(),
        };
        let mut concurrent = ConcurrentSearch::new(graph, missing_heads)?;
        // If an operation is shallower than every remaining target, it can't
        // have a target as an ancestor.
        while let Some(min_pending_depth) = pending.values().copied().min() {
            // Take one step in `PastSearch`.
            let Some(current) = past.next() else {
                // Every remaining target is outside the past.
                break;
            };
            if pending.remove(&current).is_some() {
                found.insert(current);
            }
            for pred in graph
                .predecessors_for(&current)
                .ok_or(CgkaError::OperationNotFound)?
            {
                if graph.depth(pred)? >= min_pending_depth {
                    past.push(*pred);
                }
            }

            // Take one step in `ConcurrentSearch`.
            match concurrent.next(graph, self, min_pending_depth)? {
                None => {
                    // Every remaining target is in the past.
                    found.extend(pending.into_keys());
                    break;
                }
                Some((current, in_past)) => {
                    if pending.remove(&current).is_some() && in_past {
                        found.insert(current);
                    }
                }
            }
        }
        Ok(found)
    }

    /// The predecessors, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = &Digest<CgkaOperation>> {
        self.0.iter()
    }

    /// Whether `op_hash` is one of the predecessors.
    pub fn contains(&self, op_hash: &Digest<CgkaOperation>) -> bool {
        self.0.contains(op_hash)
    }

    /// Whether there are no predecessors.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<Digest<CgkaOperation>> for Predecessors {
    fn from_iter<I: IntoIterator<Item = Digest<CgkaOperation>>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<const N: usize> From<[Digest<CgkaOperation>; N]> for Predecessors {
    fn from(op_hashes: [Digest<CgkaOperation>; N]) -> Self {
        op_hashes.into_iter().collect()
    }
}

impl<'a> IntoIterator for &'a Predecessors {
    type Item = &'a Digest<CgkaOperation>;
    type IntoIter = alloc::collections::btree_set::Iter<'a, Digest<CgkaOperation>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A count and then the digests, ascending.
impl Encode for Predecessors {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl Decode for Predecessors {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for Predecessors {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (op_hashes, rest) = BTreeSet::decode_next(bytes)?;
        Ok((Self(op_hashes), rest))
    }
}

/// A search back through an operation's causal past, starting from its
/// predecessors. It keeps every operation ever queued so none is visited
/// twice.
struct PastSearch {
    frontier: Vec<Digest<CgkaOperation>>,
    queued: Set<Digest<CgkaOperation>>,
}

impl PastSearch {
    fn push(&mut self, op_hash: Digest<CgkaOperation>) {
        if self.queued.insert(op_hash) {
            self.frontier.push(op_hash);
        }
    }

    fn next(&mut self) -> Option<Digest<CgkaOperation>> {
        self.frontier.pop()
    }
}

/// A search through the operations concurrent with an operation, which are
/// those outside its causal past, starting from the heads missing from its
/// predecessors, deepest first.
///
/// An operation is in the past if it is one of the predecessors or one of its
/// children is in the past. Every operation outside the past is reached from
/// a missing head through operations outside it, and each operation pushed is
/// shallower than the one just visited, so operations are visited deepest
/// first. A child is deeper than its parent, so when an operation is visited
/// each child outside the past has been marked outside, and any other child
/// is in the past. The search continues only through operations outside the
/// past.
///
/// An unvisited target outside the past has a queued operation, at least as
/// deep as itself, on a chain from a missing head down to it. So once every
/// queued operation is shallower than every undecided target, those targets
/// are all in the past.
struct ConcurrentSearch {
    frontier: BinaryHeap<(u64, Digest<CgkaOperation>)>,
    queued: Set<Digest<CgkaOperation>>,
    outside: Set<Digest<CgkaOperation>>,
}

impl ConcurrentSearch {
    fn new(
        graph: &CgkaOperationGraph,
        concurrent_heads: impl IntoIterator<Item = Digest<CgkaOperation>>,
    ) -> Result<Self, CgkaError> {
        let mut search = Self {
            frontier: BinaryHeap::new(),
            queued: Set::new(),
            outside: Set::new(),
        };
        for head in concurrent_heads {
            search.push(graph, head)?;
        }
        Ok(search)
    }

    fn push(
        &mut self,
        graph: &CgkaOperationGraph,
        op_hash: Digest<CgkaOperation>,
    ) -> Result<(), CgkaError> {
        if self.queued.insert(op_hash) {
            self.frontier.push((graph.depth(&op_hash)?, op_hash));
        }
        Ok(())
    }

    /// The next operation, and whether it is in the past of an operation with
    /// `predecessors`. Returns `None` once every operation outside that past at
    /// least `min_depth` deep has been visited.
    fn next(
        &mut self,
        graph: &CgkaOperationGraph,
        predecessors: &Predecessors,
        min_depth: u64,
    ) -> Result<Option<(Digest<CgkaOperation>, bool)>, CgkaError> {
        let Some(deepest) = self
            .frontier
            .peek_mut()
            .filter(|deepest| deepest.0 >= min_depth)
        else {
            return Ok(None);
        };
        let (_, current) = PeekMut::pop(deepest);
        let in_past = predecessors.contains(&current)
            || graph
                .children_of(&current)
                .any(|child| !self.outside.contains(child));
        if !in_past {
            self.outside.insert(current);
            for pred in graph
                .predecessors_for(&current)
                .ok_or(CgkaError::OperationNotFound)?
            {
                self.push(graph, *pred)?;
            }
        }
        Ok(Some((current, in_past)))
    }
}
