//! The immediate causal predecessors of a CGKA operation.

use crate::operation::{CgkaOperation, CgkaOperationGraph};
use alloc::{collections::BTreeSet, vec::Vec};
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
        graph.cgka_op_heads.iter().all(|head| self.0.contains(head))
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
