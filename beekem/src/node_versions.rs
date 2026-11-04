//! The versions of a value at a tree node.

use crate::keys::HasShareKey;
use alloc::collections::BTreeSet;
use keyhive_crypto::share_key::ShareKey;
use nonempty::NonEmpty;

/// The versions of a value at a tree node, in ascending order and without
/// duplicates.
///
/// A node has more than one version after concurrent writes. A write removes
/// the versions whose share keys it lists as removed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeVersions<V>(NonEmpty<V>);

impl<V: Ord + Clone> NodeVersions<V> {
    /// Construct a `NodeVersions` with all versions in `values`.
    pub(crate) fn new(values: NonEmpty<V>) -> Self {
        Self(sorted_and_deduplicated(values))
    }

    /// Merge `values` into the node, first removing the versions whose share
    /// keys are in `removed`.
    pub(crate) fn merge(&mut self, mut values: NonEmpty<V>, removed: &BTreeSet<ShareKey>)
    where
        V: HasShareKey,
    {
        values.extend(
            self.0
                .iter()
                .filter(|value| !removed.contains(&value.share_key()))
                .cloned(),
        );
        self.0 = sorted_and_deduplicated(values);
    }

    /// The versions, in ascending order.
    pub(crate) fn values(&self) -> &NonEmpty<V> {
        &self.0
    }

    /// Whether the node has more than one version.
    pub fn has_conflict(&self) -> bool {
        !self.0.tail.is_empty()
    }

    /// The node's single version. Returns `None` if this is a conflict node.
    pub(crate) fn non_conflict_version(&self) -> Option<&V> {
        (!self.has_conflict()).then_some(&self.0.head)
    }
}

/// `values` in ascending order without duplicates.
fn sorted_and_deduplicated<V: Ord>(mut values: NonEmpty<V>) -> NonEmpty<V> {
    values.sort();
    let NonEmpty { head, tail } = values;
    let mut kept = NonEmpty::new(head);
    for value in tail {
        if *kept.last() != value {
            kept.push(value);
        }
    }
    kept
}
