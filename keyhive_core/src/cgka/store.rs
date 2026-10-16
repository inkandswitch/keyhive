//! Every authorized CGKA operation a replica holds, applied to a tree or not.
//!
//! Storing and forwarding an operation is separate from applying it. A relay
//! stores what it is authorized to hold, in whatever order it arrives, and
//! serves it on; only a member builds a tree, fed from here in causal order.

use crate::principal::document::id::DocumentId;
use beekem::operation::CgkaOperation;
use keyhive_crypto::{digest::Digest, verified::Verified};
use std::{collections::HashMap, sync::Arc};

/// Content-addressed and unordered, like the certificate set.
#[derive(Debug, Clone, Default)]
pub(crate) struct CgkaOpStore(
    HashMap<DocumentId, HashMap<Digest<CgkaOperation>, Arc<Verified<CgkaOperation>>>>,
);

impl CgkaOpStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Store `op` under its document. `true` if it was not already held.
    pub(crate) fn insert(&mut self, op: Arc<Verified<CgkaOperation>>) -> bool {
        let doc_id = DocumentId::from(op.payload().doc_id);
        self.0
            .entry(doc_id)
            .or_default()
            .insert(op.digest(), op)
            .is_none()
    }

    /// Every operation held for `doc`, in no particular order.
    pub(crate) fn ops_for(
        &self,
        doc: DocumentId,
    ) -> impl Iterator<Item = &Arc<Verified<CgkaOperation>>> {
        self.0.get(&doc).into_iter().flat_map(HashMap::values)
    }

    /// Every document an operation is held for.
    pub(crate) fn documents(&self) -> impl Iterator<Item = DocumentId> + '_ {
        self.0
            .iter()
            .filter(|(_, ops)| !ops.is_empty())
            .map(|(id, _)| *id)
    }

    /// Whether any operation is held for `doc`.
    pub(crate) fn holds(&self, doc: DocumentId) -> bool {
        self.0.get(&doc).is_some_and(|ops| !ops.is_empty())
    }

    /// How many operations are held, across every document.
    pub(crate) fn len(&self) -> usize {
        self.0.values().map(HashMap::len).sum()
    }
}
