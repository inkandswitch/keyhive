use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{riblt, snapshots::Snapshot, SnapshotId};

pub(crate) struct Snapshots<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Snapshots<'a, R> {
    pub(crate) fn store_snapshot(&self, snapshot: Snapshot) -> Arc<Snapshot> {
        self.state.borrow_mut().snapshots.store(snapshot)
    }

    pub(crate) fn next_snapshot_symbols(
        &self,
        snapshot_id: SnapshotId,
        count: u64,
    ) -> Option<Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>> {
        self.state
            .borrow_mut()
            .snapshots
            .next_n_symbols(snapshot_id, count)
    }

    pub(crate) fn we_have_snapshot_with_source(&self, source: SnapshotId) -> bool {
        self.state
            .borrow()
            .snapshots
            .we_have_snapshot_with_source(source)
    }

    pub(crate) fn lookup_snapshot(&self, snapshot_id: SnapshotId) -> Option<Arc<Snapshot>> {
        self.state.borrow().snapshots.lookup(snapshot_id)
    }
}
