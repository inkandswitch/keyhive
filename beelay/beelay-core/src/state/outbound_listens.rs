use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{PeerAddress, SnapshotId};

use super::Snapshot;

pub(crate) struct OutboundListens<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<R: rand::Rng + rand::CryptoRng> OutboundListens<'_, R> {
    pub(crate) fn is_in_progress(&mut self, peer: PeerAddress, snapshot_id: SnapshotId) -> bool {
        self.state
            .borrow_mut()
            .forwarded_listens
            .is_in_progress(peer, snapshot_id)
    }

    pub(crate) fn begin_forward(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) {
        self.state
            .borrow_mut()
            .forwarded_listens
            .begin_forward(peer, snapshot_id);
    }

    pub(crate) fn offset(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) -> Option<u64> {
        self.state
            .borrow_mut()
            .forwarded_listens
            .offset(peer, snapshot_id)
    }

    pub(crate) fn complete_forward(
        &mut self,
        peer: &PeerAddress,
        snapshot_id: SnapshotId,
        new_offset: u64,
    ) {
        self.state
            .borrow_mut()
            .forwarded_listens
            .complete_forward(peer, snapshot_id, new_offset);
    }

    pub(crate) fn forward_failed(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) {
        self.state
            .borrow_mut()
            .forwarded_listens
            .forward_failed(peer, snapshot_id);
    }
}
