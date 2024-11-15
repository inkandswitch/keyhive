use std::collections::{HashMap, HashSet};

use crate::{PeerAddress, SnapshotId};

pub(crate) struct OutboundListens {
    offsets: HashMap<(PeerAddress, SnapshotId), u64>,
    in_flight: HashMap<SnapshotId, HashSet<PeerAddress>>,
}

impl OutboundListens {
    pub(crate) fn new() -> Self {
        Self {
            offsets: HashMap::new(),
            in_flight: HashMap::new(),
        }
    }

    pub(crate) fn is_in_progress(&mut self, peer: PeerAddress, snapshot_id: SnapshotId) -> bool {
        self.in_flight
            .get(&snapshot_id)
            .map(|set| set.contains(&peer))
            .unwrap_or(false)
    }

    pub(crate) fn begin_forward(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) {
        self.in_flight
            .entry(snapshot_id)
            .or_default()
            .insert(peer.clone());
    }

    pub(crate) fn offset(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) -> Option<u64> {
        self.offsets.get(&(peer.clone(), snapshot_id)).copied()
    }

    pub(crate) fn complete_forward(
        &mut self,
        peer: &PeerAddress,
        snapshot_id: SnapshotId,
        new_offset: u64,
    ) {
        let offset = self.offsets.entry((peer.clone(), snapshot_id)).or_default();
        *offset = (*offset).max(new_offset);
        self.in_flight.entry(snapshot_id).or_default().remove(peer);
    }

    pub(crate) fn forward_failed(&mut self, peer: &PeerAddress, snapshot_id: SnapshotId) {
        if let Some(in_flight) = self.in_flight.get_mut(&snapshot_id) {
            in_flight.remove(peer);
        }
    }
}
