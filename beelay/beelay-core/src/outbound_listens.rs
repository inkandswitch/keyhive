use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::{future::LocalBoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};

use crate::{effects::TaskEffects, snapshots::Snapshot, PeerId, SnapshotId, TargetNodeInfo};

pub(crate) struct OutboundListens {
    offsets: HashMap<(TargetNodeInfo, SnapshotId), u64>,
    in_flight: HashMap<SnapshotId, HashSet<TargetNodeInfo>>,
}

impl OutboundListens {
    pub(super) fn spawn<R: rand::Rng + rand::CryptoRng + 'static>(
        effects: TaskEffects<R>,
    ) -> (
        LocalBoxFuture<'static, ()>,
        futures::channel::mpsc::UnboundedSender<Vec<InboundListen>>,
    ) {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        let fut = handle_listens(effects, rx);
        (fut.boxed_local(), tx)
    }

    pub(crate) fn new() -> Self {
        Self {
            offsets: HashMap::new(),
            in_flight: HashMap::new(),
        }
    }

    pub(crate) fn is_in_progress(&mut self, peer: TargetNodeInfo, snapshot: Arc<Snapshot>) -> bool {
        self.in_flight
            .get(&snapshot.id())
            .map(|set| set.contains(&peer))
            .unwrap_or(false)
    }

    pub(crate) fn begin_forward(&mut self, peer: &TargetNodeInfo, snapshot: &SnapshotId) {
        self.in_flight
            .entry(*snapshot)
            .or_default()
            .insert(peer.clone());
    }

    pub(crate) fn offset(&mut self, peer: &TargetNodeInfo, snapshot: &SnapshotId) -> Option<u64> {
        self.offsets.get(&(peer.clone(), *snapshot)).copied()
    }

    pub(crate) fn complete_forward(
        &mut self,
        peer: &TargetNodeInfo,
        snapshot: &SnapshotId,
        new_offset: u64,
    ) {
        let offset = self.offsets.entry((peer.clone(), *snapshot)).or_default();
        *offset = (*offset).max(new_offset);
        self.in_flight.entry(*snapshot).or_default().remove(peer);
    }
}

pub(super) struct InboundListen {
    pub(crate) from_peer: PeerId,
    pub(crate) snapshot: Arc<Snapshot>,
}

impl std::fmt::Debug for InboundListen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundListen")
            .field("from_peer", &self.from_peer.to_string())
            .field("snapshot", &self.snapshot.id())
            .finish()
    }
}

async fn handle_listens<R: rand::Rng + rand::CryptoRng>(
    effects: TaskEffects<R>,
    mut listen_requests: futures::channel::mpsc::UnboundedReceiver<Vec<InboundListen>>,
) {
    let mut outbound_listeners = OutboundListens::new();
    let mut ongoing_listen_tasks = FuturesUnordered::new();
    let mut listen_handlers = FuturesUnordered::new();

    loop {
        futures::select! {
            new_listen_requests = listen_requests.select_next_some() => {
                let snapshots = new_listen_requests.into_iter().map(|listen| listen.snapshot);
                for snapshot in snapshots {
                    if tracing::enabled!(tracing::Level::DEBUG) {
                        let remotes = snapshot.remote_snapshots().keys().map(|k| k.to_string()).collect::<Vec<_>>();
                        tracing::trace!(
                            snapshot=?snapshot.id(),
                            ?remotes,
                            "forwarding listens for snapshot"
                        );
                    }
                    for (remote, remote_id) in snapshot.remote_snapshots() {
                        let remote = remote.clone();
                        let remote_id = *remote_id;
                        if !outbound_listeners.is_in_progress(remote.clone(), snapshot.clone()) {
                            outbound_listeners.begin_forward(&remote, &snapshot.id());
                            let offset = outbound_listeners.offset(&remote, &snapshot.id());
                            let effects = effects.clone();
                            let task = async move {
                                let result = effects.listen(remote.clone(), remote_id, offset).await;
                                (remote, remote_id, result)
                            };
                            ongoing_listen_tasks.push(task);
                        }
                    }
                }
            },
            result = ongoing_listen_tasks.select_next_some() => {
                let (peer_transport, snapshot, result) = result;
                match result {
                    Ok((notifications, offset, peer)) => {
                        outbound_listeners.complete_forward(&peer_transport, &snapshot, offset);
                        for notification in notifications {
                            let task = crate::notification_handler::handle(effects.clone(), peer, notification);
                            listen_handlers.push(task);
                        }
                    },
                    Err(e) => {
                        tracing::error!(err=?e, "error in forarded listen");
                        outbound_listeners.complete_forward(&peer_transport, &snapshot, 0);
                    }
                }
            },
            _ = listen_handlers.select_next_some() => {
                tracing::trace!("listen handler complete");
            }
        }
    }
}
