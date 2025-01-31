use std::collections::{hash_map::Entry, HashMap, HashSet};

use keyhive_core::{crypto::digest::Digest, event::StaticEvent};

use crate::{documents::CommitHash, network::TargetNodeInfo, riblt, state::TaskContext, PeerId};

mod keyhive_sync_id;
pub(crate) use keyhive_sync_id::KeyhiveSyncId;
mod op_hash;
pub(crate) use op_hash::OpHash;

/// Syncs the keyhive auth graph with a peer
///
/// # Parameters
/// - `ctx`:                      The task context
/// - `peer`:                     The peer to sync with
/// - `additional_peers_to_send`: Additional peers to requests sync for beyond the
///                               ops reachable by the requesting peer. This is
///                               used to request ops about a peer we haven't
///                               seen before
#[tracing::instrument(skip(ctx, peer))]
pub(crate) async fn sync_keyhive<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    peer: TargetNodeInfo,
    additional_peers_to_send: Vec<PeerId>,
) {
    tracing::debug!("syncing keyhive auth graph");
    // start a keyhive auth sync session
    let remote_peer_id = match peer.last_known_peer_id {
        Some(p) => p,
        None => ctx.requests().ping(peer.clone()).await.unwrap(),
    };
    let additional_peers = additional_peers_to_send
        .into_iter()
        .map(|p| p.as_key().into())
        .collect::<Vec<_>>();
    let local_ops = ctx
        .keyhive()
        .keyhive_ops(*remote_peer_id.as_key(), additional_peers.clone());
    let mut decoder = riblt::Decoder::<OpHash>::new();
    for op_hash in local_ops.keys() {
        decoder.add_symbol(&OpHash::from(*op_hash));
    }
    tracing::trace!("beginning sync");
    let Ok((session_id, first_symbols)) = ctx
        .requests()
        .begin_auth_sync(peer.clone(), additional_peers)
        .await
    else {
        tracing::warn!("error begining auth sync");
        return;
    };
    for symbol in first_symbols {
        decoder.add_coded_symbol(&symbol);
        decoder.try_decode().unwrap();
        if decoder.decoded() {
            break;
        }
    }

    while !decoder.decoded() {
        let Ok(next_symbols) = ctx
            .requests()
            .keyhive_symbols(peer.clone(), session_id)
            .await
        else {
            tracing::warn!("failed to fetch symbols, exiting");
            return;
        };
        for symbol in next_symbols {
            decoder.add_coded_symbol(&symbol);
            decoder.try_decode().unwrap();
            if decoder.decoded() {
                break;
            }
        }
    }
    decoder.try_decode().unwrap();

    let to_download = decoder
        .get_remote_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect::<Vec<_>>();
    if !to_download.is_empty() {
        tracing::trace!(?to_download, "downloading ops");
        let ops = ctx
            .requests()
            .request_keyhive_ops(peer.clone(), session_id, to_download)
            .await
            .unwrap();
        ctx.keyhive().apply_keyhive_events(ops).expect("FIXME");
    } else {
        tracing::trace!("no new keyhive ops to download");
    }

    let hashes_to_upload = decoder
        .get_local_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect::<HashSet<_>>();
    if !hashes_to_upload.is_empty() {
        tracing::trace!(?hashes_to_upload, "uploading ops");
        let to_upload = hashes_to_upload
            .into_iter()
            .filter_map(|h| local_ops.get(&(h.into())).cloned())
            .collect();
        ctx.requests()
            .upload_keyhive_ops(peer, to_upload, session_id)
            .await
            .unwrap();
    } else {
        tracing::trace!("no keyhive ops to upload");
    }
}

pub(crate) async fn sync_keyhive_with_forwarding_peers<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    additional_peers_to_send: Vec<PeerId>,
) {
    let tasks = ctx.forwarding_peers().into_iter().map(|peer| {
        let ctx = ctx.clone();
        let additional_peers = additional_peers_to_send.clone();
        async move {
            sync_keyhive(ctx, peer, additional_peers).await;
        }
    });
    futures::future::join_all(tasks).await;
}

pub(crate) struct KeyhiveSyncSessions {
    sessions: HashMap<KeyhiveSyncId, Session>,
    forwarded_sessions: HashMap<KeyhiveSyncId, u64>,
}

impl KeyhiveSyncSessions {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            forwarded_sessions: HashMap::new(),
        }
    }

    pub(crate) fn new_session<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        ops: HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>>,
    ) -> (KeyhiveSyncId, Vec<riblt::CodedSymbol<OpHash>>) {
        tracing::trace!("creating new keyhive sync session");
        let session_id = KeyhiveSyncId::random(rng);
        let mut encoder = riblt::Encoder::new();
        for op_hash in ops.keys() {
            encoder.add_symbol(&OpHash::from(*op_hash));
        }
        let first_10_symbols = encoder.next_n_symbols(10);
        let session = Session { ops, encoder };
        self.sessions.insert(session_id, session);
        (session_id, first_10_symbols)
    }

    pub(crate) fn next_n_symbols(
        &mut self,
        session_id: KeyhiveSyncId,
        n: u64,
    ) -> Option<Vec<riblt::CodedSymbol<OpHash>>> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return None;
        };
        Some(session.next_n_symbols(n))
    }

    pub(crate) fn events(
        &self,
        session_id: KeyhiveSyncId,
        hashes: Vec<OpHash>,
    ) -> Vec<StaticEvent<CommitHash>> {
        let Some(session) = self.sessions.get(&session_id) else {
            return Vec::new();
        };
        session.events(hashes)
    }

    pub(crate) fn track_forwarded_session(&mut self, session: KeyhiveSyncId) {
        self.forwarded_sessions.entry(session).or_insert(1);
    }

    pub(crate) fn has_forwarded_session(&self, session: KeyhiveSyncId) -> bool {
        self.forwarded_sessions
            .get(&session)
            .map(|c| *c > 0)
            .unwrap_or(false)
    }

    pub(crate) fn untrack_forwarded_session(&mut self, session: KeyhiveSyncId) {
        match self.forwarded_sessions.entry(session) {
            Entry::Occupied(mut e) => {
                let c = e.get_mut();
                if *c == 1 {
                    e.remove();
                } else {
                    *c -= 1;
                }
            }
            Entry::Vacant(_) => {}
        }
    }
}

struct Session {
    ops: HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>>,
    encoder: riblt::Encoder<OpHash>,
}

impl Session {
    fn next_n_symbols(&mut self, n: u64) -> Vec<riblt::CodedSymbol<OpHash>> {
        self.encoder.next_n_symbols(n as u64)
    }

    fn events(&self, hashes: Vec<OpHash>) -> Vec<StaticEvent<CommitHash>> {
        hashes
            .iter()
            .filter_map(|h| self.ops.get(&Digest::from(*h)).cloned())
            .collect()
    }
}
