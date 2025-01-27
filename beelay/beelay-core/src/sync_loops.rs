use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    future::Future,
    pin::Pin,
};

use futures::{stream::FuturesUnordered, FutureExt, StreamExt};

use crate::{
    doc_status::DocEvent,
    network::{messages::UploadItem, RpcError},
    state::keyhive::batch,
    streams::{CompletedHandshake, ResolvedDirection},
    CommitOrBundle, DocumentId, PeerId, StreamId, TaskContext,
};

pub(crate) struct SyncLoops {
    streams: HashMap<StreamId, ConnState>,
    doc_versions: HashMap<DocumentId, u64>,
    doc_events_pending_decryption: Vec<EventPendingDecryption>,
    running_sync_loops: FuturesUnordered<Pin<Box<dyn Future<Output = StreamId>>>>,
    running_uploads: FuturesUnordered<Pin<Box<dyn Future<Output = Result<(), RpcError>>>>>,
    running_decryptions:
        FuturesUnordered<Pin<Box<dyn Future<Output = Vec<(batch::DecryptResponse, u64)>>>>>,
}

struct EventPendingDecryption {
    doc: DocumentId,
    version_last_attempted_decryption_at: Option<u64>,
    payload: CommitOrBundle,
}

enum ConnState {
    Syncing,
    Idle,
}

impl SyncLoops {
    pub(crate) fn new() -> Self {
        SyncLoops {
            streams: HashMap::new(),
            // argh! This is horrible horrible horrible
            doc_versions: HashMap::new(),
            doc_events_pending_decryption: Vec::new(),
            running_sync_loops: FuturesUnordered::new(),
            running_uploads: FuturesUnordered::new(),
            running_decryptions: FuturesUnordered::new(),
        }
    }

    /// Kick off any new sync loops based on currently connected peers
    pub(crate) fn reconcile<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
        &mut self,
        ctx: &TaskContext<R>,
    ) {
        let established = ctx.state().streams().established();
        let doc_changes = ctx.state().docs().take_doc_changes();
        if !doc_changes.is_empty() {}
        let mut missing = self.streams.keys().cloned().collect::<HashSet<_>>();
        for (
            stream_id,
            CompletedHandshake {
                their_peer_id,
                resolved_direction,
            },
        ) in established
        {
            missing.remove(&stream_id);

            // We don't start sync loops for incoming streams
            if resolved_direction != ResolvedDirection::Accepting {
                if !self.streams.contains_key(&stream_id) {
                    tracing::trace!(?stream_id, ?their_peer_id, "starting sync loop for stream");
                    self.running_sync_loops
                        .push(sync_loop(ctx.clone(), stream_id, their_peer_id).boxed_local());
                    self.streams.insert(stream_id, ConnState::Syncing);
                }
            }

            // forward everything which has changed and which the remote has access
            for (doc_id, changes) in &doc_changes {
                match self.doc_versions.entry(doc_id.clone()) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() += 1;
                        *entry.get()
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(0);
                        0
                    }
                };
                self.doc_events_pending_decryption
                    .extend(changes.iter().map(|c| EventPendingDecryption {
                        doc: doc_id.clone(),
                        version_last_attempted_decryption_at: None,
                        payload: c.payload.clone().into(),
                    }));

                let doc_id = doc_id.clone();
                let changes = changes.clone();
                let their_peer_id = their_peer_id.clone();
                let ctx = ctx.clone();
                let upload_task = async move {
                    if ctx.state().keyhive().can_pull(their_peer_id, &doc_id).await {
                        let to_upload = changes
                            .iter()
                            .filter_map(|c| {
                                if c.sender != Some(their_peer_id) {
                                    Some(c.payload.clone().into())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<UploadItem>>();
                        if !to_upload.is_empty() {
                            ctx.requests()
                                .upload_commits(stream_id.into(), doc_id.clone(), to_upload)
                                .await?;
                        }
                    }
                    Ok(())
                };
                self.running_uploads.push(upload_task.boxed_local());
            }
        }
        self.streams.retain(|k, _v| !missing.contains(k));

        let mut next_decryption_batch = Vec::new();
        for evt in std::mem::take(&mut self.doc_events_pending_decryption) {
            let doc_version = self.doc_versions.get(&evt.doc).expect("we just set this!");
            if evt.version_last_attempted_decryption_at.unwrap_or(0) < *doc_version {
                next_decryption_batch.push((
                    batch::DecryptRequest {
                        doc_id: evt.doc,
                        payload: evt.payload,
                    },
                    *doc_version,
                ));
            } else {
                self.doc_events_pending_decryption.push(evt);
            }
        }

        if !next_decryption_batch.is_empty() {
            let decrypt_ctx = ctx.clone();
            let decryption_task = async move {
                let (decrypt_batch, versions) = next_decryption_batch
                    .into_iter()
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                let results = decrypt_ctx
                    .state()
                    .keyhive()
                    .decrypt_batch(decrypt_batch)
                    .await;
                results.into_iter().zip(versions).collect()
            };
            self.running_decryptions.push(decryption_task.boxed_local());
        }
    }

    /// Drive currently running sync loops
    pub(crate) async fn process_pending<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        ctx: &TaskContext<R>,
    ) {
        if self.running_sync_loops.is_empty()
            && self.running_uploads.is_empty()
            && self.running_decryptions.is_empty()
        {
            // `process_pending` is called inside a sync loop, so here we have to just wait until this future is dropped
            futures::future::pending::<()>().await;
        }
        futures::select! {
            stream_id = self.running_sync_loops.select_next_some() => {
                tracing::trace!(?stream_id, "sync loop completed");
                self.streams.insert(stream_id, ConnState::Idle);
            }
            _ = self.running_uploads.select_next_some() => {
                tracing::trace!("upload completed");
            }
            decryption_complete = self.running_decryptions.select_next_some() => {
                for (result, doc_version) in decryption_complete {
                    match result {
                        batch::DecryptResponse::Success(doc_id, data) => {
                            tracing::trace!("decryption succeeded");
                            ctx.io().new_doc_event(doc_id, DocEvent::Data { data })
                        },
                        batch::DecryptResponse::Corrupted(doc_id) => {
                            tracing::warn!(%doc_id, "data for document was corrupted");
                        },
                        batch::DecryptResponse::TryLater(doc_id, content) => {
                            tracing::trace!(%doc_id, "decryption failed, retrying later");
                            self.doc_events_pending_decryption.push(EventPendingDecryption {
                                doc: doc_id,
                                version_last_attempted_decryption_at: Some(doc_version),
                                payload: content
                            })
                        }
                    }
                }
            }
        }
    }
}

async fn sync_loop<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    stream_id: StreamId,
    peer_id: PeerId,
) -> StreamId {
    crate::sync::sync_with_peer(ctx, stream_id.into(), peer_id)
        .await
        .unwrap();
    stream_id
}

// fn decrypt_commit_or_bundle<R: rand::Rng + rand::CryptoRng>(
//     ctx: &TaskContext<R>,
//     doc_id: DocumentId,
//     commit_or_bundle: CommitOrBundle,
// ) -> Option<CommitOrBundle> {
//     match commit_or_bundle {
//         CommitOrBundle::Commit(c) => {
//             let decrypted = match ctx.state().keyhive().decrypt(
//                 doc_id,
//                 c.parents(),
//                 c.hash(),
//                 c.contents().to_vec(),
//             ) {
//                 Ok(d) => d,
//                 Err(e) => {
//                     tracing::warn!(err=?e, "failed to decrypt commit");
//                     return None;
//                 }
//             };
//             let commit = Commit::new(c.parents().to_vec(), decrypted, c.hash());
//             Some(CommitOrBundle::Commit(commit))
//         }
//         CommitOrBundle::Bundle(s) => {
//             let decrypted = match ctx.state().keyhive().decrypt(
//                 doc_id,
//                 &[s.start()],
//                 *s.hash(),
//                 s.bundled_commits().to_vec(),
//             ) {
//                 Ok(d) => d,
//                 Err(e) => {
//                     tracing::warn!(err=?e, "failed to decrypt bundle");
//                     return None;
//                 }
//             };
//             let bundle = CommitBundle::builder()
//                 .start(s.start())
//                 .end(s.end())
//                 .checkpoints(s.checkpoints().to_vec())
//                 .bundled_commits(decrypted)
//                 .build();
//             Some(CommitOrBundle::Bundle(bundle))
//         }
//     }
// }
