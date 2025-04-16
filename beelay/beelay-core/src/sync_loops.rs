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
    streams::{EstablishedStream, ResolvedDirection, SyncPhase},
    CommitOrBundle, DocumentId, PeerId, StreamId, TaskContext, SYNC_INTERVAL,
};

pub(crate) struct SyncLoops {
    doc_versions: HashMap<DocumentId, u64>,
    doc_events_pending_decryption: Vec<EventPendingDecryption>,
    running_sync_loops: FuturesUnordered<Pin<Box<dyn Future<Output = StreamId>>>>,
    running_uploads: FuturesUnordered<Pin<Box<dyn Future<Output = Result<(), RpcError>>>>>,

    #[allow(clippy::type_complexity)]
    running_decryptions:
        FuturesUnordered<Pin<Box<dyn Future<Output = Vec<(batch::DecryptResponse, u64)>>>>>,
}

struct EventPendingDecryption {
    doc: DocumentId,
    version_last_attempted_decryption_at: Option<u64>,
    payload: CommitOrBundle,
}

impl SyncLoops {
    pub(crate) fn new() -> Self {
        SyncLoops {
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
        for EstablishedStream {
            their_peer_id,
            direction,
            id: stream_id,
            sync_phase,
            received_sync_needed,
        } in established
        {
            let has_new_doc = !doc_changes
                .keys()
                .collect::<HashSet<_>>()
                .difference(&self.doc_versions.keys().collect::<HashSet<_>>())
                .collect::<Vec<_>>()
                .is_empty();
            let should_start_sync = {
                if direction == ResolvedDirection::Accepting {
                    false
                } else if has_new_doc {
                    tracing::trace!(%their_peer_id, "beginning new sync loop as we have new documents");
                    true
                } else if received_sync_needed {
                    tracing::trace!(%their_peer_id, "beginning new sync loop as they have sent us a syncneeded message");
                    ctx.state().streams().clear_received_sync_needed(stream_id);
                    true
                } else {
                    // Start a sync if we haven't synced before, or it's been
                    // more than SYNC_INTERVAL since the last sync
                    match sync_phase {
                        SyncPhase::Listening {
                            last_synced_at: Some(last_synced_at),
                        } => ctx.now() - last_synced_at > SYNC_INTERVAL,
                        SyncPhase::Listening {
                            last_synced_at: None,
                        } => true,
                        SyncPhase::Syncing { .. } => false,
                    }
                }
            };

            if has_new_doc && direction == ResolvedDirection::Accepting {
                tracing::trace!(%their_peer_id, "sending them a syncneeded message as we are the acceptor and have new docs");
                self.running_uploads
                    .push(ctx.requests().sync_needed(stream_id.into()).boxed_local());
            }

            if should_start_sync {
                tracing::trace!(?stream_id, ?their_peer_id, "starting sync loop for stream");
                self.running_sync_loops
                    .push(sync_loop(ctx.clone(), stream_id, their_peer_id).boxed_local());
                ctx.state()
                    .streams()
                    .mark_sync_started(ctx.now(), stream_id);
            }

            // forward everything which has changed and which the remote has access
            for (doc_id, changes) in &doc_changes {
                match self.doc_versions.entry(*doc_id) {
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
                        doc: *doc_id,
                        version_last_attempted_decryption_at: None,
                        payload: c.payload.clone().into(),
                    }));

                let doc_id = *doc_id;
                let changes = changes.clone();
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
                                .upload_commits(stream_id.into(), doc_id, to_upload)
                                .await?;
                        }
                    }
                    Ok(())
                };
                self.running_uploads.push(upload_task.boxed_local());
            }
        }

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
                ctx.state().streams().mark_sync_complete(ctx.now(), stream_id);
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
    if let Err(e) = crate::sync::sync_with_peer(ctx, stream_id.into(), peer_id).await {
        tracing::error!(err=%e, "sync loop stopping due to error");
    }
    stream_id
}
