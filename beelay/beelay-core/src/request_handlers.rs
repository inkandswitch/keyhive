use std::sync::Arc;

use futures::FutureExt;
use keyhive_core::principal::identifier::Identifier;

use crate::{
    auth,
    blob::BlobMeta,
    keyhive_sync::{self, KeyhiveSyncId},
    log::Source,
    network::messages::{self, BlobRef, ContentAndLinks, FetchedSedimentree, TreePart, UploadItem},
    riblt,
    sedimentree::{self, LooseCommit},
    snapshots::{self, Snapshot},
    state::{RpcError, TaskContext},
    sync_docs, Audience, Commit, CommitBundle, CommitCategory, CommitHash, CommitOrBundle,
    DocumentId, OutgoingResponse, PeerId, Response, SnapshotId, StorageKey,
};

#[derive(Debug, thiserror::Error)]
#[error("auth failed")]
pub struct AuthenticationFailed;

#[tracing::instrument(skip(ctx, request, receive_audience), fields(from_peer))]
pub(super) async fn handle_request<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    request: auth::Signed<auth::Message>,
    receive_audience: Option<String>,
) -> Result<OutgoingResponse, AuthenticationFailed> {
    let recv_aud = receive_audience.map(Audience::service_name);
    let (request, from) = match ctx.auth().authenticate_received_msg(request, recv_aud) {
        Ok(authed) => (authed.content, PeerId::from(authed.from)),
        Err(e) => {
            tracing::debug!(err=?e, "failed to authenticate incoming message");
            return Err(AuthenticationFailed);
        }
    };
    tracing::Span::current().record("from_peer", from.to_string());
    let response = match request {
        crate::Request::UploadCommits {
            doc,
            data,
            category,
        } => {
            tracing::debug!(doc=%doc, "upload commits");
            if !ctx.keyhive().can_write(from, &doc) {
                tracing::trace!("not authorized to write to doc");
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::AuthorizationFailed,
                });
            }
            upload_commits(ctx, from, doc, data, category).await;
            Response::UploadCommits
        }
        crate::Request::FetchSedimentree(doc_id) => {
            tracing::debug!(doc=%doc_id, "fetch sedimentree");
            if !ctx.keyhive().can_pull(from, &doc_id) {
                tracing::trace!("not authorized to read doc");
                // TODO: Return an empty response rather than an authorization failure?
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::AuthorizationFailed,
                });
            }
            let trees = fetch_sedimentree(ctx, doc_id).await;
            Response::FetchSedimentree(trees)
        }
        crate::Request::FetchBlobPart {
            blob,
            offset,
            length,
        } => {
            tracing::debug!("fetch blob part");
            // TODO: Scope the fetchblob by document ID so we can check permissions
            match ctx.storage().load(StorageKey::blob(blob)).await {
                None => Response::Error("no such blob".to_string()),
                Some(data) => {
                    let offset = offset as usize;
                    let length = length as usize;
                    Response::FetchBlobPart(data[offset..offset + length].to_vec())
                }
            }
        }
        crate::Request::UploadBlob(_vec) => todo!(),
        crate::Request::CreateSnapshot {
            root_doc,
            source_snapshot,
        } => {
            tracing::debug!(%root_doc, "create snapshot");
            let (snapshot_id, first_symbols) =
                create_snapshot(ctx, from, source_snapshot, root_doc).await;
            Response::CreateSnapshot {
                snapshot_id,
                first_symbols,
            }
        }
        crate::Request::SnapshotSymbols { snapshot_id } => {
            tracing::debug!("snapshot symbols");
            if let Some(symbols) = ctx.snapshots().next_snapshot_symbols(snapshot_id, 100) {
                Response::SnapshotSymbols(symbols)
            } else {
                Response::Error("no such snapshot".to_string())
            }
        }
        crate::Request::Listen(snapshot_id, from_offset) => {
            tracing::debug!(%snapshot_id, ?from_offset, "listen");
            let result = handle_listen(ctx, from, snapshot_id, from_offset).await;
            match result {
                Ok((events, remote_offset)) => Response::Listen {
                    notifications: events,
                    remote_offset,
                },
                Err(e) => Response::Error(e.to_string()),
            }
        }
        messages::Request::BeginAuthSync { additional_peers } => {
            tracing::debug!("begin auth sync");
            let (session_id, first_symbols) = ctx
                .keyhive()
                .new_keyhive_sync_session(from, additional_peers);
            Response::BeginAuthSync {
                session_id,
                first_symbols,
            }
        }
        messages::Request::KeyhiveSymbols { session_id } => {
            tracing::debug!(%session_id, "keyhive symbols");
            if let Some(symbols) = ctx.keyhive().next_n_keyhive_sync_symbols(session_id, 100) {
                Response::KeyhiveSymbols(symbols)
            } else {
                Response::Error("no such session".to_string())
            }
        }
        messages::Request::RequestKeyhiveOps { session, op_hashes } => {
            tracing::debug!(%session, "keyhive ops");
            let ops = ctx
                .keyhive()
                .get_keyhive_ops(session, op_hashes.into_iter().map(|o| o.into()).collect());
            Response::RequestKeyhiveOps(ops)
        }
        messages::Request::UploadKeyhiveOps {
            source_session,
            ops,
        } => {
            tracing::debug!(%source_session, "upload keyhive ops");
            ctx.keyhive()
                .apply_keyhive_events(ops.clone())
                .expect("FIXME");
            if !ctx.keyhive().has_forwarded_session(source_session) {
                tracing::trace!("uploading ops to forwarding peers");
                ctx.keyhive().track_forwarded_session(source_session);
                let forwarding_peers = ctx.forwarding_peers();
                let upload_tasks = forwarding_peers.into_iter().filter_map({
                    let ctx = ctx.clone();
                    move |peer| {
                        if peer.is_source_of(&from) {
                            None
                        } else {
                            Some(ctx.requests().upload_keyhive_ops(
                                peer,
                                ops.clone(),
                                source_session,
                            ))
                        }
                    }
                });
                futures::future::join_all(upload_tasks).await;
                ctx.keyhive().untrack_forwarded_session(source_session);
            }
            Response::UploadKeyhiveOps
        }
        messages::Request::Ping => {
            tracing::debug!("ping");
            Response::Pong
        }
    };
    Ok(OutgoingResponse {
        audience: Audience::peer(&from),
        response,
    })
}

async fn fetch_sedimentree<R: rand::Rng + rand::CryptoRng>(
    ctx: crate::state::TaskContext<R>,
    doc_id: DocumentId,
) -> FetchedSedimentree {
    let content_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
    let reachability_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Links);

    let content = crate::sedimentree::storage::load(ctx.clone(), content_root);
    let links = crate::sedimentree::storage::load(ctx, reachability_root);
    let (content, links) = futures::future::join(content, links).await;
    match (content, links) {
        (None, _) => FetchedSedimentree::NotFound,
        (Some(content), links) => FetchedSedimentree::Found(ContentAndLinks {
            content: content.minimize().summarize(),
            links: links.map(|i| i.minimize().summarize()).unwrap_or_default(),
        }),
    }
}

#[tracing::instrument(skip(ctx, from_peer), fields(from_peer = %from_peer))]
async fn upload_commits<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    from_peer: PeerId,
    doc: DocumentId,
    data: Vec<UploadItem>,
    content: CommitCategory,
) {
    tracing::trace!("handling upload");
    let tasks = data.into_iter().map(|d| {
        let mut ctx = ctx.clone();
        async move {
            if ctx.log().has_item(&d) {
                tracing::debug!("we recently handled this upload, skipping");
                return;
            }
            let (blob, data) = match d.blob.clone() {
                BlobRef::Blob(b) => {
                    let data = ctx.storage().load(StorageKey::blob(b)).await;
                    let Some(data) = data else {
                        tracing::error!("no such blob");
                        // TODO: return an error
                        panic!("no such blob")
                    };
                    (BlobMeta::new(&data), data)
                }
                BlobRef::Inline(contents) => {
                    let blob = BlobMeta::new(&contents);
                    ctx.storage()
                        .put(StorageKey::blob(blob.hash()), contents.clone())
                        .await;
                    (blob, contents)
                }
            };
            ctx.log()
                .new_remote_commit(doc, from_peer, d.clone(), content);
            tracing::trace!("stored uploaded blobs, emitting event");
            ctx.emit_doc_event(crate::DocEvent {
                doc,
                data: match d.tree_part {
                    TreePart::Commit { hash, ref parents } => {
                        CommitOrBundle::Commit(Commit::new(parents.clone(), data.clone(), hash))
                    }
                    TreePart::Stratum {
                        start,
                        end,
                        ref checkpoints,
                    } => CommitOrBundle::Bundle(
                        CommitBundle::builder()
                            .start(start)
                            .end(end)
                            .checkpoints(checkpoints.clone())
                            .bundled_commits(data.clone())
                            .build(),
                    ),
                },
            });
            for peer in ctx.forwarding_peers() {
                if peer.is_source_of(&from_peer) {
                    continue;
                }
                // FIXME: We should centralize this silly ping business
                let peer_id = match peer.last_known_peer_id {
                    Some(peer_id) => peer_id,
                    None => {
                        tracing::trace!("no known peer id, pinging");
                        ctx.requests().ping(peer.clone()).await.unwrap()
                    }
                };
                tracing::trace!(to_peer=%peer_id, "forwarding uploaded commits");
                let ctx = ctx.clone();
                let d = d.clone();
                ctx.spawn(move |ctx| async move {
                    keyhive_sync::sync_keyhive(ctx.clone(), peer.clone(), Vec::new()).await;
                    if !ctx.keyhive().can_pull(peer_id, &doc) {
                        tracing::trace!("not forwarding to peer without access");
                        return;
                    }
                    if let Err(e) = ctx
                        .requests()
                        .upload_commits(peer, doc, vec![d], content)
                        .await
                    {
                        tracing::warn!(err=?e, "error forwarding upload to peer");
                    }
                })
            }
            match d.tree_part {
                TreePart::Commit { hash, parents } => {
                    let commit = LooseCommit::new(hash, parents, blob);
                    sedimentree::storage::write_loose_commit(
                        ctx.clone(),
                        StorageKey::sedimentree_root(&doc, content),
                        &commit,
                    )
                    .await;
                }
                TreePart::Stratum {
                    start,
                    end,
                    checkpoints,
                } => {
                    let bundle = CommitBundle::builder()
                        .start(start)
                        .end(end)
                        .checkpoints(checkpoints)
                        .bundled_commits(data)
                        .build();
                    sedimentree::storage::write_bundle(
                        ctx.clone(),
                        StorageKey::sedimentree_root(&doc, content),
                        bundle,
                    )
                    .await;
                }
            }
        }
    });
    futures::future::join_all(tasks).await;
}

async fn create_snapshot<R: rand::Rng + rand::CryptoRng + 'static>(
    mut ctx: crate::state::TaskContext<R>,
    requestor: crate::PeerId,
    source_snapshot: SnapshotId,
    root_doc: DocumentId,
) -> (
    snapshots::SnapshotId,
    Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>,
) {
    if ctx
        .snapshots()
        .we_have_snapshot_with_source(source_snapshot)
    {
        tracing::debug!("forwarding loop detected, returning empty snapshot");
        // We're in a forward loop, create an empty snapshot and return
        // TODO: Actually handle this properly
        let empty = snapshots::Snapshot::empty(&mut ctx, root_doc, Some(source_snapshot));
        let empty = ctx.snapshots().store_snapshot(empty);
        let symbols = ctx
            .snapshots()
            .next_snapshot_symbols(empty.id(), 10)
            .expect("symbols should exist");
        return (empty.id(), symbols);
    }

    let snapshot = snapshots::Snapshot::load(
        ctx.clone(),
        Some(requestor),
        root_doc,
        Some(source_snapshot),
    )
    .await;
    let mut snapshot = ctx.snapshots().store_snapshot(snapshot);

    let mut nodes_to_ask = ctx.forwarding_peers();
    nodes_to_ask.retain(|n| !n.is_source_of(&requestor));
    if !nodes_to_ask.is_empty() {
        if tracing::enabled!(tracing::Level::TRACE) {
            let nodes_to_ask = nodes_to_ask
                .iter()
                .map(|n| n.audience().to_string())
                .collect::<Vec<_>>();
            tracing::trace!(?nodes_to_ask, %requestor, "asking remote peers");
        } else {
            tracing::debug!(%requestor, "asking remote peers");
        }
        let syncing = nodes_to_ask.into_iter().map(|c| {
            let fut = sync_docs::sync_root_doc(ctx.clone(), &snapshot, c.clone());
            fut.map(move |r| (c, r))
        });
        let forwarded = futures::future::join_all(syncing).await;
        let mut reloaded_snapshot = snapshots::Snapshot::load(
            ctx.clone(),
            Some(requestor),
            root_doc,
            Some(source_snapshot),
        )
        .await;
        for (peer, sync_result) in forwarded {
            match sync_result {
                Ok(sync_result) => {
                    reloaded_snapshot.add_remote(peer, sync_result.remote_snapshot);
                }
                Err(e) => {
                    tracing::warn!(err=?e, "error forwarding create snapshot to remote");
                }
            }
        }
        snapshot = ctx.snapshots().store_snapshot(reloaded_snapshot);
        tracing::trace!(we_have_doc=%snapshot.we_have_doc(), "finished requesting missing doc from peers");
    } else {
        tracing::trace!("no peers to ask");
    }

    if !ctx.keyhive().can_pull(requestor, &root_doc) {
        tracing::debug!("peer not authorized to read root doc, returning empty");
        // TODO: Have an actual empty response
        let empty = snapshots::Snapshot::empty(&mut ctx, root_doc, Some(source_snapshot));
        let empty = ctx.snapshots().store_snapshot(empty);
        let symbols = ctx
            .snapshots()
            .next_snapshot_symbols(empty.id(), 10)
            .expect("symbols should exist");
        return (empty.id(), symbols);
    }

    let snapshot_id = snapshot.id();
    let first_symbols = ctx
        .snapshots()
        .next_snapshot_symbols(snapshot_id, 10)
        .expect("symbols exist");
    (snapshot_id, first_symbols)
}

async fn handle_listen<R: rand::Rng + rand::CryptoRng + 'static>(
    mut ctx: crate::state::TaskContext<R>,
    from_peer: PeerId,
    on_snapshot: SnapshotId,
    from_offset: Option<u64>,
) -> Result<(Vec<messages::Notification>, u64), RpcError> {
    let snapshot = ctx
        .snapshots()
        .lookup_snapshot(on_snapshot)
        .ok_or_else(|| RpcError::ErrorReported("No such snapshot".to_string()))?;

    ensure_forwarded_listens(ctx.clone(), &from_peer, snapshot.clone());

    // Check local log
    let local_entries = ctx
        .log()
        .entries_for(&snapshot, from_offset)
        .into_iter()
        .filter(|e| e.source != Source::Remote(from_peer))
        .collect::<Vec<_>>();
    if !local_entries.is_empty() {
        return Ok((
            local_entries_to_notifications(local_entries),
            ctx.log().offset() as u64,
        ));
    }

    // If no local entries, wait for new ones
    let mut stopping = ctx.stopping().fuse();
    loop {
        ensure_forwarded_listens(ctx.clone(), &from_peer, snapshot.clone());
        futures::select! {
            _ = ctx.wait_for_new_log_entries().fuse() => {
                let new_entries = ctx
                    .log()
                    .entries_for(&snapshot, from_offset);
                let filtered = new_entries
                    .into_iter()
                    .filter(|e| {
                        if e.source == Source::Remote(from_peer) {
                            return false;
                        }
                        if !ctx.keyhive().can_pull(from_peer, &e.doc) {
                            return false;
                        }
                        return true
                    })
                    .collect::<Vec<_>>();
                if !filtered.is_empty() {
                    return Ok((
                        local_entries_to_notifications(filtered),
                        ctx.log().offset() as u64,
                    ));
                }
            },
            _ = stopping => {
                tracing::trace!("beelay is stopping, returning empty from listen request");
                return Ok((vec![], 0));
            }
        }
    }
}

fn local_entries_to_notifications(
    entries: Vec<crate::log::DocEvent>,
) -> Vec<messages::Notification> {
    entries
        .into_iter()
        .map(|e| messages::Notification {
            doc: e.doc,
            data: e.contents,
        })
        .collect()
}

// Ensure that for a given snapshot there are in-flight listen requests to all forwarding targets
fn ensure_forwarded_listens<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    from_peer: &PeerId,
    snapshot: Arc<Snapshot>,
) {
    let forward_targets = snapshot
        .remote_snapshots()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    for (target, remote_snapshot_id) in forward_targets {
        if !target.is_source_of(from_peer) {
            if !ctx
                .forwarded_listens()
                .is_in_progress(target.target.clone(), remote_snapshot_id)
            {
                tracing::trace!(to=%target, snapshot=%snapshot.id(), %remote_snapshot_id, "forwarding listen request");
                ctx.forwarded_listens()
                    .begin_forward(&target.target, remote_snapshot_id);
                let ctx = ctx.clone();
                ctx.spawn(move |ctx| async move {
                    let listen_req = ctx.requests().listen(
                        target.clone(),
                        remote_snapshot_id,
                        ctx.forwarded_listens()
                            .offset(&target.target, remote_snapshot_id),
                    );
                    let (notifications, new_offset, notifying_peer) = futures::select! {
                        response = listen_req.fuse() => {
                                match response {
                                    Ok(r) => r,
                                    Err(e) => {
                                        tracing::error!(err=?e, "error forwarding listen request");
                                        ctx
                                            .forwarded_listens()
                                            .forward_failed(&target.target, remote_snapshot_id);
                                        return;
                                    }
                                }
                            }
                        _ = ctx.stopping().fuse() => {
                            tracing::trace!("stop in forwarded listen");
                            return;
                        }
                    };

                    for notification in notifications {
                        crate::listen::persist_listen_event(
                            ctx.clone(),
                            notifying_peer,
                            notification,
                        )
                        .await;
                    }
                    ctx.forwarded_listens().complete_forward(
                        &target.target,
                        remote_snapshot_id,
                        new_offset,
                    );
                });
            }
        }
    }
}
