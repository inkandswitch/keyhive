use futures::{pin_mut, FutureExt};

use crate::{
    blob::BlobMeta,
    effects::RpcError,
    log::Source,
    messages::{BlobRef, ContentAndLinks, FetchedSedimentree, TreePart, UploadItem},
    riblt::doc_and_heads::CodedDocAndHeadsSymbol,
    sedimentree::{self, LooseCommit},
    snapshots, sync_docs, Audience, Commit, CommitBundle, CommitCategory, CommitOrBundle,
    DocumentId, OutgoingResponse, PeerId, Response, SnapshotId, StorageKey,
};

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub(crate) enum RequestSource {
    Stream(crate::StreamId, crate::connection::ConnRequestId),
    Command(crate::InboundRequestId),
}

pub(super) async fn handle_request<R: rand::Rng + rand::CryptoRng + 'static>(
    effects: crate::effects::TaskEffects<R>,
    source: RequestSource,
    from: PeerId,
    request: crate::Request,
) -> OutgoingResponse {
    let response = match request {
        crate::Request::UploadCommits {
            doc,
            data,
            category,
        } => {
            if !effects.can_write(from, &doc) {
                return OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error("not authorized".to_string()),
                    responding_to: source,
                };
            }
            upload_commits(effects, from, doc, data, category).await;
            Response::UploadCommits
        }
        crate::Request::FetchSedimentree(doc_id) => {
            if !effects.can_read(from, &doc_id) {
                // TODO: Return an empty response rather than an error
                return OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error("not authorized".to_string()),
                    responding_to: source,
                };
            }
            let trees = fetch_sedimentree(effects, doc_id).await;
            Response::FetchSedimentree(trees)
        }
        crate::Request::FetchBlobPart {
            blob,
            offset,
            length,
        } => {
            // TODO: Scope the fetchblob by document ID so we can check permissions
            match effects.load(StorageKey::blob(blob)).await {
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
            let (snapshot_id, first_symbols) =
                create_snapshot(effects, from, source_snapshot, root_doc).await;
            Response::CreateSnapshot {
                snapshot_id,
                first_symbols,
            }
        }
        crate::Request::SnapshotSymbols { snapshot_id } => {
            if let Some(symbols) = effects.next_snapshot_symbols(snapshot_id, 100) {
                Response::SnapshotSymbols(symbols)
            } else {
                Response::Error("no such snapshot".to_string())
            }
        }
        crate::Request::Listen(snapshot_id, from_offset) => {
            let result = handle_listen(effects, from, snapshot_id, from_offset).await;
            match result {
                Ok((events, remote_offset)) => Response::Listen {
                    notifications: events,
                    remote_offset,
                },
                Err(e) => Response::Error(e.to_string()),
            }
        }
    };
    OutgoingResponse {
        audience: Audience::peer(&from),
        response,
        responding_to: source,
    }
}

async fn fetch_sedimentree<R: rand::Rng + rand::CryptoRng>(
    effects: crate::effects::TaskEffects<R>,
    doc_id: DocumentId,
) -> FetchedSedimentree {
    let content_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
    let reachability_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Links);

    let content = crate::sedimentree::storage::load(effects.clone(), content_root);
    let links = crate::sedimentree::storage::load(effects, reachability_root);
    let (content, links) = futures::future::join(content, links).await;
    match (content, links) {
        (None, _) => FetchedSedimentree::NotFound,
        (Some(content), links) => FetchedSedimentree::Found(ContentAndLinks {
            content: content.minimize().summarize(),
            links: links.map(|i| i.minimize().summarize()).unwrap_or_default(),
        }),
    }
}

#[tracing::instrument(skip(effects, from_peer), fields(from_peer = %from_peer))]
async fn upload_commits<R: rand::Rng + rand::CryptoRng + 'static>(
    effects: crate::effects::TaskEffects<R>,
    from_peer: PeerId,
    doc: DocumentId,
    data: Vec<UploadItem>,
    content: CommitCategory,
) {
    tracing::trace!("handling upload");
    let tasks = data.into_iter().map(|d| {
        let mut effects = effects.clone();
        async move {
            if effects.log().has_item(&d) {
                tracing::debug!("we recently handled this upload, skipping");
                return;
            }
            let (blob, data) = match d.blob.clone() {
                BlobRef::Blob(b) => {
                    let data = effects.load(StorageKey::blob(b)).await;
                    let Some(data) = data else {
                        tracing::error!("no such blob");
                        // TODO: return an error
                        panic!("no such blob")
                    };
                    (BlobMeta::new(&data), data)
                }
                BlobRef::Inline(contents) => {
                    let blob = BlobMeta::new(&contents);
                    effects
                        .put(StorageKey::blob(blob.hash()), contents.clone())
                        .await;
                    (blob, contents)
                }
            };
            effects
                .log()
                .new_remote_commit(doc, from_peer, d.clone(), content);
            tracing::trace!("stored uploaded blobs, emitting event");
            effects.emit_doc_event(crate::DocEvent {
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
            for peer in effects.who_should_i_ask(doc) {
                if !peer.is_source_of(&from_peer) {
                    let effects = effects.clone();
                    let d = d.clone();
                    effects.spawn(move |effects| async move {
                        if let Err(e) = effects.upload_commits(peer, doc, vec![d], content).await {
                            tracing::warn!(err=?e, "error forwarding upload to peer");
                        }
                    })
                }
            }
            match d.tree_part {
                TreePart::Commit { hash, parents } => {
                    let commit = LooseCommit::new(hash, parents, blob);
                    sedimentree::storage::write_loose_commit(
                        effects.clone(),
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
                        effects.clone(),
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

async fn create_snapshot<R: rand::Rng + rand::CryptoRng>(
    mut effects: crate::effects::TaskEffects<R>,
    requestor: crate::PeerId,
    source_snapshot: SnapshotId,
    root_doc: DocumentId,
) -> (snapshots::SnapshotId, Vec<CodedDocAndHeadsSymbol>) {
    if effects.we_have_snapshot_with_source(source_snapshot) {
        tracing::debug!("forwarding loop detected, returning empty snapshot");
        // We're in a forward loop, create an empty snapshot and return
        // TODO: Actually handle this properly
        let empty = snapshots::Snapshot::empty(&mut effects, root_doc, Some(source_snapshot));
        let empty = effects.store_snapshot(empty);
        let symbols = effects
            .next_snapshot_symbols(empty.id(), 10)
            .expect("symbols should exist");
        return (empty.id(), symbols);
    }

    let snapshot = snapshots::Snapshot::load(
        effects.clone(),
        Some(requestor),
        root_doc,
        Some(source_snapshot),
    )
    .await;
    let mut snapshot = effects.store_snapshot(snapshot);

    let mut nodes_to_ask = effects.who_should_i_ask(root_doc);
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
            let fut = sync_docs::sync_root_doc(effects.clone(), &snapshot, c.clone());
            fut.map(move |r| (c, r))
        });
        let forwarded = futures::future::join_all(syncing).await;
        let mut reloaded_snapshot = snapshots::Snapshot::load(
            effects.clone(),
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
        snapshot = effects.store_snapshot(reloaded_snapshot);
        tracing::trace!(we_have_doc=%snapshot.we_have_doc(), "finished requesting missing doc from peers");
    } else {
        tracing::trace!("no peers to ask");
    }

    let snapshot_id = snapshot.id();
    let first_symbols = effects
        .next_snapshot_symbols(snapshot_id, 10)
        .expect("symbols exist");
    (snapshot_id, first_symbols)
}

async fn handle_listen<R: rand::Rng + rand::CryptoRng>(
    mut effects: crate::effects::TaskEffects<R>,
    from_peer: PeerId,
    on_snapshot: SnapshotId,
    from_offset: Option<u64>,
) -> Result<(Vec<crate::messages::Notification>, u64), RpcError> {
    let snapshot = effects
        .lookup_snapshot(on_snapshot)
        .ok_or_else(|| RpcError::ErrorReported("No such snapshot".to_string()))?;

    effects.ensure_forwarded_listen(from_peer, snapshot.clone());

    // Check local log
    let local_entries = effects
        .log()
        .entries_for(&snapshot, from_offset)
        .into_iter()
        .filter(|e| e.source != Source::Remote(from_peer))
        .collect::<Vec<_>>();
    if !local_entries.is_empty() {
        return Ok((
            local_entries_to_notifications(local_entries),
            effects.log().offset() as u64,
        ));
    }

    // If no local entries, wait for new ones
    let stopping = effects.stopping().fuse();
    pin_mut!(stopping);
    let new_entries = loop {
        futures::select! {
            new_entries = effects.new_local_log_entries(snapshot.clone()).fuse() => {
                tracing::trace!(?new_entries, "checking local log");
                let new_entries = new_entries
                    .into_iter()
                    .filter(|e| e.source != Source::Remote(from_peer))
                    .collect::<Vec<_>>();
                if !new_entries.is_empty() {
                    break new_entries;
                }
            },
            _ = stopping => {
                tracing::trace!("beelay is stopping, returning empty from listen request");
                break vec![];
            }
        }
    };

    Ok((
        local_entries_to_notifications(new_entries),
        effects.log().offset() as u64,
    ))
}

fn local_entries_to_notifications(
    entries: Vec<crate::log::DocEvent>,
) -> Vec<crate::messages::Notification> {
    entries
        .into_iter()
        .map(|e| crate::messages::Notification {
            doc: e.doc,
            data: e.contents,
        })
        .collect()
}
