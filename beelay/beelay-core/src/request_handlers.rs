use crate::{
    blob::BlobMeta,
    messages::{BlobRef, ContentAndIndex, FetchedSedimentree, TreePart, UploadItem},
    riblt::{self, doc_and_heads::CodedDocAndHeadsSymbol},
    sedimentree::{self, LooseCommit},
    snapshots,
    subscriptions::Subscription,
    sync_docs, CommitBundle, CommitCategory, DocumentId, OutgoingResponse, PeerId, RequestId,
    Response, StorageKey,
};

pub(super) async fn handle_request<R: rand::Rng>(
    mut effects: crate::effects::TaskEffects<R>,
    from: PeerId,
    req_id: RequestId,
    request: crate::Request,
) -> Option<OutgoingResponse> {
    let response = match request {
        crate::Request::UploadCommits {
            doc,
            data,
            category,
        } => {
            upload_commits(effects, from.clone(), doc, data, category).await;
            Response::UploadCommits
        }
        crate::Request::FetchSedimentree(doc_id) => {
            let trees = fetch_sedimentree(effects, doc_id).await;
            Response::FetchSedimentree(trees)
        }
        crate::Request::FetchBlobPart {
            blob,
            offset,
            length,
        } => match effects.load(StorageKey::blob(blob)).await {
            None => Response::Error("no such blob".to_string()),
            Some(data) => {
                let offset = offset as usize;
                let length = length as usize;
                Response::FetchBlobPart(data[offset..offset + length].to_vec())
            }
        },
        crate::Request::UploadBlob(_vec) => todo!(),
        crate::Request::CreateSnapshot { root_doc } => {
            let (snapshot_id, first_symbols) =
                create_snapshot(effects, from.clone(), root_doc).await;
            Response::CreateSnapshot {
                snapshot_id,
                first_symbols,
            }
        }
        crate::Request::SnapshotSymbols { snapshot_id } => {
            if let Some((_, encoder)) = effects.snapshots_mut().get_mut(&snapshot_id) {
                Response::SnapshotSymbols(encoder.next_n_symbols(100))
            } else {
                Response::Error("no such snapshot".to_string())
            }
        }
        crate::Request::Listen(snapshot_id) => {
            let sub = effects
                .snapshots_mut()
                .get(&snapshot_id)
                .map(|(s, _)| Subscription::new(&from, s));
            let remote_snapshots = effects
                .snapshots()
                .get(&snapshot_id)
                .map(|(s, _)| {
                    s.remote_snapshots()
                        .iter()
                        .map(|(p, s)| (p.clone(), s.clone()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let do_listen = remote_snapshots.into_iter().map(|(remote_peer, remote_snapshot)| {
               tracing::trace!(source_remote_peer=%from, target_remote_peer=%remote_peer, %remote_snapshot, "forwarding listen request");
               effects.listen(remote_peer, remote_snapshot)
            });
            futures::future::join_all(do_listen).await;
            if let Some(sub) = sub {
                effects.subscriptions().add(sub);
                Response::Listen
            } else {
                Response::Error(format!("no such snapshot"))
            }
        }
    };
    Some(OutgoingResponse {
        target: from,
        id: req_id,
        response,
    })
}

async fn fetch_sedimentree<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    doc_id: DocumentId,
) -> FetchedSedimentree {
    let content_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
    let reachability_root = StorageKey::sedimentree_root(&doc_id, CommitCategory::Index);

    let content = crate::sedimentree::storage::load(effects.clone(), content_root);
    let index = crate::sedimentree::storage::load(effects, reachability_root);
    let (content, index) = futures::future::join(content, index).await;
    match (content, index) {
        (None, _) => FetchedSedimentree::NotFound,
        (Some(content), index) => FetchedSedimentree::Found(ContentAndIndex {
            content: content.minimize().summarize(),
            index: index.map(|i| i.minimize().summarize()).unwrap_or_default(),
        }),
    }
}

#[tracing::instrument(skip(effects))]
async fn upload_commits<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    from_peer: PeerId,
    doc: DocumentId,
    data: Vec<UploadItem>,
    content: CommitCategory,
) {
    tracing::trace!("handling upload");
    let tasks = data.into_iter().map(|d| {
        let mut effects = effects.clone();
        let from_peer = from_peer.clone();
        async move {
            let (blob, data) = match d.blob.clone() {
                BlobRef::Blob(b) => {
                    let data = effects.load(StorageKey::blob(b)).await;
                    let Some(data) = data else {
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
                .new_commit(doc.clone(), from_peer, d.clone(), content);
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

async fn create_snapshot<R: rand::Rng>(
    mut effects: crate::effects::TaskEffects<R>,
    requestor: PeerId,
    root_doc: DocumentId,
) -> (snapshots::SnapshotId, Vec<CodedDocAndHeadsSymbol>) {
    let mut snapshot = snapshots::Snapshot::load(effects.clone(), root_doc).await;

    let mut peers_to_ask = effects.who_should_i_ask(root_doc.clone()).await;
    peers_to_ask.remove(&requestor);
    if !peers_to_ask.is_empty() {
        tracing::trace!(?peers_to_ask, "asking remote peers");
        let syncing = peers_to_ask.into_iter().map(|p| async {
            let result = sync_docs::sync_root_doc(effects.clone(), &snapshot, p.clone()).await;
            (p, result)
        });
        let forwarded = futures::future::join_all(syncing).await;
        snapshot = snapshots::Snapshot::load(effects.clone(), root_doc).await;
        for (peer, sync_result) in forwarded {
            snapshot.add_remote(peer, sync_result.remote_snapshot);
        }
        tracing::trace!(we_have_doc=%snapshot.we_have_doc(), "finished requesting missing doc from peers");
    } else {
        tracing::trace!("no peers to ask");
    }

    let snapshot_id = snapshot.id();
    let mut encoder = riblt::doc_and_heads::Encoder::new(&snapshot);
    let first_symbols = encoder.next_n_symbols(10);
    effects
        .snapshots_mut()
        .insert(snapshot_id, (snapshot, encoder));
    (snapshot_id, first_symbols)
}
