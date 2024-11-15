use futures::{pin_mut, StreamExt};

use crate::{
    blob::BlobMeta,
    effects::{RpcError, TaskEffects},
    messages::{BlobRef, Notification, TreePart, UploadItem},
    sedimentree::{self, LooseCommit},
    Commit, CommitBundle, CommitCategory, CommitOrBundle, DocEvent, SnapshotId, StorageKey,
};

pub(crate) async fn listen<R: rand::Rng + rand::CryptoRng>(
    effects: TaskEffects<R>,
    on_snapshot: SnapshotId,
    to_peer: crate::TargetNodeInfo,
) {
    let handler_effects = effects.clone();
    let notification_stream =
        futures::stream::try_unfold((effects, None), |(effects, remote_offset)| {
            let to_peer = to_peer.clone();
            async move {
                tracing::info!("making a listen request");
                let (notifications, remote_offset, from) = effects
                    .listen(to_peer.clone(), on_snapshot, remote_offset)
                    .await?;
                Ok::<_, RpcError>(Some((
                    (notifications, from),
                    (effects, Some(remote_offset)),
                )))
            }
        });
    pin_mut!(notification_stream);
    while let Some(notifications) = notification_stream.next().await {
        match notifications {
            Ok((n, from)) => {
                tracing::debug!("received notifications from remote");
                for notification in n {
                    handle(handler_effects.clone(), from, notification).await;
                }
            }
            Err(e) => {
                tracing::error!(?e, "error listening for notifications");
                break;
            }
        }
    }
}

pub(crate) async fn handle<R: rand::Rng + rand::CryptoRng>(
    mut effects: TaskEffects<R>,
    for_peer: crate::PeerId,
    notification: Notification,
) {
    tracing::debug!(?notification, "received notification");
    effects.log().remote_notification(for_peer, &notification);
    let Notification { doc, data } = notification;
    let UploadItem { blob, tree_part } = data;
    let BlobRef::Inline(blob_data) = blob else {
        panic!("blob refs in notifications not yet supported");
    };
    let data = match &tree_part {
        TreePart::Commit { hash, parents } => {
            CommitOrBundle::Commit(Commit::new(parents.clone(), blob_data.to_vec(), *hash))
        }
        TreePart::Stratum {
            start,
            end,
            checkpoints,
        } => CommitOrBundle::Bundle(
            CommitBundle::builder()
                .start(*start)
                .end(*end)
                .bundled_commits(blob_data.to_vec())
                .checkpoints(checkpoints.clone())
                .build(),
        ),
    };
    let blob = BlobMeta::new(&blob_data);
    effects
        .put(StorageKey::blob(blob.hash()), blob_data.clone())
        .await;
    let path = StorageKey::sedimentree_root(&doc, CommitCategory::Content);
    match tree_part {
        TreePart::Commit { hash, parents } => {
            let loose = LooseCommit::new(hash, parents, blob);
            sedimentree::storage::write_loose_commit(effects.clone(), path, &loose).await;
        }
        TreePart::Stratum {
            start,
            end,
            checkpoints,
        } => {
            let bundle = CommitBundle::builder()
                .start(start)
                .end(end)
                .bundled_commits(blob_data)
                .checkpoints(checkpoints)
                .build();
            sedimentree::storage::write_bundle(effects.clone(), path, bundle).await;
        }
    }
    effects.emit_doc_event(DocEvent {
        doc,
        data: data.clone(),
    });
}
