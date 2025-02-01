use futures::{pin_mut, FutureExt, StreamExt};

use crate::{
    blob::BlobMeta,
    network::messages::{BlobRef, Notification, TreePart, UploadItem},
    sedimentree::{self, LooseCommit},
    state::{RpcError, TaskContext},
    Commit, CommitBundle, CommitCategory, CommitOrBundle, DocEvent, SnapshotId, StorageKey,
};

pub(crate) async fn listen<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    on_snapshot: SnapshotId,
    to_peer: crate::TargetNodeInfo,
) {
    let handler_effects = ctx.clone();
    let notification_stream =
        futures::stream::try_unfold((ctx, None), |(effects, remote_offset)| {
            let to_peer = to_peer.clone();
            async move {
                tracing::info!(?to_peer, ?on_snapshot, "making a listen request");
                let req = effects
                    .requests()
                    .listen(to_peer.clone(), on_snapshot, remote_offset);
                futures::select! {
                    resp = req.fuse() => {
                        let (notifications, remote_offset, from) = resp?;
                        Ok::<_, RpcError>(Some((
                            (notifications, from),
                            (effects, Some(remote_offset)),
                        )))
                    }
                    _ = effects.stopping().fuse() => {
                        Ok::<_, RpcError>(None)
                    }
                }
            }
        });
    pin_mut!(notification_stream);
    while let Some(notifications) = notification_stream.next().await {
        match notifications {
            Ok((n, from)) => {
                tracing::debug!("received notifications from remote");
                for notification in n {
                    persist_listen_event(handler_effects.clone(), from, notification).await;
                }
            }
            Err(e) => {
                tracing::error!(?e, "error listening for notifications");
                break;
            }
        }
    }
}

pub(crate) async fn persist_listen_event<R: rand::Rng + rand::CryptoRng>(
    mut ctx: TaskContext<R>,
    for_peer: crate::PeerId,
    notification: Notification,
) {
    tracing::debug!(?notification, "received notification");
    ctx.log().remote_notification(for_peer, &notification);
    let Notification { doc, data } = notification;
    let UploadItem { blob, tree_part } = data;
    let BlobRef::Inline(blob_data) = blob else {
        panic!("blob refs in notifications not yet supported");
    };
    let decrypted_data = match &tree_part {
        TreePart::Commit { hash, parents } => {
            let Ok(decrypted) =
                ctx.keyhive()
                    .decrypt(doc.clone(), &parents, *hash, blob_data.clone())
            else {
                tracing::warn!("unable to decrypt");
                return;
            };
            CommitOrBundle::Commit(Commit::new(parents.clone(), decrypted, *hash))
        }
        TreePart::Stratum {
            start,
            end,
            checkpoints,
            hash,
        } => {
            let Ok(decrypted) =
                ctx.keyhive()
                    .decrypt(doc.clone(), &[*start], *hash, blob_data.clone())
            else {
                tracing::warn!("unable to decrypt");
                return;
            };
            CommitOrBundle::Bundle(
                CommitBundle::builder()
                    .start(*start)
                    .end(*end)
                    .bundled_commits(decrypted)
                    .checkpoints(checkpoints.clone())
                    .build(),
            )
        }
    };
    let blob = BlobMeta::new(&blob_data);
    ctx.storage()
        .put(StorageKey::blob(blob.hash()), blob_data.clone())
        .await;
    let path = StorageKey::sedimentree_root(&doc, CommitCategory::Content);
    match tree_part {
        TreePart::Commit { hash, parents } => {
            let loose = LooseCommit::new(hash, parents, blob);
            sedimentree::storage::write_loose_commit(ctx.clone(), path, &loose).await;
        }
        TreePart::Stratum {
            start,
            end,
            checkpoints,
            hash: _,
        } => {
            let stratum = sedimentree::Stratum::new(start, end, checkpoints.clone(), blob);
            sedimentree::storage::write_stratum(ctx.clone(), path, stratum).await;
        }
    }
    ctx.emit_doc_event(DocEvent::Data {
        doc,
        data: decrypted_data.clone(),
    });
}
