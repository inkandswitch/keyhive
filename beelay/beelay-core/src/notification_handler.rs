use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    blob::BlobMeta,
    effects::TaskEffects,
    messages::{BlobRef, Notification, TreePart, UploadItem},
    sedimentree::{self, LooseCommit},
    Commit, CommitBundle, CommitCategory, CommitOrBundle, DocEvent, StorageKey,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct HandlerId(u64);

static LAST_HANDLER_ID: AtomicU64 = AtomicU64::new(0);

impl HandlerId {
    pub(crate) fn new() -> HandlerId {
        HandlerId(LAST_HANDLER_ID.fetch_add(1, Ordering::Relaxed))
    }
}

pub(crate) async fn handle<R: rand::Rng>(mut effects: TaskEffects<R>, notification: Notification) {
    tracing::debug!(?notification, "received notification");
    effects.log().remote_notification(&notification);
    let Notification {
        from_peer,
        doc,
        data,
    } = notification;
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
        peer: from_peer,
        doc,
        data: data.clone(),
    });
}
