use crate::{
    blob::BlobMeta,
    commands::{Encode, LooseCommit, ReachabilityIndexEntry},
    sedimentree, CommitCategory, DocumentId, StorageKey,
};

#[derive(Debug)]
pub struct AddLink {
    pub from: DocumentId,
    pub to: DocumentId,
}

#[tracing::instrument(skip(ctx, link), fields(from=%link.from, to=%link.to))]
pub(super) async fn add_link<R: rand::Rng + rand::CryptoRng>(
    ctx: crate::state::TaskContext<R>,
    link: AddLink,
) {
    tracing::trace!("adding link");
    let links_tree = sedimentree::storage::load(
        ctx.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Links),
    )
    .await
    .unwrap_or_default();
    let new_entry = ReachabilityIndexEntry::new(link.to);

    let encoded = new_entry.encode();
    let blob = BlobMeta::new(&encoded);
    ctx.storage()
        .put(StorageKey::blob(blob.hash()), encoded.clone())
        .await;

    let commit = LooseCommit::new(new_entry.hash(), links_tree.heads(), blob);
    sedimentree::storage::write_loose_commit(
        ctx.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Links),
        &commit,
    )
    .await;
}
