mod counter_doc;
use counter_doc::Doc;

use beelay::{Beelay, CommitOrBundle, DocumentId};

#[tokio::main]
async fn main() {
    let mut beelay1 = Beelay::builder().spawn_tokio().await;
    let (doc, doc_id) = create_dag(&mut beelay1, 5000).await;
    let doc_raw = beelay1.load_doc(doc_id).await.unwrap();
    let num_bytes = doc_raw
        .iter()
        .flat_map(|c| {
            c.iter().map(|c| match c {
                CommitOrBundle::Commit(c) => c.contents().len(),
                CommitOrBundle::Bundle(b) => b.bundled_commits().len(),
            })
        })
        .sum::<usize>();
    println!("Total size of compressed doc: {}", num_bytes);
    let reloaded = Doc::load(doc_raw.unwrap_or_default());
    println!("original value: {}", doc.value());
    println!("reloaded value: {}", reloaded.value());
}

async fn create_dag(beelay: &mut Beelay, depth: usize) -> (Doc, DocumentId) {
    let doc_id = beelay.create_doc().await.unwrap();
    let mut doc = Doc::new();
    for _ in 0..depth {
        let commit = doc.increment(1);
        let commit_hash = commit.hash();
        let encoded = commit.encode();
        let commit = beelay::Commit::new(commit.parents, encoded, commit_hash);
        let new_bundles = beelay.add_commits(doc_id, vec![commit]).await.unwrap();
        if !new_bundles.is_empty() {
            for bundle in new_bundles {
                println!("Adding new bundle");
                let bundled = doc.bundle(bundle.start, bundle.end, bundle.checkpoints);
                beelay.add_bundle(doc_id, bundled).await.unwrap();
            }
        }
    }
    println!("uncompressed size: {}", doc.size());
    (doc, doc_id)
}
