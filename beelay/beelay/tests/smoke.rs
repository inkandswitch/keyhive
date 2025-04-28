use beelay::{signing::MemorySigner, storage::MemoryStorage, Commit, CommitHash, Repo};
use rand::thread_rng;

#[tokio::test]
async fn save_and_load() {
    let storage = MemoryStorage::new();
    let signer = MemorySigner::generate();
    let beelay = Repo::load(storage, signer, rand::thread_rng()).await;

    let initial_commit = commit("hello world".into(), vec![]);
    let doc = beelay.create(initial_commit.clone()).await;

    beelay
        .add_commits(
            &doc,
            vec![commit("hello again world", vec![initial_commit.hash()])],
        )
        .await;

    let reloaded = beelay.find(&doc).await.expect("should find doc");
    assert_eq!(reloaded, doc);
}

async fn commit(data: Vec<u8>, parents: Vec<CommitHash>) -> Commit {
    let hash = blake3::hash(&data).as_bytes();
    Commit::new(parents, data, hash)
}
