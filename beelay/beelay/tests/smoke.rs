use std::collections::HashMap;

use beelay::{AddLink, Beelay, Commit, CommitHash, Forwarding};
use beelay_core::{Audience, CommitOrBundle};
use futures::StreamExt;
use rand::Rng;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn create_and_sync() {
    test_utils::init_logging();
    let mut beelay = Beelay::builder().spawn_tokio().await;
    test_utils::add_rewrite(beelay.peer_id(), "peer1");
    let doc_id = beelay.create_doc().await.unwrap();

    let commit1 = Commit::new(vec![], vec![1, 2, 3], random_commit_hash());
    let commit2 = Commit::new(vec![commit1.hash()], vec![4, 5, 6], random_commit_hash());

    beelay
        .add_commits(doc_id, vec![commit1.clone(), commit2.clone()])
        .await
        .unwrap();

    let doc2_id = beelay.create_doc().await.unwrap();
    let commit3 = Commit::new(vec![], vec![7, 8, 9], random_commit_hash());
    beelay
        .add_commits(doc2_id, vec![commit3.clone()])
        .await
        .unwrap();

    beelay
        .add_link(AddLink {
            from: doc_id,
            to: doc2_id,
        })
        .await
        .unwrap();

    let mut beelay2 = Beelay::builder().spawn_tokio().await;
    test_utils::add_rewrite(beelay2.peer_id(), "peer2");
    tracing::info!("about to connect");
    connect(&beelay, &beelay2, Forwarding::DontForward).await;
    tracing::info!("now we're doing the actual test");

    beelay2.sync_doc(doc_id).await.unwrap();

    let commits = beelay2
        .load_doc(doc_id)
        .await
        .unwrap()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit, got bundle");
            };
            (c.hash(), c)
        })
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(commits.get(&commit1.hash()).unwrap(), &commit1);
    assert_eq!(commits.get(&commit2.hash()).unwrap(), &commit2);

    let doc2 = beelay2
        .load_doc(doc2_id)
        .await
        .unwrap()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit, got bundle");
            };
            (c.hash(), c)
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(doc2.get(&commit3.hash()).unwrap(), &commit3);
}

async fn connect(left: &Beelay, right: &Beelay, forwarding: Forwarding) {
    let (tx_left, rx_right) = futures::channel::mpsc::channel::<Vec<u8>>(10);
    let (tx_right, rx_left) = futures::channel::mpsc::channel::<Vec<u8>>(10);

    let rx_right = rx_right.map(Ok::<_, futures::channel::mpsc::SendError>);
    let rx_left = rx_left.map(Ok::<_, futures::channel::mpsc::SendError>);

    let connecting_right = right.accept_stream(rx_right, tx_right, None, Forwarding::DontForward);
    tokio::spawn(async move {
        let result = connecting_right.driver.await;
        tracing::debug!(?result, "right driver finished");
    });

    let peer_id = right.peer_id();
    let connecting_left =
        left.connect_stream(rx_left, tx_left, Audience::peer(&peer_id), forwarding);
    tokio::spawn(async move {
        let result = connecting_left.driver.await;
        tracing::debug!(?result, "left driver finished");
    });

    let connected = futures::future::join(connecting_left.ready, connecting_right.ready);

    let (ready_left, ready_right) = connected.await;
    ready_left.expect("left should be connected");
    ready_right.expect("right should be connected");
}

fn random_commit_hash() -> CommitHash {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    CommitHash::from(bytes)
}
