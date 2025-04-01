use std::collections::HashSet;

use beelay_core::{Commit, CommitOrBundle};
use keyhive_core::principal::public::Public;
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn decrypt_on_reload() {
    // Check that all the CGKA ops are persisted as they occur so we can reload
    // the beelay and still sucessfully decrypt
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();

    let (doc_id, initial_commit) = network.beelay(&peer1).create_doc(vec![]).unwrap();
    let mut commits = vec![CommitOrBundle::Commit(initial_commit.clone())];
    let mut last_commit = initial_commit;
    for i in 0..2 {
        let contents = format!("hello {}", i);
        let hash = blake3::hash(contents.as_bytes());
        let commit = Commit::new(
            vec![last_commit.hash()],
            "hello".into(),
            hash.as_bytes().into(),
        );
        network
            .beelay(&peer1)
            .add_commits(doc_id, vec![commit.clone()])
            .unwrap();
        commits.push(CommitOrBundle::Commit(commit.clone()));
        last_commit = commit;
    }

    network.reload_peer(&peer1);

    let doc = network
        .beelay(&peer1)
        .load_doc(doc_id)
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    let original = commits.into_iter().collect::<HashSet<_>>();
    assert_eq!(doc, original);
}

#[test]
fn decrypt_after_sync_on_reload() {
    // Check that all the CGKA ops are persisted as they occur so we can reload
    // the beelay and still sucessfully decrypt
    init_logging();
    let mut network = Network::new();
    let alice = network.create_peer("peer1").build();
    let bob = network.create_peer("peer2").build();

    let bob_contact = network.beelay(&bob).contact_card().unwrap();

    let (doc_id, initial_commit) = network
        .beelay(&alice)
        .create_doc(vec![bob_contact.into()])
        .unwrap();
    let mut commits = vec![CommitOrBundle::Commit(initial_commit.clone())];
    let mut last_commit = initial_commit;
    for i in 0..2 {
        let contents = format!("hello {}", i);
        let hash = blake3::hash(contents.as_bytes());
        let commit = Commit::new(
            vec![last_commit.hash()],
            "hello".into(),
            hash.as_bytes().into(),
        );
        network
            .beelay(&alice)
            .add_commits(doc_id, vec![commit.clone()])
            .unwrap();
        commits.push(CommitOrBundle::Commit(commit.clone()));
        last_commit = commit;
    }

    // now sync to bob
    network.connect_stream(&bob, &alice);

    // We should have the commits on bob
    let doc = network
        .beelay(&bob)
        .load_doc(doc_id)
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    let original = commits.into_iter().collect::<HashSet<_>>();
    assert_eq!(doc, original);

    network.reload_peer(&bob);

    // We should have the commits on bob after reload
    let doc = network
        .beelay(&bob)
        .load_doc(doc_id)
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(doc, original);
}
