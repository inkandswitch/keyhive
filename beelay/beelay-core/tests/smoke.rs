use std::collections::HashSet;

use beelay_core::{Access, CommitHash, CommitOrBundle, Forwarding};
use network::{ConnForwarding, ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn save_and_load() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");

    let doc_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit1.clone()]);

    let loaded = network.beelay(&peer1).load_doc(doc_id).unwrap();
    assert_eq!(loaded, vec![CommitOrBundle::Commit(commit1)]);
}

#[test]
fn create_and_sync() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    let peer2_to_peer1 = network
        .beelay(&peer2)
        .register_endpoint(&peer1, Forwarding::DontForward);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone(), commit2.clone()]);

    let doc2_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit3 = beelay_core::Commit::new(vec![], vec![7, 8, 9], CommitHash::from([3; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc2_id, vec![commit3.clone()]);

    network.beelay(&peer1).add_link(beelay_core::AddLink {
        from: doc1_id,
        to: doc2_id,
    });

    let sync_with_2 = network.beelay(&peer2).sync_doc(doc1_id, peer2_to_peer1);

    let commits_on_2: HashSet<beelay_core::Commit> = network
        .beelay(&peer2)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone(), commit2.clone()]
        .into_iter()
        .collect::<HashSet<_>>();

    let docs_on_2 = sync_with_2
        .differing_docs
        .into_iter()
        .collect::<HashSet<_>>();
    let expected_docs = vec![doc1_id, doc2_id].into_iter().collect::<HashSet<_>>();

    if !(docs_on_2 == expected_docs) {
        println!("failed to converge");
        assert_eq!(docs_on_2, vec![doc1_id, doc2_id].into_iter().collect());
    }

    assert_eq!(commits_on_2, expected_commits);
}

#[test]
fn create_and_sync_via_stream() {
    init_logging();
    test_utils::add_rewrite(
        keyhive_core::principal::public::Public.id().to_string(),
        "<PUBLIC>",
    );
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    let ConnectedPair {
        left_to_right: stream,
        ..
    } = network.connect_stream(&peer2, &peer1, ConnForwarding::Neither);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone(), commit2.clone()])
        .unwrap();

    let doc2_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit3 = beelay_core::Commit::new(vec![], vec![7, 8, 9], CommitHash::from([3; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc2_id, vec![commit3.clone()])
        .unwrap();

    network.beelay(&peer1).add_link(beelay_core::AddLink {
        from: doc1_id,
        to: doc2_id,
    });

    let sync_with_2 = network.beelay(&peer2).sync_doc(doc1_id, stream);

    let commits_on_2: HashSet<beelay_core::Commit> = network
        .beelay(&peer2)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone(), commit2.clone()]
        .into_iter()
        .collect::<HashSet<_>>();

    let docs_on_2 = sync_with_2
        .differing_docs
        .into_iter()
        .collect::<HashSet<_>>();
    let expected_docs = vec![doc1_id, doc2_id].into_iter().collect::<HashSet<_>>();

    if !(docs_on_2 == expected_docs) {
        println!("failed to converge");
        assert_eq!(docs_on_2, vec![doc1_id, doc2_id].into_iter().collect());
    }

    assert_eq!(commits_on_2, expected_commits);
}

#[test]
fn request_from_connected() {
    // Test that in a network like this:
    //
    // peer1 <-> peer2 <-> peer3
    //
    // If peer1 has a document and peer 2 is configured to forward requests to
    // peer1 then requesting the document on peer3 will result in the document
    // being synced to peer3.

    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let peer3_to_peer2 = network
        .beelay(&peer3)
        .register_endpoint(&peer2, Forwarding::DontForward);
    let _peer2_to_peer1 = network
        .beelay(&peer2)
        .register_endpoint(&peer1, Forwarding::Forward);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    network.beelay(&peer3).sync_doc(doc1_id, peer3_to_peer2);
    let commits_on_3: HashSet<beelay_core::Commit> = network
        .beelay(&peer3)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone()].into_iter().collect::<HashSet<_>>();
    assert_eq!(commits_on_3, expected_commits);
}

#[test]
fn saving_many_times_loads_correctly() {
    init_logging();
    let mut network = Network::new();
    let peer = network.create_peer("peer");

    let doc_id = network.beelay(&peer).create_doc(Access::Public);

    let mut saved_commits = HashSet::new();

    const NUM_COMMITS: usize = 101;
    let mut last_commit_hash = None;
    for i in 0..NUM_COMMITS {
        let this_hash = CommitHash::from([i as u8; 32]);
        let commit = beelay_core::Commit::new(
            last_commit_hash.iter().cloned().collect(),
            vec![i as u8; 3],
            this_hash,
        );
        saved_commits.insert(commit.clone());
        network.beelay(&peer).add_commits(doc_id, vec![commit]);
        last_commit_hash = Some(this_hash);
    }

    let loaded_commits = network
        .beelay(&peer)
        .load_doc(doc_id)
        .expect("doc not found")
        .into_iter()
        .map(|c_or_b| {
            let CommitOrBundle::Commit(c) = c_or_b else {
                panic!("expected a commit");
            };
            c
        })
        .collect::<HashSet<_>>();
    assert_eq!(loaded_commits.len(), NUM_COMMITS); // Plus one because an initial commit is added in create_doc
    if loaded_commits != saved_commits {
        let diff = loaded_commits
            .symmetric_difference(&saved_commits)
            .collect::<Vec<_>>();
        println!(
            "saved and loaded commits differ, {} differing elements",
            diff.len()
        );
        println!("difference: {:?}", diff);
    }
}
