use beelay_core::{Access, CommitHash, CommitOrBundle, Forwarding};
use network::{ConnForwarding, ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn loopy_topology_sync_is_bounded() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let ConnectedPair {
        left_to_right: peer1_to_peer2,
        right_to_left: peer2_to_peer1,
    } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);
    let ConnectedPair {
        left_to_right: peer2_to_peer3,
        right_to_left: peer3_to_peer2,
    } = network.connect_stream(&peer2, &peer3, ConnForwarding::Both);
    let ConnectedPair {
        left_to_right: peer3_to_peer1,
        right_to_left: peer1_to_peer3,
    } = network.connect_stream(&peer3, &peer1, ConnForwarding::Both);

    //Create a doc on peer1
    let doc1_id = network
        .beelay(&peer1)
        .create_doc_with_contents(Access::Public, "hello".into());

    // fetch the doc on peer3
    let sync_with_2 = network.beelay(&peer3).sync_doc(doc1_id, peer3_to_peer2);
    assert_eq!(sync_with_2.found, true);
    let doc_on_peer3 = network
        .beelay(&peer3)
        .load_doc(doc1_id)
        .expect("doc not found");
    assert_eq!(doc_on_peer3.len(), 1);
    assert_eq!(
        doc_on_peer3[0],
        CommitOrBundle::Commit(beelay_core::Commit::new(
            vec![],
            "hello".into(),
            CommitHash::from([1; 32]),
        ))
    );
}

#[test]
fn added_commits_are_uploaded_to_forwarding_peers() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    // Configure peer1 to forward to peer2
    let _peer1_to_peer2 = network
        .beelay(&peer1)
        .register_endpoint(&peer2, Forwarding::Forward);

    // Create a document on peer1
    let doc_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit1.clone()]);

    // The commit should have been automatically forwarded to peer2
    let commits_on_peer2 = network.beelay(&peer2).load_doc(doc_id).unwrap_or_default();

    let expected_commits = vec![CommitOrBundle::Commit(commit1)];
    assert_eq!(
        commits_on_peer2, expected_commits,
        "Commit should have been automatically forwarded to peer2"
    );
}

#[test]
fn added_commits_are_automatically_forwarded_by_intermediate_nodes() {
    init_logging();
    let mut network = Network::new();
    let left = network.create_peer("left");
    let middle = network.create_peer("middle");
    let right = network.create_peer("right");

    // Connect left->middle->right with forwarding enabled
    network.connect_stream(&left, &middle, ConnForwarding::LeftToRight);
    network.connect_stream(&middle, &right, ConnForwarding::LeftToRight);

    // Create a doc and add a commit on the left node
    let doc_id = network.beelay(&left).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&left)
        .add_commits(doc_id, vec![commit1.clone()]);

    // Verify that the commit propagated through middle to right
    let expected_commits = vec![CommitOrBundle::Commit(commit1.clone())];

    let commits_on_middle = network.beelay(&middle).load_doc(doc_id).unwrap_or_default();
    let commits_on_right = network.beelay(&right).load_doc(doc_id).unwrap_or_default();

    assert_eq!(
        commits_on_middle, expected_commits,
        "Commit should have propagated to middle node"
    );
    assert_eq!(
        commits_on_right, expected_commits,
        "Commit should have been forwarded by middle node to right node"
    );
}

#[test]
fn added_commits_do_not_loop_forever_in_mesh_topologies() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    // Connect all peers to each other with forwarding enabled
    network.connect_stream(&peer1, &peer2, ConnForwarding::Both);
    network.connect_stream(&peer2, &peer3, ConnForwarding::Both);
    network.connect_stream(&peer3, &peer1, ConnForwarding::Both);

    // Create a doc and add a commit on peer1
    let doc_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit1.clone()]);

    // Verify that all peers have the commit
    let expected_commits = vec![CommitOrBundle::Commit(commit1)];

    let commits_on_peer1 = network.beelay(&peer1).load_doc(doc_id).unwrap_or_default();
    let commits_on_peer2 = network.beelay(&peer2).load_doc(doc_id).unwrap_or_default();
    let commits_on_peer3 = network.beelay(&peer3).load_doc(doc_id).unwrap_or_default();

    assert_eq!(
        commits_on_peer1, expected_commits,
        "Commit should be present on peer1"
    );
    assert_eq!(
        commits_on_peer2, expected_commits,
        "Commit should have propagated to peer2"
    );
    assert_eq!(
        commits_on_peer3, expected_commits,
        "Commit should have propagated to peer3"
    );
}
