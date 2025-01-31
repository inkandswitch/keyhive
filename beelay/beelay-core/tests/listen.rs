use std::collections::HashSet;

use beelay_core::{Access, Commit, CommitHash, CommitOrBundle, DocEvent, Forwarding};
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn listen_to_connected() {
    // Test that in a network like this:
    //
    // peer1 <-> peer2 <-> peer3
    //
    // If peer1 has a document and peer 2 is configured to forward requests to
    // peer1 then listening to the document on peer3 will result in updates on
    // peer1 being propagated to peer3.

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
    let commit1 = Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    // Sync up
    let sync_with_2 = network.beelay(&peer3).sync_doc(doc1_id, peer3_to_peer2);

    // Now listen to further changes on peer3
    network
        .beelay(&peer3)
        .listen(peer3_to_peer2, sync_with_2.remote_snapshot);

    // Now make a change on peer1
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);

    // The commits should have been forwarded to peer3
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
    let expected_commits = vec![commit1.clone(), commit2.clone()]
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(commits_on_3, expected_commits);
}

#[test]
fn listen() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let peer1_to_peer2 = network
        .beelay(&peer1)
        .register_endpoint(&peer2, Forwarding::DontForward);
    let peer2_to_peer3 = network
        .beelay(&peer2)
        .register_endpoint(&peer3, Forwarding::DontForward);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let _sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer1_to_peer2);
    let sync_with_3 = network.beelay(&peer2).sync_doc(doc1_id, peer2_to_peer3);
    network
        .beelay(&peer2)
        .listen(peer2_to_peer3, sync_with_3.remote_snapshot);

    // Now add a commit on beelay 3 and check that it appears on beelay 2
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    // Clear prior notifications
    network.beelay(&peer2).pop_notifications();
    network
        .beelay(&peer3)
        .add_commits(doc1_id, vec![commit2.clone()]);
    let notifications = network.beelay(&peer2).pop_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0],
        DocEvent::Data {
            doc: doc1_id,
            data: CommitOrBundle::Commit(commit2)
        }
    );
}

#[test]
fn three_peers_listening_to_each_other_do_not_loop() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let peer1_to_peer2 = network
        .beelay(&peer1)
        .register_endpoint(&peer2, Forwarding::DontForward);
    let peer3_to_peer2 = network
        .beelay(&peer3)
        .register_endpoint(&peer2, Forwarding::DontForward);
    let _peer2_to_peer3 = network
        .beelay(&peer2)
        .register_endpoint(&peer3, Forwarding::Forward);
    let _peer2_to_peer1 = network
        .beelay(&peer2)
        .register_endpoint(&peer1, Forwarding::Forward);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer1_to_peer2);
    network
        .beelay(&peer1)
        .listen(peer1_to_peer2, sync_with_2.remote_snapshot);

    let sync_with_3 = network.beelay(&peer3).sync_doc(doc1_id, peer3_to_peer2);
    network
        .beelay(&peer3)
        .listen(peer3_to_peer2, sync_with_3.remote_snapshot);

    // Now add a commit on beelay 1 and check that everything terminates
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);
}

#[test]
fn two_peers_listening_to_each_other_do_not_loop() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    let peer1_to_peer2 = network
        .beelay(&peer1)
        .register_endpoint(&peer2, Forwarding::Forward);
    let peer2_to_peer1 = network
        .beelay(&peer2)
        .register_endpoint(&peer1, Forwarding::Forward);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer1_to_peer2);
    network
        .beelay(&peer1)
        .listen(peer1_to_peer2, sync_with_2.remote_snapshot);
    network
        .beelay(&peer2)
        .listen(peer2_to_peer1, sync_with_2.local_snapshot);

    // Now add a commit on beelay 1 and check that everything terminates
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);
}
