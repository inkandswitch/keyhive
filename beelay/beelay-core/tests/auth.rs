use beelay_core::{Access, Commit};
use network::{ConnForwarding, ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn giving_access_to_peer_enables_reading() {
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
        right_to_left: peer3_to_peer2,
        ..
    } = network.connect_stream(&peer2, &peer3, ConnForwarding::Both);

    let doc = network
        .beelay(&peer1)
        .create_doc_with_contents(Access::Private, "somedoc".into());
    network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

    // Now fetch the doc on peer2, it shouldn't be found because we don't have access
    let synced_to_2 = network.beelay(&peer2).sync_doc(doc, peer2_to_peer1);
    assert_eq!(synced_to_2.found, false);

    // Likewise peer3 should not have access
    let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
    assert_eq!(synced_to_3.found, false);

    // Now give access to peer2
    network.beelay(&peer1).add_member(doc, peer2).unwrap();

    // Syncing from peer2 should now work
    let synced_to_2 = network.beelay(&peer2).sync_doc(doc, peer2_to_peer1);
    assert_eq!(synced_to_2.found, true);

    // But syncing from peer2 to peer3 should fail
    let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
    assert_eq!(synced_to_3.found, false);

    // Now add peer3
    network.beelay(&peer1).add_member(doc, peer3).unwrap();

    // Now the sync should work
    let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
    assert_eq!(synced_to_3.found, true);

    let commits_on_3_before_revocation = network.beelay(&peer3).load_doc(doc).unwrap();

    // Now, revoking access to peer3 should make the sync fail again
    network.beelay(&peer1).remove_member(doc, peer3).unwrap();

    // Add a new commit on peer1
    network.beelay(&peer1).add_commits(
        doc,
        vec![Commit::new(vec![], "whooop".into(), [7; 32].into())],
    );

    tracing::info!("done uploading");

    // Now run sync on 3 again
    let _synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);

    // Load commits on 3, they should be the same as before the call to add them
    let commits_on_3_after_revocation = network.beelay(&peer3).load_doc(doc).unwrap();
    assert_eq!(
        commits_on_3_before_revocation,
        commits_on_3_after_revocation
    );
}
