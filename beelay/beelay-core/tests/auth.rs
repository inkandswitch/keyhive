use beelay_core::{Access, Commit, CommitHash, CommitOrBundle, DocEvent};
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
        ..
    } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);
    let ConnectedPair {
        right_to_left: peer3_to_peer2,
        ..
    } = network.connect_stream(&peer2, &peer3, ConnForwarding::Both);

    let doc = network
        .beelay(&peer1)
        .create_doc_with_contents(Access::Private, "somedoc".into());
    network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

    // Now fetch the doc on peer3, it shouldn't be found because we don't have access
    let result = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
    assert_eq!(result.found, false);

    // Now give access to peer3 and peer2
    network.beelay(&peer1).add_member(doc, peer2);
    network.beelay(&peer1).add_member(doc, peer3);

    // now try the sync again
    network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);
    let result = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
    assert_eq!(result.found, true);
}
