use beelay_core::Access;
use network::{ConnForwarding, ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn pending_inbound_listens_are_cancelled_by_shutdown() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    let ConnectedPair { right_to_left, .. } =
        network.connect_stream(&peer1, &peer2, ConnForwarding::Both);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);

    let snapshot = network
        .beelay(&peer2)
        .sync_doc(doc1_id, right_to_left)
        .remote_snapshot;
    network.beelay(&peer2).listen(right_to_left, snapshot);

    network.beelay(&peer1).shutdown();
}

#[test]
fn shutdown_while_forwarding_listen_does_not_throw() {
    // Make a topology like this (<-> indicates forwarding in both directions)
    //
    // peer1 <-> peer2 <-> peer3
    //
    // Now, peer1 creates a doc. Peer3 syncs the doc and then listens to it.
    // this means that peer2 is forwarding listen requests to peer1
    // Now shutdown peer2. This should mean there is an outbound listen
    // request from peer3 to peer2 which never receives a response. In
    // this case we should still terminate correctly.
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let ConnectedPair { .. } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);
    let ConnectedPair {
        right_to_left: peer3_to_peer2,
        ..
    } = network.connect_stream(&peer2, &peer3, ConnForwarding::Both);

    let doc1_id = network.beelay(&peer1).create_doc(Access::Public);

    let snapshot = network
        .beelay(&peer3)
        .sync_doc(doc1_id, peer3_to_peer2)
        .remote_snapshot;
    network.beelay(&peer3).listen(peer3_to_peer2, snapshot);

    network.beelay(&peer2).dirty_shutdown();
    network.beelay(&peer3).shutdown();
}
