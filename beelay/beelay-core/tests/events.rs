use beelay_core::{Commit, CommitHash, CommitOrBundle, DocEvent};
use network::{ConnForwarding, Network};
use test_utils::init_logging;

mod network;

#[test]
fn uploaded_commits_emits_local_event() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    network.connect_stream(&peer1, &peer2, ConnForwarding::LeftToRight);

    // Now, create a document on left
    let doc_id = network.beelay(&peer1).create_doc();
    let commit = Commit::new(vec![], "hello".into(), CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit.clone()]);
    // Check that it was notified on the right
    let notis = network.beelay(&peer2).pop_notifications();
    assert_eq!(notis.len(), 1);
    assert_eq!(
        notis[0],
        DocEvent {
            doc: doc_id,
            data: CommitOrBundle::Commit(commit)
        }
    );
}
