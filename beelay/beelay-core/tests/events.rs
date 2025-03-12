use std::collections::HashMap;

use beelay_core::{
    doc_status::DocEvent, keyhive::MemberAccess, Commit, CommitHash, CommitOrBundle,
};
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn sync_emits_local_notifications() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer2_contact = network.beelay(&peer2).contact_card();

    // Now, create a document on left
    let (doc_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact])
        .unwrap();

    // Clear notifications
    network.beelay(&peer2).pop_notifications();

    network.connect_stream(&peer1, &peer2);

    // Check that after sync we were notified of the new changes available
    let notis = network.beelay(&peer2).pop_notifications();

    assert_eq!(notis.len(), 1);
    assert_eq!(
        notis,
        HashMap::from_iter(vec![(
            doc_id.clone(),
            vec![DocEvent::Data {
                data: CommitOrBundle::Commit(initial_commit.clone()),
            }]
        )])
    );
}

#[test]
fn listen_emits_local_notifications() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer2_contact_card = network.beelay(&peer2).contact_card();

    // Now, create a document on left
    let (doc_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact_card])
        .unwrap();
    let peer2_contact = network.beelay(&peer2).contact_card();
    network
        .beelay(&peer1)
        .add_member_to_doc(doc_id.clone(), peer2_contact, MemberAccess::Write);

    network.connect_stream(&peer1, &peer2);

    // Clear notifications
    network.beelay(&peer2).pop_notifications();

    // Now add another commit on peer1
    let new_commit = Commit::new(
        vec![initial_commit.hash()],
        "hello".into(),
        CommitHash::from([7; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc_id.clone(), vec![new_commit.clone()])
        .unwrap();

    let notis = network.beelay(&peer2).pop_notifications();

    assert_eq!(notis.len(), 1);
    assert_eq!(
        notis,
        HashMap::from_iter(vec![(
            doc_id.clone(),
            vec![DocEvent::Data {
                data: CommitOrBundle::Commit(new_commit.clone()),
            }]
        )])
    );
}
