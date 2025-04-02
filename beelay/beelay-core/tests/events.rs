use std::collections::HashMap;

use beelay_core::{
    conn_info::{ConnState, ConnectionInfo},
    doc_status::DocEvent,
    keyhive::MemberAccess,
    Commit, CommitHash, CommitOrBundle,
};
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn sync_emits_local_notifications() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();
    let peer2_contact = network.beelay(&peer2).contact_card().unwrap();

    // Now, create a document on left
    let (doc_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact.into()])
        .unwrap();

    // Clear notifications
    network.beelay(&peer2).pop_notifications();

    network.connect_stream(&peer1, &peer2);

    // Check that after sync we were notified of the new changes available
    let notis = network.beelay(&peer2).pop_notifications();

    assert_eq!(
        notis,
        HashMap::from_iter(vec![(
            doc_id.clone(),
            vec![
                DocEvent::Discovered,
                DocEvent::Data {
                    data: CommitOrBundle::Commit(initial_commit.clone()),
                }
            ]
        )])
    );
}

#[test]
fn listen_emits_local_notifications() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();
    let peer2_contact_card = network.beelay(&peer2).contact_card().unwrap();

    // Now, create a document on left
    let (doc_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact_card.into()])
        .unwrap();
    let peer2_contact = network.beelay(&peer2).contact_card().unwrap();
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

#[test]
fn connect_emits_peer_changes() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();

    network.connect_stream(&peer1, &peer2);

    let mut peer_changes = network.beelay(&peer1).peer_changes().clone();
    let peer2_changes = peer_changes.remove(&peer2).unwrap();
    assert!(!peer2_changes.is_empty());

    let ConnectionInfo { peer_id, state } = peer2_changes[0].clone();
    assert_eq!(peer_id, peer2);
    let ConnState::Syncing { started_at } = state else {
        panic!("expected first state to be Syncing");
    };

    let ConnectionInfo { peer_id, state } = peer2_changes[1].clone();
    assert_eq!(peer_id, peer2);
    let ConnState::Listening { last_synced_at } = state else {
        panic!("expected second state to be Listening");
    };
    let Some(last_synced_at) = last_synced_at else {
        panic!("expected last_synced_at to be Some");
    };
    assert!(last_synced_at > started_at);
}

#[test]
fn discovered_emitted_on_sync_of_new_doc() {
    init_logging();
    let mut network = Network::new();
    let alice = network.create_peer("peer1").build();
    let bob = network.create_peer("peer2").build();
    let bob_contact = network.beelay(&bob).contact_card().unwrap();

    let (doc, _) = network
        .beelay(&alice)
        .create_doc(vec![bob_contact.into()])
        .unwrap();

    network.beelay(&bob).pop_notifications();
    network.connect_stream(&bob, &alice);

    let notis = network
        .beelay(&bob)
        .pop_notifications()
        .remove(&doc)
        .unwrap();
    println!("{:?}", notis);
    let noti = notis.first().unwrap();
    assert!(matches!(noti, DocEvent::Discovered));
}

#[test]
fn discovered_emitted_on_upload_of_new_doc() {
    init_logging();
    let mut network = Network::new();
    let alice = network.create_peer("peer1").build();
    let bob = network.create_peer("peer2").build();
    let bob_contact = network.beelay(&bob).contact_card().unwrap();

    let (doc, _) = network
        .beelay(&alice)
        .create_doc(vec![bob_contact.into()])
        .unwrap();

    network.beelay(&bob).pop_notifications();
    network.connect_stream(&alice, &bob);

    let notis = network
        .beelay(&bob)
        .pop_notifications()
        .remove(&doc)
        .unwrap();
    println!("{:?}", notis);
    let noti = notis.first().unwrap();
    assert!(matches!(noti, DocEvent::Discovered));
}
