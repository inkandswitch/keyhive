use std::{collections::HashSet, time::Duration};

use beelay_core::{
    conn_info,
    doc_status::DocStatus,
    keyhive::{AddMemberToGroup, KeyhiveEntityId, MemberAccess},
    CommitHash, CommitOrBundle,
};
use ed25519_dalek::SigningKey;
use network::{ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn create_and_load() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();

    let (doc_id, initial_commit) = network.beelay(&peer1).create_doc(vec![]).unwrap();
    let commit1 = beelay_core::Commit::new(
        vec![initial_commit.hash()],
        vec![1, 2, 3],
        CommitHash::from([1; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit1.clone()])
        .unwrap();

    let loaded = network
        .beelay(&peer1)
        .load_doc(doc_id)
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(
        loaded,
        HashSet::from_iter(vec![
            CommitOrBundle::Commit(initial_commit),
            CommitOrBundle::Commit(commit1)
        ])
    );
}

#[test]
fn create_and_sync_via_stream() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();
    let peer2_contact = network.beelay(&peer2).contact_card().unwrap();

    // First create the doc
    let (doc1_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact.into()])
        .unwrap();

    let DocStatus {
        local_heads: Some(start_heads),
    } = network.beelay(&peer1).doc_status(&doc1_id)
    else {
        panic!("no local heads on peer1");
    };
    assert_eq!(start_heads, vec![initial_commit.hash()]);

    let commit1 = beelay_core::Commit::new(start_heads, vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()])
        .unwrap();
    // let commit2 = beelay_core::Commit::new(
    //     vec![commit1.hash()],
    //     vec![4, 5, 6],
    //     CommitHash::from([2; 32]),
    // );
    // network
    //     .beelay(&peer1)
    //     .add_commits(doc1_id, vec![commit1.clone(), commit2.clone()])
    //     .unwrap();

    // Monitor the doc on peer2
    let status = network.beelay(&peer2).doc_status(&doc1_id);
    assert_eq!(
        status,
        beelay_core::doc_status::DocStatus { local_heads: None }
    );

    // Now connect the other peer
    let ConnectedPair { .. } = network.connect_stream(&peer2, &peer1);

    // The other end should now be synced because `connect_stream` will run the network until quiescent
    assert_eq!(
        network.beelay(&peer2).doc_status(&doc1_id),
        DocStatus {
            local_heads: Some(vec![CommitHash::from([1; 32])])
        }
    );

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
    // let expected_commits = vec![initial_commit, commit1.clone(), commit2.clone()]
    let expected_commits = vec![initial_commit, commit1.clone()]
        .into_iter()
        .collect::<HashSet<_>>();

    let table = network.beelay(&peer2).log_keyhive_events(
        keyhive_core::debug_events::Nicknames::default()
            .with_nickname(doc1_id.as_bytes(), "doc1")
            .with_nickname(peer1.as_bytes(), "peer1")
            .with_nickname(peer2.as_bytes(), "peer2"),
    );
    keyhive_core::debug_events::terminal::print_event_table_verbose(table);

    assert_eq!(commits_on_2, expected_commits);
}

#[test]
fn changes_published_after_sync() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();

    // First create the doc
    let (doc1_id, initial_commit) = network.beelay(&peer1).create_doc(vec![]).unwrap();
    let peer2_contact = network.beelay(&peer2).contact_card().unwrap();
    network
        .beelay(&peer1)
        .add_member_to_doc(doc1_id, peer2_contact, MemberAccess::Read);

    // Now connect the other peer
    let ConnectedPair { .. } = network.connect_stream(&peer2, &peer1);

    // The other end should now be synced because `connect_stream` will run the network until quiescent
    assert_eq!(
        network.beelay(&peer2).doc_status(&doc1_id),
        DocStatus {
            local_heads: Some(vec![initial_commit.hash()])
        }
    );

    // Now make a new commit on peer1
    let commit1 = beelay_core::Commit::new(
        vec![initial_commit.hash()],
        vec![1, 2, 3],
        CommitHash::from([1; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()])
        .unwrap();
    network.run_until_quiescent();

    // check that peer2 has the commit
    assert_eq!(
        network.beelay(&peer2).doc_status(&doc1_id),
        DocStatus {
            local_heads: Some(vec![commit1.hash()])
        }
    );

    // Check that the content is correct
    let commit1_on_2 = network
        .beelay(&peer2)
        .load_doc(doc1_id)
        .unwrap()
        .into_iter()
        .filter_map(|c| match c {
            CommitOrBundle::Commit(c) => {
                if c.hash() == commit1.hash() {
                    Some(c)
                } else {
                    None
                }
            }
            _ => None,
        })
        .next()
        .unwrap();

    assert_eq!(commit1_on_2.contents(), vec![1, 2, 3]);
}

#[test]
fn save_and_load() {
    init_logging();
    let mut network = Network::new();
    let key = SigningKey::generate(&mut rand::thread_rng());
    let peer1 = network
        .create_peer("peer1")
        .signing_key(key.clone())
        .build();

    // Create a document
    let (doc1_id, _) = network.beelay(&peer1).create_doc(vec![]).unwrap();

    assert!(!network.beelay(&peer1).storage().is_empty());
    for (key, value) in network.beelay(&peer1).storage() {
        tracing::info!("Key: {}, Value: {}", key, value.len());
    }

    // Now creaet a new network and peer with the same storage
    let mut network2 = Network::new();
    let peer2 = network2
        .create_peer("peer2")
        .storage(network.beelay(&peer1).storage().clone())
        .signing_key(key)
        .build();

    // Check that the document is in storage
    let _doc = network2.beelay(&peer2).load_doc(doc1_id).unwrap();
    // TODO: re-enable once doc creation events are stored properly
    // assert_eq!(
    //     doc,
    //     vec![beelay_core::CommitOrBundle::Commit(initial_commit)]
    // );
}

#[test]
fn sync_loops_are_rerun() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();
    let peer2 = network.create_peer("peer2").build();

    let ConnectedPair { left_to_right, .. } = network.connect_stream(&peer1, &peer2);

    let conn_infos = network.beelay(&peer1).conn_info();
    let conn_info = conn_infos.get(&left_to_right).unwrap();
    let conn_info::ConnState::Listening {
        last_synced_at: Some(first_sync),
    } = conn_info.state.clone()
    else {
        panic!("expected Listening state");
    };

    // Now wait until longer than the sync timeout
    network.advance_time(beelay_core::SYNC_INTERVAL + Duration::from_millis(10));

    let conn_infos = network.beelay(&peer1).conn_info();
    let conn_info = conn_infos.get(&left_to_right).unwrap();
    let conn_info::ConnState::Listening {
        last_synced_at: Some(second_sync),
    } = conn_info.state.clone()
    else {
        panic!("expected Listening state");
    };

    assert!(second_sync > first_sync);
}

#[test]
fn newly_accessible_documents_are_synced() {
    init_logging();
    let mut network = Network::new();
    let alice = network.create_peer("alice").build();
    let bob = network.create_peer("bob").build();
    let charlie = network.create_peer("charlie").build();

    // First create a group on alice with charlie as a member. Then, sync with Charlie and disconnect.
    // Charlie now adds bob to the group. Concurrently alice creates a document in the group. bob syncs
    // with Charlie - so he now has the membership ops proving he has access to the group. Finally, Bob
    // syncs with Alice. He should have access to the doc.

    let charlie_contact = network.beelay(&charlie).contact_card().unwrap();
    let group = network.beelay(&alice).create_group(vec![]).unwrap();
    network
        .beelay(&alice)
        .add_member_to_group(AddMemberToGroup {
            group_id: group,
            member: KeyhiveEntityId::Individual(charlie_contact),
            access: MemberAccess::Admin,
        })
        .unwrap();

    // Now connect to charlie and sync
    // Now, sync with charlie
    let ConnectedPair {
        left_to_right: alice_to_charlie,
        ..
    } = network.connect_stream(&alice, &charlie);

    // Sync should have happened now as we run until quiescent

    // Now disconnect from alice
    network.beelay(&alice).disconnect(alice_to_charlie);

    // Now, add bob to the group on charlie
    let bob_contact = network.beelay(&bob).contact_card().unwrap();
    network
        .beelay(&charlie)
        .add_member_to_group(AddMemberToGroup {
            group_id: group,
            member: KeyhiveEntityId::Individual(bob_contact),
            access: MemberAccess::Admin,
        })
        .unwrap();

    // Sync bob with charlie
    let ConnectedPair {
        left_to_right: bob_to_charlie,
        ..
    } = network.connect_stream(&bob, &charlie);
    network.beelay(&bob).disconnect(bob_to_charlie);

    // Concurrently create a document on Alice
    let (doc, initial_commit) = network
        .beelay(&alice)
        .create_doc(vec![KeyhiveEntityId::Group(group)])
        .unwrap();

    // Connect bob to alice
    let ConnectedPair {
        left_to_right: bob_to_alice,
        ..
    } = network.connect_stream(&bob, &alice);

    // We should now be able to download the document

    let doc_on_bob = network.beelay(&bob).load_doc_encrypted(doc).unwrap();

    // Check that the new commit is part of the doc on bob
    let commit_hashes = doc_on_bob
        .into_iter()
        .map(|c| match c {
            CommitOrBundle::Commit(c) => c.hash(),
            CommitOrBundle::Bundle(b) => *b.hash(),
        })
        .collect::<HashSet<_>>();
    assert!(commit_hashes.contains(&initial_commit.hash()));
}
