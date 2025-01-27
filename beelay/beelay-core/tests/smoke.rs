use std::collections::HashSet;

use beelay_core::{doc_status::DocStatus, keyhive::MemberAccess, CommitHash, CommitOrBundle};
use ed25519_dalek::SigningKey;
use network::{ConnectedPair, Network};
use test_utils::init_logging;

mod network;

#[test]
fn create_and_load() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");

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
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer2_contact = network.beelay(&peer2).contact_card();

    // First create the doc
    let (doc1_id, initial_commit) = network
        .beelay(&peer1)
        .create_doc(vec![peer2_contact])
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

    assert_eq!(commits_on_2, expected_commits);
}

#[test]
fn changes_published_after_sync() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    // First create the doc
    let (doc1_id, initial_commit) = network.beelay(&peer1).create_doc(vec![]).unwrap();
    let peer2_contact = network.beelay(&peer2).contact_card();
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
    let peer1 = network.create_peer_with_key("peer1", key.clone());

    // Create a document
    let (doc1_id, _) = network.beelay(&peer1).create_doc(vec![]).unwrap();

    assert!(!network.beelay(&peer1).storage().is_empty());
    for (key, value) in network.beelay(&peer1).storage() {
        tracing::info!("Key: {}, Value: {}", key, value.len());
    }
    // network.beelay(&peer1).shutdown();

    // Now creaet a new network and peer with the same storage
    let mut network2 = Network::new();
    let peer2 = network2.load_peer("peer2", network.beelay(&peer1).storage().clone(), key);

    // Check that the document is in storage
    let _doc = network2.beelay(&peer2).load_doc(doc1_id).unwrap();
    // TODO: re-enable once doc creation events are stored properly
    // assert_eq!(
    //     doc,
    //     vec![beelay_core::CommitOrBundle::Commit(initial_commit)]
    // );
}
