use std::collections::HashMap;

use beelay_core::{Commit, CommitOrBundle};
use keyhive_core::debug_events::{terminal, Nicknames};
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn decrypt_on_reload() {
    // Check that all the CGKA ops are persisted as they occur so we can reload
    // the beelay and still sucessfully decrypt
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1").build();

    let (doc_id, initial_commit) = network.beelay(&peer1).create_doc(vec![]).unwrap();
    let mut commits = vec![CommitOrBundle::Commit(initial_commit.clone())];
    let mut last_commit = initial_commit;
    for i in 0..2 {
        let contents = format!("hello {}", i);
        let hash = blake3::hash(contents.as_bytes());
        let commit = Commit::new(
            vec![last_commit.hash()],
            "hello".into(),
            hash.as_bytes().into(),
        );
        network
            .beelay(&peer1)
            .add_commits(doc_id, vec![commit.clone()])
            .unwrap();
        commits.push(CommitOrBundle::Commit(last_commit));
        last_commit = commit.clone();
    }

    keyhive_core::debug_events::terminal::print_event_table_verbose(
        network.beelay(&peer1).log_keyhive_events(
            Nicknames::default()
                .with_nickname(peer1.as_bytes(), "peer1")
                .with_nickname(doc_id.as_bytes(), "doc"),
        ),
    );

    network.reload_peer(&peer1);

    keyhive_core::debug_events::terminal::print_event_table_verbose(
        network.beelay(&peer1).log_keyhive_events(
            Nicknames::default()
                .with_nickname(peer1.as_bytes(), "peer1")
                .with_nickname(doc_id.as_bytes(), "doc"),
        ),
    );

    let doc = network.beelay(&peer1).load_doc(doc_id).unwrap();
    // FIXME assert_eq!(doc, commits);
}
