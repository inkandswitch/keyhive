use std::sync::Arc;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    principal::{agent::Agent, membered::Membered, peer::Peer, public::Public},
    test_utils::make_simple_keyhive,
};
use nonempty::nonempty;

fn main() {
    divan::main();
}

/// Generate a batch of events simulating the demo sync server scenario.
///
/// Models the following scenario:
/// - Many docs are made public
/// - Each peer is directly added to some docs
/// - When syncing events for any peer, the system must traverse delegation
///   chains for all public docs (since both individual access and public access
///   are checked)
async fn generate_events(n_peers: usize, n_public_docs: usize) -> Vec<StaticEvent<[u8; 32]>> {
    let alice = make_simple_keyhive().await.unwrap();

    let public_indie = Public.individual();
    let public_peer = Peer::Individual(public_indie.id(), Arc::new(Mutex::new(public_indie)));

    // Create public docs (Public individual as coparent, like the demo)
    let mut docs = Vec::with_capacity(n_public_docs);
    for i in 0..n_public_docs {
        let hash: [u8; 32] = blake3::hash(&(i as u64).to_le_bytes()).into();
        let doc = alice
            .generate_doc(vec![public_peer.dupe()], nonempty![hash])
            .await
            .unwrap();
        docs.push(doc);
    }

    // Register peers and add each to every doc directly
    for _ in 0..n_peers {
        let peer = make_simple_keyhive().await.unwrap();
        let peer_contact = peer.contact_card().await.unwrap();
        let peer_on_alice = alice.receive_contact_card(&peer_contact).await.unwrap();
        let peer_id = { peer_on_alice.lock().await.id() };

        for doc in &docs {
            let doc_id = { doc.lock().await.doc_id() };
            alice
                .add_member(
                    Agent::Individual(peer_id, peer_on_alice.dupe()),
                    &Membered::Document(doc_id, doc.dupe()),
                    Access::Write,
                    &[],
                )
                .await
                .unwrap();
        }
    }

    // Extract all events (HashMap iteration order = non-deterministic)
    let alice_active: Agent<_, _, _> = alice.active().lock().await.clone().into();
    let events_map = alice.static_events_for_agent(&alice_active).await.unwrap();
    events_map.into_values().collect()
}

#[divan::bench(args = [
    (5, 10),
    (10, 20),
    (15, 30),
    (20, 40),
    (30, 60),
])]
fn ingest_unsorted_static_events(
    bencher: divan::Bencher,
    (n_peers, n_public_docs): (usize, usize),
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let events = rt.block_on(generate_events(n_peers, n_public_docs));
    let event_count = events.len();

    eprintln!("n_peers={n_peers}, n_public_docs={n_public_docs}: generated {event_count} events");

    bencher
        .counter(divan::counter::ItemsCount::new(event_count))
        .with_inputs(|| events.clone())
        .bench_local_values(|events| {
            rt.block_on(async {
                let dest = make_simple_keyhive().await.unwrap();
                dest.ingest_unsorted_static_events(events).await;
            });
        });
}
