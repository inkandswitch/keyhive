//! Benchmarks for `ingest_unsorted_static_events`.
//!
//! cargo bench --bench bench_ingest --features test_utils

use divan::{counter::ItemsCount, Bencher};
use keyhive_core::{event::static_event::StaticEvent, test_utils::make_simple_keyhive};
use keyline::power::Power;
use nonempty::nonempty;
use tokio::runtime::Runtime;

fn main() {
    divan::main();
}

async fn generate_events(n_peers: usize, n_docs: usize) -> Vec<StaticEvent<[u8; 32]>> {
    let alice = make_simple_keyhive().await.unwrap();

    let mut docs = Vec::with_capacity(n_docs);
    for i in 0..n_docs {
        let hash: [u8; 32] = blake3::hash(&(i as u64).to_le_bytes()).into();
        let doc = alice.generate_doc(vec![], nonempty![hash]).await.unwrap();
        docs.push(doc);
    }

    for _ in 0..n_peers {
        let peer = make_simple_keyhive().await.unwrap();
        let peer_contact = peer.generate_contact_card().await.unwrap();
        let peer_id = alice.receive_contact_card(&peer_contact).await.unwrap();

        for doc_id in &docs {
            alice
                .add_member(peer_id, *doc_id, Power::Edit)
                .await
                .unwrap();
        }
    }

    let alice_id = { alice.active().id() };
    let events_map = alice
        .static_events_for_agent(alice_id)
        .await
        .expect("selects events");
    events_map.into_values().collect()
}

#[divan::bench(
    args = [
        (5, 10),
        (10, 20),
        (15, 30),
        (20, 40),
        (30, 60),
    ],
    sample_count = 5,
    sample_size = 1,
)]
fn ingest_unsorted_static_events(bencher: Bencher, (n_peers, n_docs): (usize, usize)) {
    let rt = Runtime::new().unwrap();
    let events = rt.block_on(generate_events(n_peers, n_docs));
    let event_count = events.len();

    eprintln!("n_peers={n_peers}, n_docs={n_docs}: generated {event_count} events");

    bencher
        .counter(ItemsCount::new(event_count))
        .with_inputs(|| events.clone())
        .bench_local_values(|events| {
            rt.block_on(async {
                let dest = make_simple_keyhive().await.unwrap();
                dest.ingest_unsorted_static_events(events).await;
            });
        });
}
