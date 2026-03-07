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
/// Models the demo pattern where:
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

    // Register peers and add each to every doc directly.
    // Also collect each peer's own prekey events (Add ops) since alice's
    // keyhive only has RotateKeyOps from contact cards, not the original
    // AddKeyOps that a real server would have received from each peer.
    let mut peer_prekey_events: Vec<StaticEvent<[u8; 32]>> = Vec::new();

    for _ in 0..n_peers {
        let peer = make_simple_keyhive().await.unwrap();

        // Collect the peer's own prekey events (AddKeyOps)
        let peer_active: Agent<_, _, _> = peer.active().lock().await.clone().into();
        for key_ops in peer.reachable_prekey_ops_for_agent(&peer_active).await.values() {
            for key_op in key_ops {
                use keyhive_core::principal::individual::op::KeyOp;
                let static_ev: StaticEvent<[u8; 32]> = match key_op.as_ref().clone() {
                    KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new((*add).clone())),
                    KeyOp::Rotate(rot) => StaticEvent::PrekeyRotated(Box::new((*rot).clone())),
                };
                peer_prekey_events.push(static_ev);
            }
        }

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

    // Extract alice's events + merge in peer prekey events
    let alice_active: Agent<_, _, _> = alice.active().lock().await.clone().into();
    let mut events_map = alice.static_events_for_agent(&alice_active).await.unwrap();
    for ev in peer_prekey_events {
        use keyhive_core::crypto::digest::Digest;
        let hash = Digest::hash(&ev);
        events_map.entry(hash).or_insert(ev);
    }

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

/// Generate events with deep delegation chains via repeated revoke+re-add cycles.
/// Each cycle creates a revocation and new delegations that reference it,
/// building up chain depth and exercising reverse_topsort's O(N²) behavior.
async fn generate_deep_chain_events(n_cycles: usize) -> Vec<StaticEvent<[u8; 32]>> {
    let alice = make_simple_keyhive().await.unwrap();

    let hash: [u8; 32] = blake3::hash(b"test-doc").into();
    let doc = alice
        .generate_doc(vec![], nonempty![hash])
        .await
        .unwrap();
    let doc_id = { doc.lock().await.doc_id() };

    // Create a pool of peers and add them all initially
    let mut peer_ids = Vec::new();
    let mut peer_agents = Vec::new();
    for _ in 0..3 {
        let peer = make_simple_keyhive().await.unwrap();
        let peer_contact = peer.contact_card().await.unwrap();
        let peer_on_alice = alice.receive_contact_card(&peer_contact).await.unwrap();
        let peer_id = { peer_on_alice.lock().await.id() };
        let agent = Agent::Individual(peer_id, peer_on_alice.dupe());
        alice
            .add_member(
                agent.clone(),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
        peer_ids.push(peer_id.into());
        peer_agents.push((peer_id, peer_on_alice));
    }

    // Repeated cycles: revoke one member (retain others), then re-add them
    for i in 0..n_cycles {
        let revoke_idx = i % peer_ids.len();
        let revoke_id = peer_ids[revoke_idx];

        // Revoke with retain_all=true: creates revocation + re-adds for others
        alice
            .revoke_member(revoke_id, true, &Membered::Document(doc_id, doc.dupe()))
            .await
            .unwrap();

        // Re-add the revoked member
        let (peer_id, peer_on_alice) = &peer_agents[revoke_idx];
        alice
            .add_member(
                Agent::Individual(*peer_id, peer_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    }

    let alice_active: Agent<_, _, _> = alice.active().lock().await.clone().into();
    let events_map = alice.static_events_for_agent(&alice_active).await.unwrap();
    events_map.into_values().collect()
}

/// Benchmark event generation with deep delegation chains.
/// Each add_member/revoke_member call triggers rebuild() -> reverse_topsort(),
/// so this directly measures reverse_topsort scaling as the group grows.
#[divan::bench(args = [10, 50, 100, 200, 300, 400])]
fn generate_deep_chain(bencher: divan::Bencher, n_cycles: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    bencher.bench_local(|| {
        rt.block_on(generate_deep_chain_events(n_cycles));
    });
}

/// Benchmark with deep delegation chains (revoke+re-add cycles) to stress reverse_topsort.
#[divan::bench(args = [10, 50, 100, 200, 300, 400, 500])]
fn ingest_deep_chain(bencher: divan::Bencher, n_cycles: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let events = rt.block_on(generate_deep_chain_events(n_cycles));
    let event_count = events.len();
    eprintln!("deep_chain({}): {} events", n_cycles, event_count);

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
