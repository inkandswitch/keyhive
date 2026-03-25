#[path = "bench_utils.rs"]
#[allow(dead_code)]
mod bench_utils;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered, peer::Peer, public::Public},
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;
use std::sync::Arc;

fn main() {
    divan::main();
}

type BenchMembered = Membered<MemorySigner, [u8; 32], NoListener>;
type BenchAgent = Agent<MemorySigner, [u8; 32], NoListener>;

/// Create a fresh peer keyhive, exchange contact cards with alice, and return
/// the peer's agent as seen by alice.
async fn make_peer_agent(alice: &bench_utils::BenchKeyhive) -> BenchAgent {
    let peer = make_simple_keyhive().await.unwrap();
    let peer_contact = peer.contact_card().await.unwrap();
    let peer_on_alice = alice.receive_contact_card(&peer_contact).await.unwrap();
    let peer_id = peer_on_alice.lock().await.id();
    Agent::Individual(peer_id, peer_on_alice)
}

/// Build a keyhive with `n_docs` docs and nested group membership.
///
/// Structure:
///   - A chain of 3 groups: g_bottom -> g_mid -> g_top
///   - g_top is added as a member of 2 docs (first and last)
///   - 5 peers are direct members of g_bottom
///   - A fresh peer is prepared but not yet added to g_bottom
async fn setup_many_docs_nested(
    n_docs: usize,
) -> (bench_utils::BenchKeyhive, BenchMembered, BenchAgent) {
    let alice = make_simple_keyhive().await.unwrap();

    let public_indie = Public.individual();
    let public_peer = Peer::Individual(public_indie.id(), Arc::new(Mutex::new(public_indie)));

    // Create a chain of 3 nested groups: g_bottom → g_mid → g_top
    let g_bottom = alice.generate_group(vec![]).await.unwrap();
    let g_bottom_id = g_bottom.lock().await.group_id();

    let g_mid = alice.generate_group(vec![]).await.unwrap();
    let g_mid_id = g_mid.lock().await.group_id();

    let g_top = alice.generate_group(vec![]).await.unwrap();
    let g_top_id = g_top.lock().await.group_id();

    // g_bottom is a member of g_mid
    alice
        .add_member(
            Agent::Group(g_bottom_id, g_bottom.dupe()),
            &Membered::Group(g_mid_id, g_mid.dupe()),
            Access::Read,
            &[],
        )
        .await
        .unwrap();

    // g_mid is a member of g_top
    alice
        .add_member(
            Agent::Group(g_mid_id, g_mid.dupe()),
            &Membered::Group(g_top_id, g_top.dupe()),
            Access::Read,
            &[],
        )
        .await
        .unwrap();

    // Add 5 peers as members of g_bottom (gives the BFS real membership to walk)
    for _ in 0..5 {
        let agent = make_peer_agent(&alice).await;
        alice
            .add_member(
                agent,
                &Membered::Group(g_bottom_id, g_bottom.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    }

    // Create n_docs docs. Only 2 contain the group chain; the rest are unrelated.
    for i in 0..n_docs {
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let doc = alice
            .generate_doc(vec![public_peer.dupe()], nonempty![content])
            .await
            .unwrap();
        // Only the first and last docs contain the group chain
        if i == 0 || i == n_docs - 1 {
            let doc_id = doc.lock().await.doc_id();
            alice
                .add_member(
                    Agent::Group(g_top_id, g_top.dupe()),
                    &Membered::Document(doc_id, doc.dupe()),
                    Access::Read,
                    &[],
                )
                .await
                .unwrap();
        }
    }

    // Prepare a fresh peer to add to g_bottom (the benchmark target)
    let agent = make_peer_agent(&alice).await;

    let membered = Membered::Group(g_bottom_id, g_bottom.dupe());

    (alice, membered, agent)
}

/// Measures the cost of `add_member` to a nested group when there are many docs.
/// Each doc's transitive_members BFS must walk through the 3-group chain.
#[divan::bench(args = [10, 50, 100, 500])]
fn add_member_nested_groups(bencher: divan::Bencher, n_docs: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    bencher
        .with_inputs(|| rt.block_on(setup_many_docs_nested(n_docs)))
        .bench_local_values(|(alice, membered, agent)| {
            rt.block_on(async {
                std::hint::black_box(
                    alice
                        .add_member(agent, &membered, Access::Read, &[])
                        .await
                        .unwrap(),
                );
            });
            // Intentional leak: prevent drop of the keyhive (with n_docs
            // Arc<Mutex<Document>>s) from being measured. divan's
            // bench_local_values includes drop time, and we observed that
            // deallocation cost dominates the actual operation at higher
            // doc counts. Memory growth is bounded: divan runs each sample
            // in a fresh process, and the leaked allocations are reclaimed
            // on exit.
            std::mem::forget(alice);
            std::mem::forget(membered);
        });
}

/// Measures the cost of `revoke_member` from a nested group when there are many docs.
#[divan::bench(args = [10, 50, 100, 500])]
fn revoke_member_nested_groups(bencher: divan::Bencher, n_docs: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    bencher
        .with_inputs(|| {
            rt.block_on(async {
                let (alice, membered, agent) = setup_many_docs_nested(n_docs).await;
                let to_revoke = agent.id();
                // Add the member first so we can revoke them
                alice
                    .add_member(agent, &membered, Access::Read, &[])
                    .await
                    .unwrap();
                (alice, membered, to_revoke)
            })
        })
        .bench_local_values(|(alice, membered, to_revoke)| {
            rt.block_on(async {
                let _ = std::hint::black_box(alice.revoke_member(to_revoke, true, &membered).await);
            });
            // Intentional leak: see comment in add_member_nested_groups
            std::mem::forget(alice);
            std::mem::forget(membered);
        });
}
