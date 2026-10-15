#[path = "bench_utils.rs"]
#[allow(dead_code)]
mod bench_utils;

use bench_utils::BenchKeyhive;

use divan::Bencher;
use keyhive_core::{
    principal::{group::id::GroupId, individual::id::IndividualId, public::Public},
    test_utils::make_simple_keyhive,
};
use keyline::power::Power;
use nonempty::nonempty;
use tokio::runtime::Runtime;

fn main() {
    divan::main();
}

/// Create a fresh peer keyhive, exchange contact cards with alice, and return
/// the peer's id as seen by alice.
async fn make_peer_id(alice: &BenchKeyhive) -> IndividualId {
    let peer = make_simple_keyhive().await.unwrap();
    let peer_contact = peer.generate_contact_card().await.unwrap();
    alice.receive_contact_card(&peer_contact).await.unwrap()
}

/// Build a keyhive with `n_docs` docs and nested group membership.
///
/// Structure:
///   - A chain of 3 groups: g_bottom -> g_mid -> g_top
///   - g_top is added as a member of 2 docs (first and last)
///   - 5 peers are direct members of g_bottom
///   - A fresh peer is prepared but not yet added to g_bottom
async fn setup_many_docs_nested(n_docs: usize) -> (BenchKeyhive, GroupId, IndividualId) {
    let alice = make_simple_keyhive().await.unwrap();

    // Create a chain of 3 nested groups: g_bottom → g_mid → g_top
    let g_bottom_id = alice.generate_group(vec![]).await.unwrap();
    let g_mid_id = alice.generate_group(vec![]).await.unwrap();
    let g_top_id = alice.generate_group(vec![]).await.unwrap();

    // g_bottom is a member of g_mid
    alice
        .add_member(g_bottom_id, g_mid_id, Power::Read)
        .await
        .unwrap();

    // g_mid is a member of g_top
    alice
        .add_member(g_mid_id, g_top_id, Power::Read)
        .await
        .unwrap();

    // Add 5 peers as members of g_bottom (gives the BFS real membership to walk)
    for _ in 0..5 {
        let peer = make_peer_id(&alice).await;
        alice
            .add_member(peer, g_bottom_id, Power::Read)
            .await
            .unwrap();
    }

    // Create n_docs docs. Only 2 contain the group chain; the rest are unrelated.
    for i in 0..n_docs {
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let doc_id = alice
            .generate_doc(vec![Public.id()], nonempty![content])
            .await
            .unwrap();
        // Only the first and last docs contain the group chain
        if i == 0 || i == n_docs - 1 {
            alice
                .add_member(g_top_id, doc_id, Power::Read)
                .await
                .unwrap();
        }
    }

    // Prepare a fresh peer to add to g_bottom (the benchmark target)
    let peer = make_peer_id(&alice).await;

    (alice, g_bottom_id, peer)
}

/// Measures the cost of `add_member` to a nested group when there are many docs.
/// Each document's readers are read before and after.
#[divan::bench(args = [10, 50, 100, 500])]
fn add_member_nested_groups(bencher: Bencher, n_docs: usize) {
    let rt = Runtime::new().unwrap();

    bencher
        .with_inputs(|| rt.block_on(setup_many_docs_nested(n_docs)))
        .bench_local_values(|(alice, membered, peer)| {
            rt.block_on(async {
                std::hint::black_box(alice.add_member(peer, membered, Power::Read).await.unwrap());
            });
            // Intentional leak: prevent drop of the keyhive (with n_docs
            // Arc<Mutex<DocumentState>>s) from being measured. divan's
            // bench_local_values includes drop time, and we observed that
            // deallocation cost dominates the actual operation at higher
            // doc counts. Memory growth is bounded: divan runs each sample
            // in a fresh process, and the leaked allocations are reclaimed
            // on exit.
            std::mem::forget(alice);
        });
}

/// Measures the cost of `revoke_member` from a nested group when there are many docs.
#[divan::bench(args = [10, 50, 100, 500])]
fn revoke_member_nested_groups(bencher: Bencher, n_docs: usize) {
    let rt = Runtime::new().unwrap();

    bencher
        .with_inputs(|| {
            rt.block_on(async {
                let (alice, membered, peer) = setup_many_docs_nested(n_docs).await;
                // Add the member first so we can revoke them
                alice.add_member(peer, membered, Power::Read).await.unwrap();
                (alice, membered, peer)
            })
        })
        .bench_local_values(|(alice, membered, peer)| {
            rt.block_on(async {
                std::hint::black_box(
                    alice
                        .revoke_member(peer, true, membered)
                        .await
                        .expect("the revocation succeeds"),
                );
            });
            // Intentional leak: see comment in add_member_nested_groups
            std::mem::forget(alice);
        });
}
