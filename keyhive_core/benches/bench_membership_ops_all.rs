use std::sync::Arc;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    crypto::signer::memory::MemorySigner,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered, peer::Peer, public::Public},
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::make_simple_keyhive,
};
use nonempty::nonempty;

fn main() {
    divan::main();
}

type BenchKeyhive = Keyhive<
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    rand::rngs::OsRng,
>;
type BenchAgent = Agent<MemorySigner, [u8; 32], NoListener>;

struct Scenario {
    keyhive: BenchKeyhive,
    agents: Vec<BenchAgent>,
}

/// Set up a scenario with `n_peers` peers, each added to 2 docs.
/// One group is created containing the second half of the peers and added to the second doc,
/// so there is overlapping membership via both direct and transitive paths.
async fn setup_scenario(n_peers: usize) -> Scenario {
    let alice = make_simple_keyhive().await.unwrap();

    let public_indie = Public.individual();
    let public_peer = Peer::Individual(public_indie.id(), Arc::new(Mutex::new(public_indie)));

    // Create peers
    let mut peers_on_alice = Vec::with_capacity(n_peers);
    for _ in 0..n_peers {
        let peer = make_simple_keyhive().await.unwrap();
        let peer_contact = peer.contact_card().await.unwrap();
        let peer_on_alice = alice.receive_contact_card(&peer_contact).await.unwrap();
        let peer_id = { peer_on_alice.lock().await.id() };
        peers_on_alice.push((peer_id, peer_on_alice));
    }

    // doc1: all peers are direct members
    let doc1 = alice
        .generate_doc(vec![public_peer.dupe()], nonempty![[0u8; 32]])
        .await
        .unwrap();
    let doc1_id = doc1.lock().await.doc_id();
    for (peer_id, peer_on_alice) in &peers_on_alice {
        alice
            .add_member(
                Agent::Individual(*peer_id, peer_on_alice.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    }

    // doc2: first half are direct members
    let doc2 = alice
        .generate_doc(vec![public_peer.dupe()], nonempty![[1u8; 32]])
        .await
        .unwrap();
    let doc2_id = doc2.lock().await.doc_id();
    let half = n_peers / 2;
    for (peer_id, peer_on_alice) in &peers_on_alice[..half] {
        alice
            .add_member(
                Agent::Individual(*peer_id, peer_on_alice.dupe()),
                &Membered::Document(doc2_id, doc2.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    }

    // group: second half of peers, then group added to doc2
    let group = alice.generate_group(vec![]).await.unwrap();
    let group_id = group.lock().await.group_id();
    for (peer_id, peer_on_alice) in &peers_on_alice[half..] {
        alice
            .add_member(
                Agent::Individual(*peer_id, peer_on_alice.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    }
    alice
        .add_member(
            Agent::Group(group_id, group.dupe()),
            &Membered::Document(doc2_id, doc2.dupe()),
            Access::Read,
            &[],
        )
        .await
        .unwrap();

    let agents: Vec<BenchAgent> = peers_on_alice
        .iter()
        .map(|(id, indie)| Agent::Individual(*id, indie.dupe()))
        .collect();

    Scenario {
        keyhive: alice,
        agents,
    }
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn per_agent_calls(bencher: divan::Bencher, n_peers: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers));

    bencher.bench_local(|| {
        rt.block_on(async {
            for agent in &scenario.agents {
                std::hint::black_box(scenario.keyhive.membership_ops_for_agent(agent).await);
            }
        });
    });
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn all_agents_single_call(bencher: divan::Bencher, n_peers: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers));

    bencher.bench_local(|| {
        rt.block_on(async {
            std::hint::black_box(scenario.keyhive.membership_ops_for_all_agents().await);
        });
    });
}
