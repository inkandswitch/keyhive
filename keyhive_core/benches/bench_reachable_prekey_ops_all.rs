#[path = "bench_utils.rs"]
mod bench_utils;

use bench_utils::setup_scenario;

/// Number of extra prekey expand+rotate cycles per peer.
const PREKEY_ROTATIONS_PER_PEER: usize = 5;

fn main() {
    divan::main();
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn per_agent_calls(bencher: divan::Bencher, n_peers: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers, PREKEY_ROTATIONS_PER_PEER));

    bencher.bench_local(|| {
        rt.block_on(async {
            for agent in &scenario.agents {
                std::hint::black_box(scenario.keyhive.reachable_prekey_ops_for_agent(agent).await);
            }
        });
    });
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn all_agents_single_call(bencher: divan::Bencher, n_peers: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers, PREKEY_ROTATIONS_PER_PEER));

    bencher.bench_local(|| {
        rt.block_on(async {
            std::hint::black_box(scenario.keyhive.reachable_prekey_ops_for_all_agents().await);
        });
    });
}
