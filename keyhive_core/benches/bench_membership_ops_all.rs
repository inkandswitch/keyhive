#[path = "bench_utils.rs"]
mod bench_utils;

use bench_utils::setup_scenario;

fn main() {
    divan::main();
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn per_agent_calls(bencher: divan::Bencher, n_peers: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers, 0));

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
    let scenario = rt.block_on(setup_scenario(n_peers, 0));

    bencher.bench_local(|| {
        rt.block_on(async {
            std::hint::black_box(scenario.keyhive.membership_ops_for_all_agents().await);
        });
    });
}
