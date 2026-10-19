#[path = "bench_utils.rs"]
mod bench_utils;

use bench_utils::setup_scenario;
use divan::Bencher;
use tokio::runtime::Runtime;

fn main() {
    divan::main();
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn per_agent_calls(bencher: Bencher, n_peers: usize) {
    let rt = Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers, 0));

    bencher.bench_local(|| {
        rt.block_on(async {
            for agent_id in &scenario.agents {
                std::hint::black_box(
                    scenario
                        .keyhive
                        .event_digests_for_agent(*agent_id)
                        .await
                        .expect("selects events"),
                );
            }
        });
    });
}

#[divan::bench(args = [5, 10, 20, 30, 100])]
fn all_agents_single_call(bencher: Bencher, n_peers: usize) {
    let rt = Runtime::new().unwrap();
    let scenario = rt.block_on(setup_scenario(n_peers, 0));

    bencher.bench_local(|| {
        rt.block_on(async {
            std::hint::black_box(
                scenario
                    .keyhive
                    .all_agent_events()
                    .await
                    .expect("selects events"),
            );
        });
    });
}
