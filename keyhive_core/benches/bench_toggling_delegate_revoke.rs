//! Benchmark for toggling delegate and revoke public access on a document.
//!
//! cargo bench --bench bench_toggling_delegate_revoke --features test_utils

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    crypto::signer::memory::MemorySigner,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered, public::Public},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use nonempty::nonempty;
use std::{sync::Arc, time::Instant};

fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_toggling_delegate_revoke_benchmark());
}

async fn run_toggling_delegate_revoke_benchmark() {
    println!("Benchmark: Toggling Delegate/Revoke on a Public Document\n");

    let mut csprng = rand::rngs::OsRng;
    let sk = MemorySigner::generate(&mut csprng);
    let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new()));

    let kh = Keyhive::generate(sk.clone(), store.clone(), NoListener, rand::rngs::OsRng)
        .await
        .expect("keyhive generation should succeed");

    kh.register_individual(Arc::new(Mutex::new(Public.individual())))
        .await;

    let doc = kh
        .generate_doc(vec![], nonempty![[1u8; 32]])
        .await
        .expect("doc generation should succeed");

    let doc_id = doc.lock().await.doc_id();
    let membered_doc = Membered::Document(doc_id, doc.dupe());

    let public_agent: Agent<MemorySigner> = Public.individual().into();
    let public_id = Public.id();

    println!(
        "{:>9} | {:>13} | {:>11} | {:>10}",
        "Iteration", "Delegate (ms)", "Revoke (ms)", "Total (ms)"
    );
    println!("-----------------------------------------------------");

    let iterations = 10;

    for i in 1..=iterations {
        let delegate_start = Instant::now();
        kh.add_member(public_agent.clone(), &membered_doc, Access::Write, &[])
            .await
            .expect("add_member should succeed");
        let delegate_elapsed = delegate_start.elapsed();

        let revoke_start = Instant::now();
        kh.revoke_member(public_id, true, &membered_doc)
            .await
            .expect("revoke_member should succeed");
        let revoke_elapsed = revoke_start.elapsed();

        let total_ms =
            delegate_elapsed.as_secs_f64() * 1000.0 + revoke_elapsed.as_secs_f64() * 1000.0;

        println!(
            "{:>9} | {:>13.2} | {:>11.2} | {:>10.2}",
            i,
            delegate_elapsed.as_secs_f64() * 1000.0,
            revoke_elapsed.as_secs_f64() * 1000.0,
            total_ms
        );

        if total_ms > 30_000.0 {
            println!("\nExiting early. Iteration took over 30 seconds");
            break;
        }
    }

    println!("\nFinished...");
}
