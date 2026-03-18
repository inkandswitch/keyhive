//! Benchmark for toggling delegate and revoke public access on a document.
//!
//! cargo bench --bench bench_toggling_delegate_revoke --features test_utils

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered, public::Public},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;
use std::sync::Arc;

fn main() {
    divan::main();
}

#[divan::bench(
    args = [1, 3, 5, 7, 10],
    sample_count = 1,
    sample_size = 1,
)]
fn toggle_delegate_revoke(bencher: divan::Bencher, prior_toggles: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (kh, membered_doc, public_agent, public_id) = rt.block_on(async {
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

        // Build up history of prior toggles
        for _ in 0..prior_toggles {
            kh.add_member(public_agent.clone(), &membered_doc, Access::Write, &[])
                .await
                .expect("add_member should succeed");
            kh.revoke_member(public_id, true, &membered_doc)
                .await
                .expect("revoke_member should succeed");
        }

        (kh, membered_doc, public_agent, public_id)
    });

    bencher.bench_local(|| {
        rt.block_on(async {
            kh.add_member(public_agent.clone(), &membered_doc, Access::Write, &[])
                .await
                .expect("add_member should succeed");
            kh.revoke_member(public_id, true, &membered_doc)
                .await
                .expect("revoke_member should succeed");
        });
    });
}
