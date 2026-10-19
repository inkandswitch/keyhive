//! Benchmark for `reverse_topsort` scaling with deep delegation chains.
//!
//! Measures the cost of one delegate + revoke cycle (which triggers `rebuild()`
//! then `reverse_topsort()`) after n prior cycles have built up chain depth.
//!
//! cargo bench --bench bench_reverse_topsort --features test_utils

use future_form::Sendable;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access, keyhive::Keyhive, listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore, test_utils::make_simple_keyhive,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;
use std::sync::Arc;

fn main() {
    divan::main();
}

#[divan::bench(
    args = [1, 5, 10, 20, 50],
)]
fn reverse_topsort_via_toggle(bencher: divan::Bencher, prior_toggles: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (kh, doc, member) = rt.block_on(async {
        let mut csprng = rand::rngs::OsRng;
        let sk = MemorySigner::generate(&mut csprng);
        let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new()));

        let kh: Keyhive<Sendable, MemorySigner, [u8; 32], Vec<u8>, _, NoListener, _> =
            Keyhive::generate(sk.clone(), store.clone(), NoListener, rand::rngs::OsRng)
                .await
                .expect("keyhive generation should succeed");

        let member_card = make_simple_keyhive()
            .await
            .expect("keyhive generation should succeed")
            .get_existing_contact_card()
            .await;
        let member = kh
            .receive_contact_card(&member_card)
            .await
            .expect("a fresh contact card is valid");

        let doc = kh
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .expect("doc generation should succeed");

        // Build up history of prior toggles
        for _ in 0..prior_toggles {
            kh.add_member(member, doc, Access::Edit, &[])
                .await
                .expect("add_member should succeed");
            kh.revoke_member(member, true, doc)
                .await
                .expect("revoke_member should succeed");
        }

        (kh, doc, member)
    });

    bencher.bench_local(|| {
        rt.block_on(async {
            kh.add_member(member, doc, Access::Edit, &[])
                .await
                .expect("add_member should succeed");
            kh.revoke_member(member, true, doc)
                .await
                .expect("revoke_member should succeed");
        });
    });
}
