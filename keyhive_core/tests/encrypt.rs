use keyhive_core::{
    access::Access, crypto::signer::memory::MemorySigner, keyhive::Keyhive,
    listener::no_listener::NoListener,
};
use nonempty::nonempty;

async fn make_keyhive() -> Keyhive<MemorySigner> {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    Keyhive::generate(sk, NoListener, rand::thread_rng())
        .await
        .unwrap()
}

#[test_log::test(tokio::test)]
async fn test_encrypt_to_added_member() {
    let mut alice = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await
        .unwrap();

    let mut bob = make_keyhive().await;

    alice
        .add_member(
            bob.active().clone().into(),
            &mut doc.clone().into(),
            Access::Read,
            &[],
        )
        .await
        .unwrap();

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await
        .unwrap();

    // now sync everything to bob
    let events = alice
        .static_events_for_agent(&bob.active().clone().into())
        .unwrap();
    bob.ingest_unsorted_static_events(events.into_values().collect())
        .unwrap();

    // Now attempt to decrypt on bob
    let doc_on_bob = bob.get_document(doc.borrow().doc_id()).unwrap();
    let decrypted = bob
        .try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())
        .unwrap();

    assert_eq!(decrypted, init_content);
}
