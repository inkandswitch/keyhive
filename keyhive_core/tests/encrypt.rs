use keyhive_core::{
    access::Access, crypto::signer::memory::MemorySigner, keyhive::Keyhive,
    listener::no_listener::NoListener, store::ciphertext::memory::MemoryCiphertextStore,
};
use nonempty::nonempty;
use testresult::TestResult;

async fn make_keyhive() -> Keyhive<MemorySigner> {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    Keyhive::generate(sk, store, NoListener, rand::thread_rng())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_encrypt_to_added_member() -> TestResult {
    test_utils::init_logging();

    let mut alice = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;

    let mut bob = make_keyhive().await;

    alice
        .add_member(
            bob.active().clone().into(),
            &mut doc.clone().into(),
            Access::Read,
            &[],
        )
        .await?;

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // now sync everything to bob
    let events = alice.static_events_for_agent(&bob.active().clone().into())?;
    bob.ingest_unsorted_static_events(events.into_values().collect())?;

    // Now attempt to decrypt on bob
    let doc_on_bob = bob.get_document(doc.borrow().doc_id()).unwrap();
    let decrypted = bob.try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())?;

    assert_eq!(decrypted, init_content);
    Ok(())
}
