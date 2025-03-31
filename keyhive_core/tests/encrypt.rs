use dupe::Dupe;
use keyhive_core::{
    access::Access,
    archive::Archive,
    crypto::{encrypted, signer::memory::MemorySigner},
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::{log::Log, no_listener::NoListener},
    store::ciphertext::memory::MemoryCiphertextStore,
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

#[tokio::test]
async fn test_decrypt_after_archive_round_trip() -> TestResult {
    test_utils::init_logging();
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    let log = Log::new();
    let mut original_alice =
        Keyhive::generate(sk.clone(), store, log.dupe(), rand::thread_rng()).await?;

    tracing::info!("Creating archive BEFORE document created");
    let early_archive = original_alice.into_archive();

    let init_content = b"hello world";
    let init_hash: [u8; 32] = blake3::hash(init_content.as_slice()).into();

    let original_doc = original_alice
        .generate_doc(vec![], nonempty![init_hash])
        .await?;
    let doc_id = original_doc.borrow().doc_id();

    let encrypted = original_alice
        .try_encrypt_content(
            original_doc.clone(),
            &init_hash,
            &vec![],
            init_content.as_slice(),
        )
        .await?;
    assert!(encrypted.update_op().is_none());

    tracing::info!("Round tripping...");
    let round_tripped =
        original_alice.try_decrypt_content(original_doc.clone(), encrypted.encrypted_content())?;
    assert_eq!(round_tripped, init_content);

    let static_events = log.to_static_events();
    assert!(!log.is_empty());

    let mut rehydrated_alice = Keyhive::try_from_archive(
        &early_archive,
        sk,
        MemoryCiphertextStore::new(),
        NoListener,
        rand::thread_rng(),
    )?;

    rehydrated_alice.ingest_unsorted_static_events(static_events)?;

    let rehydrated_doc = rehydrated_alice.get_document(doc_id).unwrap();
    rehydrated_doc.borrow_mut().rebuild();
    assert_eq!(
        rehydrated_doc.borrow().cgka()?.ops_graph_len().clone(),
        original_doc.borrow().cgka()?.ops_graph_len().clone()
    );

    tracing::error!(
        "{:?}",
        early_archive
            .docs()
            .get(&doc_id)
            .expect("doc to exist")
            .cgka
            .clone()
            .unwrap()
            .owner_sks
    );
    assert!(rehydrated_alice.active().borrow().remove_me().len() > 0);
    assert_eq!(
        rehydrated_alice.active().borrow().remove_me(),
        original_alice.active().borrow().remove_me()
    );

    let decrypted = rehydrated_alice
        .try_decrypt_content(rehydrated_doc.dupe(), encrypted.encrypted_content())?;

    assert_eq!(decrypted, init_content);
    Ok(())
}
