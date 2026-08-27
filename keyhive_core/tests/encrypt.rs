use future_form::Local;
use std::{collections::HashMap, sync::Arc};

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::log::Log,
    principal::{agent::Agent, peer::Peer},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{digest::Digest, signer::memory::MemorySigner};
use nonempty::nonempty;
use testresult::TestResult;

/// Build the well-known `Public` principal as an [`Agent`].
fn public_agent<F, S, T, L>() -> Agent<F, S, T, L>
where
    F: future_form::FutureForm,
    S: keyhive_crypto::signer::async_signer::AsyncSigner<F>,
    T: keyhive_crypto::content::reference::ContentRef,
    L: keyhive_core::listener::membership::MembershipListener<F, S, T>,
{
    let public_individual = keyhive_core::principal::public::Public.individual();
    Agent::Individual(
        public_individual.id(),
        Arc::new(Mutex::new(public_individual)),
    )
}

#[allow(clippy::type_complexity)]
async fn make_keyhive() -> Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    Log<Local, MemorySigner>,
    rand::rngs::ThreadRng,
> {
    make_keyhive_with_signer(MemorySigner::generate(&mut rand::thread_rng())).await
}

#[allow(clippy::type_complexity)]
async fn make_keyhive_with_signer(
    sk: MemorySigner,
) -> Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    Log<Local, MemorySigner>,
    rand::rngs::ThreadRng,
> {
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    let log = Log::<Local, _, _>::new();
    Keyhive::<Local, _, _, _, _, _, _>::generate(sk, store, log, rand::thread_rng())
        .await
        .unwrap()
}

/// A dual-instance sender creates a doc with a fresh group coparent (no
/// Public), adds Bob (CGKA Add), SW encrypts (has_pcs_key=false due to
/// Add blanking root, generates PCS Update), Bob receives all events and
/// tries to decrypt.
///
/// This mirrors a real client flow where document generation creates a
/// fresh group and passes it as a coparent. The CGKA tree has DocOwner +
/// Alice's individual (from the group) + Bob. No Public member.
#[tokio::test]
async fn test_dual_instance_with_added_member_decrypt() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let bob = make_keyhive().await;

    let init_content = b"hello from dual-instance Alice to Bob".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Tab creates doc with a fresh group coparent.
    // No Public in the CGKA tree. CGKA has: doc identity + Alice's individual.
    let group = tab.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc_id = tab
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash],
        )
        .await?;

    // Tab adds Bob to the doc. This creates a CGKA Add(Bob) op which
    // blanks the root key in the CGKA tree.
    {
        let indie = bob.active().lock().await.individual().lock().await.clone();
        tab.register_individual(Arc::new(Mutex::new(indie))).await;
    }
    tab.add_member(bob.id(), doc_id, Access::Read, &[]).await?;

    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events_for_self = tab.static_events_for_agent(&tab_active_agent).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events_for_self.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} stuck",
        sw_pending.len()
    );

    let encrypted = sw
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    let bob_agent: Agent<_, _, _, _> = bob.active().lock().await.clone().into();
    let tab_events_for_bob = tab.static_events_for_agent(&bob_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&bob_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Two keyhive instances with the same identity (Tab + SW pattern).
/// Tab creates a doc with Public access, SW encrypts content.
/// Bob receives events from both instances and must decrypt.
///
/// This reproduces a client architecture where Tab and SW are separate
/// keyhive instances sharing the same signing key and prekey secrets.
#[tokio::test]
async fn test_dual_instance_encrypt_decrypt() -> TestResult {
    test_utils::init_logging();

    // --- Setup: Alice has two instances (Tab and SW) with the same signer ---
    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    // Transfer Tab's prekey secrets to SW (simulates shared IndexedDB storage)
    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let bob = make_keyhive().await;

    let init_content = b"hello from dual-instance Alice".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // --- Tab creates a doc with Public as a member ---
    let doc_id = tab.generate_doc(vec![], nonempty![init_hash]).await?;

    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;

    tab.force_pcs_update(doc_id).await?;

    // --- Sync Tab's events to SW (simulates server relay) ---
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events_for_self = tab.static_events_for_agent(&tab_active_agent).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events_for_self.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} events stuck in pending",
        sw_pending.len()
    );

    // --- SW encrypts content (generates PCS Update op) ---
    let encrypted = sw
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // --- Sync all events to Bob ---
    // Bob receives events from both Tab and SW (via server).
    // Merge and deduplicate by hash.
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} events stuck in pending",
        bob_pending.len()
    );

    // --- Bob decrypts ---
    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Test when SW does not have Tab's prekey secrets.
/// This happens if loadPrekeySecrets fails or the prekey
/// storage is empty. The SW can't process CGKA Add ops for the
/// active agent, leaving them pending.
#[tokio::test]
async fn test_dual_instance_without_prekey_secrets() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;
    // Deliberately not transferring prekey secrets

    let bob = make_keyhive().await;

    let init_content = b"no prekey secrets test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc_id = tab.generate_doc(vec![], nonempty![init_hash]).await?;

    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;
    tab.force_pcs_update(doc_id).await?;

    // Sync Tab's events to SW without prekey secrets. SW cannot process the
    // CGKA Add ops for the active agent, so they stay pending.
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(
        sw_pending
            .iter()
            .any(|e| matches!(e.as_ref(), StaticEvent::CgkaOperation(_))),
        "SW should have a stuck CGKA op without prekey secrets, {} pending",
        sw_pending.len()
    );

    // Transfer prekey secrets. import_prekey_secrets retries pending events,
    // so the previously-stuck CGKA ops should drain.
    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;
    let still_pending = sw.ingest_unsorted_static_events(vec![]).await;
    assert!(
        still_pending.is_empty(),
        "SW should have no pending events after importing prekey secrets. {} stuck",
        still_pending.len()
    );

    // With SW recovered, it can encrypt content under the doc's current PCS key.
    let encrypted = sw
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // Now collect events from both and send to Bob. With SW recovered, Bob
    // should ingest everything via Public.
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;
    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events once SW has recovered. {} stuck",
        bob_pending.len()
    );

    // The real end-state: Bob reads the content SW encrypted, via Public.
    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Test the scenario where SW's events are collected via the Log listener
/// (as in the real sync protocol) rather than via static_events_for_agent.
/// The Log captures events fired during ingestion, which might include
/// re-emitted Tab events alongside SW-generated events.
#[tokio::test]
async fn test_dual_instance_log_based_sync() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;

    // SW uses a Log listener to capture events (simulates sync protocol)
    let sw_log = Log::<Local, MemorySigner>::new();
    let sw = Keyhive::<Local, _, _, _, _, _, _>::generate(
        alice_signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        sw_log.clone(),
        rand::thread_rng(),
    )
    .await
    .unwrap();

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let bob = make_keyhive().await;

    let init_content = b"log-based sync test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let public_agent: Agent<_, _, _, _> = public_agent();

    // Tab creates doc with Public, revokes and re-adds (generates revocations)
    let doc_id = tab.generate_doc(vec![], nonempty![init_hash]).await?;

    tab.add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;

    tab.revoke_member(
        keyhive_core::principal::public::Public.individual().id(),
        true,
        doc_id,
    )
    .await?;

    tab.add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;

    tab.force_pcs_update(doc_id).await?;

    // Sync Tab events to SW
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;

    // Clear SW log before ingestion so we only capture events from this ingestion
    while sw_log.pop().await.is_some() {}

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(sw_pending.is_empty(), "SW pending: {}", sw_pending.len());

    // SW encrypts
    let encrypted = sw
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // Collect SW events from Log (this is what the sync protocol would send)
    let mut sw_log_events: Vec<StaticEvent<[u8; 32]>> = Vec::new();
    while let Some(evt) = sw_log.pop().await {
        sw_log_events.push(StaticEvent::from(evt));
    }

    // Bob receives Tab's events (via server) plus SW's log events (via server)
    // This simulates the server relaying events from both instances
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;

    // Merge: Tab's state-based events + SW's log-based events
    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    for evt in sw_log_events {
        all_events.insert(Digest::hash(&evt), evt);
    }

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Individual delegation fails when receiver has a dual-instance
/// keyhive (Tab + SW) and the sender picks a prekey from one instance that
/// the other instance doesn't have the secret key for.
///
/// Scenario: Bob has Tab and SW (same signing key, different prekeys).
/// Alice (the server) has Bob registered with Tab-generated prekeys.
/// Alice creates a doc, individually delegates to Bob, generating a CGKA
/// Add(Bob, tab_prekey). Bob's SW tries to ingest events but doesn't have
/// the secret key for tab_prekey. Result: UnknownInvitePrekey, CGKA ops
/// stuck in pending.
///
/// After ingestion leaves pending events,
/// the SW imports prekey secrets from shared storage (which the Tab has
/// written to). `import_prekey_secrets` automatically drains pending.
#[tokio::test]
async fn test_dual_instance_receiver_unknown_invite_prekey() -> TestResult {
    test_utils::init_logging();

    // Bob has two keyhive instances with the same signing key.
    // At init, each generates 7 random prekeys independently.
    let bob_signer = MemorySigner::generate(&mut rand::thread_rng());
    let bob_tab = make_keyhive_with_signer(bob_signer.clone()).await;
    let bob_sw = make_keyhive_with_signer(bob_signer.clone()).await;

    // Simulate the real startup: Tab saves its prekey secrets to shared
    // storage (persistent storage in a real client). We hold onto the bytes as our "storage."
    let shared_storage = bob_tab.export_prekey_secrets().await?;

    // Alice (the server/sender) is a separate identity
    let alice = make_keyhive().await;

    // Alice registers Bob using Bob-Tab's individual. This means Alice
    // only knows Bob's Tab-generated prekeys. When Alice picks a prekey
    // for CGKA Add(Bob), she'll pick a Tab-generated one.
    {
        let indie = bob_tab
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone();
        alice.register_individual(Arc::new(Mutex::new(indie))).await;
    }

    // Alice creates a doc and individually delegates to Bob.
    let init_content = b"individual delegation test content".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc_id = alice.generate_doc(vec![], nonempty![init_hash]).await?;

    alice
        .add_member(bob_tab.id(), doc_id, Access::Read, &[])
        .await?;

    // Alice encrypts so there's a PCS Update op in the tree
    let encrypted = alice
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // Collect events for Bob from Alice
    let bob_agent: Agent<_, _, _, _> = bob_sw.active().lock().await.clone().into();
    let events_for_bob = alice.static_events_for_agent(&bob_agent).await;

    // Bob's SW ingests. The CGKA Add(Bob, tab_prekey) goes to pending
    // because SW doesn't have Tab's prekey secret.
    let pending = bob_sw
        .ingest_unsorted_static_events(events_for_bob.into_values().collect())
        .await;
    assert!(
        pending
            .iter()
            .any(|e| matches!(e.as_ref(), StaticEvent::CgkaOperation(_))),
        "Expected a stuck CGKA op (the Add blocked on the missing invite prekey), {} pending",
        pending.len()
    );

    // Simulate the retry path: pending events exist, so SW loads
    // prekey secrets from shared storage and re-ingests.
    bob_sw.import_prekey_secrets(&shared_storage).await?;
    let still_pending = bob_sw.pending_event_hashes().await;
    assert!(
        still_pending.is_empty(),
        "After importing prekey secrets and re-ingesting, \
         SW should have no pending events. {} stuck",
        still_pending.len()
    );

    // The real end-state: after recovering the invite prekey, SW can derive the
    // key and read the content Alice encrypted.
    let decrypted = bob_sw
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Full dual-instance scenario: dual-instance sender (Tab + SW), group coparent,
/// server relay as intermediary. Events flow through the server before
/// reaching the receiver, matching the real sync path.
#[tokio::test]
async fn test_dual_instance_public_via_server_relay_decrypt() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let server = make_keyhive().await;
    let bob = make_keyhive().await;

    let init_content = b"dual instance public via server relay".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Tab creates doc with group coparent
    let group = tab.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc_id = tab
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash],
        )
        .await?;

    // Tab adds server relay
    {
        let indie = server
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone();
        tab.register_individual(Arc::new(Mutex::new(indie))).await;
    }
    tab.add_member(server.id(), doc_id, Access::Read, &[])
        .await?;

    // Tab calls setPublicAccess
    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;
    tab.force_pcs_update(doc_id).await?;

    // Sync Tab events to SW
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(sw_pending.is_empty(), "SW pending: {}", sw_pending.len());

    // SW encrypts
    let encrypted = sw
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // Events flow through server: Alice (Tab + SW) → Server → Bob
    let server_agent: Agent<_, _, _, _> = server.active().lock().await.clone().into();
    let tab_events_for_server = tab.static_events_for_agent(&server_agent).await;
    let sw_events_for_server = sw.static_events_for_agent(&server_agent).await;
    let mut server_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    server_events.extend(tab_events_for_server);
    server_events.extend(sw_events_for_server);

    let server_pending = server
        .ingest_unsorted_static_events(server_events.into_values().collect())
        .await;
    assert!(
        server_pending.is_empty(),
        "Server should ingest all. {} stuck",
        server_pending.len()
    );

    // Server serves events to Bob via Public visibility
    let events_for_bob = server.static_events_for_agent(&public_agent).await;

    let bob_pending = bob
        .ingest_unsorted_static_events(events_for_bob.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all. {} stuck",
        bob_pending.len()
    );

    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}
