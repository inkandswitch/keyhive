use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
    tree::PathChange,
};
use dupe::Dupe;
use keyhive_core::{
    access::Access,
    crypto::digest::Digest,
    keyhive::ReceiveCgkaOpError,
    principal::{
        document::id::DocumentId, identifier::Identifier, individual::Individual,
        membered::Membered,
    },
};
use keyhive_crypto::{share_key::ShareKey, signed::Signed, verifiable::Verifiable};
use nonempty::nonempty;
use testresult::TestResult;

type Kh = keyhive_core::keyhive::Keyhive<
    future_form::Sendable,
    keyhive_crypto::signer::memory::MemorySigner,
    [u8; 32],
    Vec<u8>,
    keyhive_core::store::ciphertext::memory::MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    keyhive_core::listener::no_listener::NoListener,
    rand::rngs::OsRng,
>;

type Mem = Membered<
    future_form::Sendable,
    keyhive_crypto::signer::memory::MemorySigner,
    [u8; 32],
    keyhive_core::listener::no_listener::NoListener,
>;

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Kh, doc: DocumentId) -> Vec<Digest<Signed<CgkaOperation>>> {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap().unwrap();
    let referenced: std::collections::HashSet<_> = ops
        .iter()
        .flat_map(|op| op.payload.predecessors())
        .collect();
    ops.iter()
        .map(|op| Digest::hash(op.as_ref()))
        .filter(|d| !referenced.contains(d))
        .collect()
}

/// Whether `observer`'s tree contains a CGKA op signed by `issuer`.
async fn contains_op_from(
    observer: &Kh,
    doc: DocumentId,
    issuer: ed25519_dalek::VerifyingKey,
) -> bool {
    let ops = observer
        .cgka_ops_for_doc(&doc)
        .await
        .unwrap()
        .unwrap_or_default();
    ops.iter().any(|op| op.issuer == issuer)
}

/// One of `kh`'s own prekeys it would use to join `doc`.
async fn own_prekey(kh: &Kh, doc: DocumentId) -> ShareKey {
    let indie = kh.get_individual(kh.id()).await.unwrap();
    let guard = indie.lock().await;
    *guard.pick_prekey(doc)
}

/// Register `who`'s identity with `observer` so it can be added.
async fn learn(observer: &Kh, who: &Kh) -> keyhive_core::principal::individual::id::IndividualId {
    let prekey = who.expand_prekeys().await.unwrap();
    let indie = std::sync::Arc::new(futures::lock::Mutex::new(Individual::new(
        keyhive_core::principal::individual::op::KeyOp::Add(prekey),
    )));
    let id = indie.lock().await.id();
    observer.register_individual(indie).await;
    id
}

/// Alice creates a document and adds Bob as a reader.
async fn doc_with_alice_and_bob() -> TestResult<(Kh, Kh, DocumentId)> {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_id = { doc.lock().await.doc_id() };
    let bob_agent = alice.get_agent(bob_id.into()).await.unwrap();
    alice
        .add_member(
            bob_agent,
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    Ok((alice, bob, doc_id))
}

/// Take a legitimate `PathChange` from `who`'s own document to retarget elsewhere.
async fn stolen_path(who: &Kh) -> Box<PathChange> {
    let doc = who
        .generate_doc(vec![], nonempty![[7u8; 32]])
        .await
        .unwrap();
    let doc_id = { doc.lock().await.doc_id() };
    who.try_encrypt_content(doc.dupe(), &[1u8; 32], &vec![], b"warm up".as_ref())
        .await
        .unwrap();
    who.cgka_ops_for_doc(&doc_id)
        .await
        .unwrap()
        .unwrap()
        .iter()
        .find_map(|op| match op.payload() {
            CgkaOperation::Update { new_path, .. } => Some(new_path.clone()),
            _ => None,
        })
        .expect("an update op was produced")
}

fn refused(result: &Result<(), ReceiveCgkaOpError>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(_)))
}

#[tokio::test]
async fn a_non_member_cannot_add_themselves() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: [0u8; 32],
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn a_non_member_cannot_remove_a_member() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: [0u8; 32],
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_non_member_cannot_update_another_members_leaf() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let mut path = stolen_path(&mallory).await;
    path.leaf_id = MemberId(bob.id().verifying_key());
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_forged_genesis_is_refused() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    // No predecessors with a key Mallory controls.
    let op = CgkaOperation::Add {
        added_id: MemberId(doc_id.verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: vec![],
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: [0u8; 32],
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

/// An add must target the same individual its delegation indicates.
#[tokio::test]
async fn an_add_cannot_target_the_wrong_subject() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let bob_delegation: [u8; 32] = alice
        .get_document(doc_id)
        .await
        .unwrap()
        .lock()
        .await
        .get_capability(&Identifier::from(bob.id()))
        .map(|d| Digest::hash(d.as_ref()).into())
        .expect("bob has a delegation");

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: bob_delegation,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

/// A remove must target the same individual its revocation revokes.
#[tokio::test]
async fn a_remove_cannot_evict_the_wrong_subject() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_id = { doc.lock().await.doc_id() };
    let membered = Membered::Document(doc_id, doc.dupe());
    for who in [&bob, &carol] {
        let id = learn(&alice, who).await;
        let agent = alice.get_agent(id.into()).await.unwrap();
        alice
            .add_member(agent, &membered, Access::Read, &[])
            .await?;
    }

    alice
        .revoke_member(Identifier::from(bob.id()), true, &membered)
        .await?;
    let bob_revocation = alice
        .cgka_ops_for_doc(&doc_id)
        .await?
        .unwrap_or_default()
        .iter()
        .find_map(|op| match op.payload() {
            CgkaOperation::Remove { authorization, .. } => Some(*authorization),
            _ => None,
        })
        .expect("a remove op for bob");

    let op = CgkaOperation::Remove {
        id: MemberId(carol.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: bob_revocation,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    Ok(())
}

/// A group of `mallory`'s own, with `subject` in it and that delegation's hash.
async fn own_group_with(mallory: &Kh, subject: Identifier) -> TestResult<(Mem, [u8; 32])> {
    let group = mallory.generate_group(vec![]).await?;
    let membered = Membered::Group(group.lock().await.group_id(), group.dupe());
    let agent = mallory.get_agent(subject).await.expect("knows the subject");
    let update = mallory
        .add_member(agent, &membered, Access::Admin, &[])
        .await?;
    Ok((membered, Digest::hash(update.delegation.as_ref()).into()))
}

/// Deliver `from`'s own history to `to` as a relay would.
async fn leak_to(from: &Kh, to: &Kh) {
    let self_agent = from.active().lock().await.clone().into();
    let events = from.static_events_for_agent(&self_agent).await;
    to.ingest_unsorted_static_events(events.into_values().collect())
        .await;
}

#[tokio::test]
async fn an_add_cannot_cite_a_delegation_over_another_resource() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let (_, elsewhere) = own_group_with(&mallory, mallory.id().into()).await?;
    leak_to(&mallory, &alice).await;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: elsewhere,
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn a_remove_cannot_cite_a_revocation_over_another_resource() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let bob_id = learn(&mallory, &bob).await;
    let (membered, _) = own_group_with(&mallory, bob_id.into()).await?;
    let revoked = mallory
        .revoke_member(bob_id.into(), false, &membered)
        .await?;
    let rev_hash: [u8; 32] = Digest::hash(
        revoked
            .revocations()
            .first()
            .expect("a revocation")
            .as_ref(),
    )
    .into();
    leak_to(&mallory, &alice).await;

    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: rev_hash,
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}
