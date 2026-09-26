use beekem::{
    id::{MemberId, TreeId},
    operation::{CgkaAuthorization, CgkaOperation},
    tree::PathChange,
};
use keyhive_core::{
    access::Access,
    crypto::digest::Digest,
    keyhive::ReceiveCgkaOpError,
    principal::{
        document::id::DocumentId,
        group::{delegation::StaticDelegation, id::GroupId, revocation::StaticRevocation},
        identifier::Identifier,
        individual::{id::IndividualId, Individual},
        public::Public,
    },
};
use keyhive_crypto::{share_key::ShareKey, signed::Signed, verifiable::Verifiable};
use nonempty::nonempty;
use testresult::TestResult;

type Kh = keyhive_core::test_utils::Hive;

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
async fn learn(observer: &Kh, who: &Kh) -> IndividualId {
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
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Access::Read, &[]).await?;
    Ok((alice, bob, doc_id))
}

/// A legitimate `PathChange` from a document of `who`'s, for retargeting elsewhere.
async fn stolen_path(who: &Kh) -> Box<PathChange> {
    let doc_id = who
        .generate_doc(vec![], nonempty![[7u8; 32]])
        .await
        .unwrap();
    who.try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"warm up".as_ref())
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

/// The individuals seated in `observer`'s CGKA tree for `doc`.
async fn tree_members(observer: &Kh, doc: DocumentId) -> Vec<IndividualId> {
    observer
        .cgka_members_for(doc)
        .await
        .expect("knows the document")
        .expect("an initialized tree")
        .into_iter()
        .collect()
}

/// The first operation on `doc` that `pick` selects, as `observer` sees it.
async fn op_where(
    observer: &Kh,
    doc: DocumentId,
    pick: impl Fn(&CgkaOperation) -> bool,
) -> Signed<CgkaOperation> {
    observer
        .cgka_ops_for_doc(&doc)
        .await
        .unwrap()
        .unwrap()
        .iter()
        .find(|op| pick(op.payload()))
        .map(|op| op.as_ref().clone())
        .expect("the operation was produced")
}

fn refused(result: &Result<(), ReceiveCgkaOpError>) -> bool {
    matches!(
        result,
        Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(_)
            | ReceiveCgkaOpError::PendingCgkaAuthorization(_))
    )
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
        authorization: CgkaAuthorization::Delegation([0u8; 32]),
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
        authorization: CgkaAuthorization::Revocation([0u8; 32]),
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

    // The key is one Mallory holds the secret for.
    let op = CgkaOperation::Add {
        added_id: MemberId(doc_id.verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: vec![],
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation([0u8; 32]),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn an_add_cannot_target_the_wrong_subject() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let bob_delegation = alice
        .get_document(doc_id)
        .await
        .unwrap()
        .lock()
        .await
        .get_capability(&Identifier::from(bob.id()))
        .map(|d| CgkaAuthorization::Delegation(d.digest().into()))
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

#[tokio::test]
async fn a_remove_cannot_evict_the_wrong_subject() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    for who in [&bob, &carol] {
        let id = learn(&alice, who).await;
        alice.add_member(id, doc_id, Access::Read, &[]).await?;
    }

    alice
        .revoke_member(Identifier::from(bob.id()), true, doc_id)
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
async fn own_group_with(
    mallory: &Kh,
    subject: Identifier,
) -> TestResult<(GroupId, CgkaAuthorization)> {
    let group_id = mallory.generate_group(vec![]).await?;
    let update = mallory
        .add_member(subject, group_id, Access::Admin, &[])
        .await?;
    Ok((
        group_id,
        CgkaAuthorization::Delegation(update.delegation.digest().into()),
    ))
}

/// Deliver `from`'s own history to `to` as a relay would.
async fn leak_to(from: &Kh, to: &Kh) {
    let events = from.static_events_for_agent(from.id()).await;
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
    let (group_id, _) = own_group_with(&mallory, bob_id.into()).await?;
    let revoked = mallory.revoke_member(bob_id, false, group_id).await?;
    let rev_hash = CgkaAuthorization::Revocation(
        revoked
            .revocations()
            .first()
            .expect("a revocation")
            .digest()
            .into(),
    );
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

#[tokio::test]
async fn the_genesis_issuer_cannot_update_another_members_leaf() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = stolen_path(&alice).await;
    path.leaf_id = MemberId(bob.id().verifying_key());
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn an_add_cannot_cite_a_delegation_below_read() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;

    let carol_id = learn(&alice, &carol).await;
    let relayed = alice
        .add_member(carol_id, doc_id, Access::Relay, &[])
        .await?;
    let authorization = CgkaAuthorization::Delegation(relayed.delegation.digest().into());

    let op = CgkaOperation::Add {
        added_id: MemberId(carol.id().verifying_key()),
        pk: own_prekey(&carol, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!tree_members(&alice, doc_id).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn an_add_cannot_grant_more_than_its_subject_reaches_here() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;
    let mallory_id = learn(&alice, &mallory).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    // The group only relays this document, so an admin delegation created inside
    // it still carries no decryption access here.
    let group_id = alice.generate_group(vec![]).await?;
    alice
        .add_member(group_id, doc_id, Access::Relay, &[])
        .await?;
    let inside = alice
        .add_member(mallory_id, group_id, Access::Admin, &[])
        .await?;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation(inside.delegation.digest().into()),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!tree_members(&alice, doc_id).await.contains(&mallory.id()));
    Ok(())
}

#[tokio::test]
async fn a_founding_delegation_cannot_seat_an_outsider() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc = alice.get_document(doc_id).await.expect("the document");
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;
    learn(&alice, &mallory).await;

    let founding = CgkaAuthorization::Delegation(
        doc.lock()
            .await
            .get_capability(&Identifier::from(alice.id()))
            .expect("the creator's founding delegation")
            .digest()
            .into(),
    );
    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: founding,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    let seated = doc
        .lock()
        .await
        .cgka()?
        .member_ids()
        .any(|id| id == mallory.id());
    assert!(!seated, "mallory must not be in the tree");
    Ok(())
}

#[tokio::test]
async fn a_founder_cannot_replace_a_genesis_the_replica_holds() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice
        .generate_doc(vec![bob_id.into()], nonempty![[0u8; 32]])
        .await?;
    let doc = alice.get_document(doc_id).await.expect("the document");

    let founding = CgkaAuthorization::Delegation(
        doc.lock()
            .await
            .get_capability(&Identifier::from(bob_id))
            .expect("bob's founding delegation")
            .digest()
            .into(),
    );
    let op = CgkaOperation::Add {
        added_id: MemberId(doc_id.verifying_key()),
        pk: own_prekey(&bob, doc_id).await,
        leaf_index: 0,
        predecessors: vec![],
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: founding,
    };
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(refused(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, bob.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn an_add_cannot_cite_a_delegation_issued_by_public() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc = alice.get_document(doc_id).await.expect("the document");
    alice
        .add_member(Public.id(), doc_id, Access::Read, &[])
        .await?;

    // Mallory grants herself admin under `Public`, using the key everybody has.
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;
    learn(&alice, &mallory).await;
    let forged = Public
        .signer()
        .try_sign_sync(StaticDelegation::<[u8; 32]> {
            can: Access::Admin,
            proof: None,
            delegate: mallory.id().into(),
            after_revocations: vec![],
            after_content: Default::default(),
        })?;
    alice.receive_delegation(&forged).await?;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        add_predecessors: vec![],
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation(Digest::hash(&forged).into()),
    };
    // Signed with the same well-known key, so the issuers match.
    let result = alice
        .receive_cgka_op(Public.signer().try_sign_sync(op)?)
        .await;

    assert!(refused(&result), "{result:?}");
    let seated = doc
        .lock()
        .await
        .cgka()?
        .member_ids()
        .any(|id| id == mallory.id());
    assert!(!seated, "mallory must not be in the tree");
    Ok(())
}

#[tokio::test]
async fn the_genesis_is_accepted_again_when_it_is_redelivered() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let genesis = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Add { predecessors, added_id, .. }
            if predecessors.is_empty() && *added_id == MemberId(doc_id.verifying_key()))
    })
    .await;

    let result = alice.receive_cgka_op(genesis).await;

    assert!(!refused(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_remove_cannot_cite_a_revocation_issued_by_public() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let bob_id = bob.id();
    alice
        .add_member(Public.id(), doc_id, Access::Read, &[])
        .await?;

    let forged_dlg = Public
        .signer()
        .try_sign_sync(StaticDelegation::<[u8; 32]> {
            can: Access::Admin,
            proof: None,
            delegate: bob_id.into(),
            after_revocations: vec![],
            after_content: Default::default(),
        })?;
    alice.receive_delegation(&forged_dlg).await?;
    let forged_rev = Public
        .signer()
        .try_sign_sync(StaticRevocation::<[u8; 32]> {
            revoke: Digest::hash(&forged_dlg),
            proof: None,
            after_content: Default::default(),
        })?;
    alice.receive_revocation(&forged_rev).await?;

    let seated = tree_members(&alice, doc_id).await;
    let leaf_idx = seated
        .iter()
        .position(|id| *id == bob_id)
        .expect("bob seated") as u32;
    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Revocation(Digest::hash(&forged_rev).into()),
    };
    let result = alice
        .receive_cgka_op(Public.signer().try_sign_sync(op)?)
        .await;

    assert!(refused(&result), "{result:?}");
    assert!(tree_members(&alice, doc_id).await.contains(&bob_id));
    Ok(())
}
