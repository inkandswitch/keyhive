use beekem::{
    id::{MemberId, TreeId},
    keys::{ConflictKeys, NodeKey},
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

/// Whether `observer`'s tree contains `op`.
async fn contains_op(observer: &Kh, doc: DocumentId, op: &Signed<CgkaOperation>) -> bool {
    let ops = observer
        .cgka_ops_for_doc(&doc)
        .await
        .unwrap()
        .unwrap_or_default();
    ops.iter().any(|known| known.as_ref() == op)
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
async fn intercepted_path(who: &Kh) -> Box<PathChange> {
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

fn is_denied(result: &Result<(), ReceiveCgkaOpError>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(_)))
}

fn is_pending(result: &Result<(), ReceiveCgkaOpError>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::PendingCgkaAuthorization(_)))
}

#[tokio::test]
async fn a_non_member_cannot_add_themselves() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    // Mallory cites a real delegation, but Alice issued it, not Mallory.
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: bob_delegation,
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn a_non_member_cannot_remove_a_member() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    // Mallory cites a real revocation, but Alice issued it, not Mallory.
    let revoked = alice
        .revoke_member(Identifier::from(bob.id()), true, doc_id)
        .await?;
    let bob_revocation = CgkaAuthorization::Revocation(
        revoked
            .revocations()
            .first()
            .expect("a revocation")
            .digest()
            .into(),
    );
    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: bob_revocation,
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn a_non_member_cannot_update_another_members_leaf() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let mut path = intercepted_path(&mallory).await;
    path.leaf_id = MemberId(bob.id().verifying_key());
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: bob_delegation,
    };
    let signed = alice.try_sign(op).await?;
    let result = alice.receive_cgka_op(signed.clone()).await;

    // Pending because, from Alice's perspective, "Bob" could still be promoted to a group
    // that contains Mallory.
    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op(&alice, doc_id, &signed).await);
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
    let signed = alice.try_sign(op).await?;
    let result = alice.receive_cgka_op(signed.clone()).await;

    // Pending because, from Alice's perspective, "Bob" could still be promoted to a group
    // that contains Carol.
    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op(&alice, doc_id, &signed).await);
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
async fn an_add_citing_a_delegation_over_another_resource_is_pending() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let (_, elsewhere) = own_group_with(&mallory, mallory.id().into()).await?;
    leak_to(&mallory, &alice).await;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: elsewhere,
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn a_remove_citing_a_revocation_over_another_resource_is_pending() -> TestResult {
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

    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, mallory.id().verifying_key()).await);
    Ok(())
}

#[tokio::test]
async fn the_creator_cannot_update_another_members_leaf() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = intercepted_path(&alice).await;
    path.leaf_id = MemberId(bob.id().verifying_key());
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!tree_members(&alice, doc_id).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn an_add_granting_more_than_its_subject_reaches_here_is_pending() -> TestResult {
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation(inside.delegation.digest().into()),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: founding,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    let seated = doc
        .lock()
        .await
        .cgka_mut()?
        .member_ids()?
        .any(|id| id == mallory.id());
    assert!(!seated, "mallory must not be in the tree");
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
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation(Digest::hash(&forged).into()),
    };
    // Signed with the same well-known key, so the issuers match.
    let result = alice
        .receive_cgka_op(Public.signer().try_sign_sync(op)?)
        .await;

    assert!(is_denied(&result), "{result:?}");
    let seated = doc
        .lock()
        .await
        .cgka_mut()?
        .member_ids()?
        .any(|id| id == mallory.id());
    assert!(!seated, "mallory must not be in the tree");
    Ok(())
}

/// The causal root of `doc`'s operations, which is its creator's add of themselves.
async fn creators_own_add(observer: &Kh, doc: DocumentId) -> Signed<CgkaOperation> {
    op_where(
        observer,
        doc,
        |op| matches!(op, CgkaOperation::Add { predecessors, .. } if predecessors.is_empty()),
    )
    .await
}

#[tokio::test]
async fn the_creators_own_add_is_accepted_again_when_it_is_redelivered() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;

    let result = alice
        .receive_cgka_op(creators_own_add(&alice, doc_id).await)
        .await;

    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_creator_delegated_as_admin_twice_can_still_process_their_founding_add() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice
        .add_member(alice.id(), doc_id, Access::Admin, &[])
        .await?;

    let result = alice
        .receive_cgka_op(creators_own_add(&alice, doc_id).await)
        .await;

    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_member_who_did_not_found_the_document_cannot_enact_a_founding_delegation() -> TestResult
{
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Access::Admin, &[]).await?;

    let reissued = creators_own_add(&alice, doc_id).await.payload().clone();
    let result = alice.receive_cgka_op(bob.try_sign(reissued).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, bob.id().verifying_key()).await);
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

    assert!(is_denied(&result), "{result:?}");
    assert!(tree_members(&alice, doc_id).await.contains(&bob_id));
    Ok(())
}

#[tokio::test]
async fn an_add_through_a_group_is_still_applied_to_cgka_graph_after_member_revoked_from_group(
) -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let carol_id = learn(&alice, &carol).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice
        .add_member(carol_id, doc_id, Access::Read, &[])
        .await?;
    carol
        .ingest_event_table(alice.events_for_agent(carol_id).await)
        .await?;

    let group_id = alice.generate_group(vec![]).await?;
    alice
        .add_member(bob_id, group_id, Access::Read, &[])
        .await?;
    alice
        .add_member(group_id, doc_id, Access::Read, &[])
        .await?;
    let add_of_bob = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Add { added_id, .. }
            if *added_id == MemberId(bob.id().verifying_key()))
    })
    .await;
    alice.revoke_member(bob_id, true, group_id).await?;

    // Carol receives the revocation before she sees the add it reverses.
    let membership_only = alice
        .events_for_agent(carol_id)
        .await
        .into_iter()
        .filter(|(_, event)| !matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();
    carol.ingest_event_table(membership_only).await?;
    assert!(!contains_op(&carol, doc_id, &add_of_bob).await);

    let result = carol.receive_cgka_op(add_of_bob.clone()).await;

    assert!(result.is_ok(), "{result:?}");
    assert!(contains_op(&carol, doc_id, &add_of_bob).await);
    Ok(())
}

#[tokio::test]
async fn an_add_through_an_individual_is_applied_once_the_individual_is_promoted_to_a_group(
) -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let group = keyhive_core::test_utils::make_simple_keyhive().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;
    let dave = keyhive_core::test_utils::make_simple_keyhive().await?;
    let group_id = learn(&alice, &group).await;
    let carol_id = learn(&alice, &carol).await;
    let dave_id = learn(&alice, &dave).await;
    learn(&dave, &group).await;
    learn(&dave, &carol).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(dave_id, doc_id, Access::Read, &[]).await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await)
        .await?;

    // Every peer first learns of `group` as an individual, from its prekeys.
    // Its key then signs a delegation over itself that adds Carol. A peer that
    // receives this delegation promotes `group` from an individual to a group.
    let group_to_carol = group
        .try_sign(StaticDelegation::<[u8; 32]> {
            can: Access::Read,
            proof: None,
            delegate: carol_id.into(),
            after_revocations: vec![],
            after_content: Default::default(),
        })
        .await?;
    alice.receive_delegation(&group_to_carol).await?;
    alice
        .add_member(group_id, doc_id, Access::Read, &[])
        .await?;
    let add_of_carol = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Add { added_id, .. }
            if *added_id == MemberId(carol.id().verifying_key()))
    })
    .await;

    // Dave receives Alice's delegation to `group` but not the delegation that
    // promotes it, so `group` is still an individual to Dave.
    let group_key = group.id().verifying_key();
    let without_group_to_carol = alice
        .events_for_agent(dave_id)
        .await
        .into_iter()
        .filter(|(_, event)| match event {
            keyhive_core::event::Event::CgkaOperation(_) => false,
            keyhive_core::event::Event::Delegated(dlg) => dlg.issuer != group_key,
            _ => true,
        })
        .collect();
    dave.ingest_event_table(without_group_to_carol).await?;

    let result = dave.receive_cgka_op(add_of_carol.clone()).await;
    assert!(is_pending(&result), "{result:?}");

    // Dave learns about the group and can now accept the pending CGKA add.
    dave.receive_delegation(&group_to_carol).await?;
    let result = dave.receive_cgka_op(add_of_carol.clone()).await;

    assert!(result.is_ok(), "{result:?}");
    assert!(contains_op(&dave, doc_id, &add_of_carol).await);
    Ok(())
}

#[tokio::test]
async fn a_remove_through_an_individual_is_applied_once_the_individual_is_promoted_to_a_group(
) -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let group = keyhive_core::test_utils::make_simple_keyhive().await?;
    let carol = keyhive_core::test_utils::make_simple_keyhive().await?;
    let dave = keyhive_core::test_utils::make_simple_keyhive().await?;
    let group_id = learn(&alice, &group).await;
    let carol_id = learn(&alice, &carol).await;
    let dave_id = learn(&alice, &dave).await;
    learn(&dave, &group).await;
    learn(&dave, &carol).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(dave_id, doc_id, Access::Read, &[]).await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await)
        .await?;
    let group_to_carol = group
        .try_sign(StaticDelegation::<[u8; 32]> {
            can: Access::Read,
            proof: None,
            delegate: carol_id.into(),
            after_revocations: vec![],
            after_content: Default::default(),
        })
        .await?;
    alice.receive_delegation(&group_to_carol).await?;
    alice
        .add_member(group_id, doc_id, Access::Read, &[])
        .await?;
    alice.revoke_member(group_id, true, doc_id).await?;
    let remove_of_carol = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Remove { id, .. }
            if *id == MemberId(carol.id().verifying_key()))
    })
    .await;

    // Dave receives the revocation of Alice's delegation to `group` while
    // `group` is still an individual to him.
    let group_key = group.id().verifying_key();
    let without_group_to_carol = alice
        .events_for_agent(dave_id)
        .await
        .into_iter()
        .filter(|(_, event)| match event {
            keyhive_core::event::Event::CgkaOperation(_) => false,
            keyhive_core::event::Event::Delegated(dlg) => dlg.issuer != group_key,
            _ => true,
        })
        .collect();
    dave.ingest_event_table(without_group_to_carol).await?;
    dave.receive_delegation(&group_to_carol).await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await)
        .await?;

    assert!(contains_op(&dave, doc_id, &remove_of_carol).await);
    Ok(())
}

#[tokio::test]
async fn a_rotation_of_another_members_leaf_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = intercepted_path(&alice).await;
    path.leaf_id = MemberId(bob.id().verifying_key());
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!result.unwrap_err().is_missing_dependency());
    Ok(())
}

#[tokio::test]
async fn a_rotation_whose_id_differs_from_its_path_leaf_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let op = CgkaOperation::Update {
        id: MemberId(alice.id().verifying_key()),
        new_path: intercepted_path(&bob).await,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_member_cannot_rotate_their_leaf_to_the_public_key() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = intercepted_path(&bob).await;
    path.leaf_pk = NodeKey::ConflictKeys(ConflictKeys {
        first: Public.share_key(),
        second: path.leaf_pk.lowest(),
        more: vec![],
    });
    let op = CgkaOperation::Update {
        id: MemberId(bob.id().verifying_key()),
        new_path: path,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
    };
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_remove_citing_a_revocation_of_access_below_read_is_denied() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Access::Relay, &[]).await?;
    let revoked = alice
        .revoke_member(Identifier::from(bob_id), true, doc_id)
        .await?;

    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Revocation(
            revoked
                .revocations()
                .first()
                .expect("a revocation")
                .digest()
                .into(),
        ),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_remove_citing_a_revocation_not_yet_received_is_pending() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let op = CgkaOperation::Remove {
        id: MemberId(bob.id().verifying_key()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Revocation([0u8; 32]),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn an_add_citing_a_delegation_not_yet_received_is_pending() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let op = CgkaOperation::Add {
        added_id: MemberId(mallory.id().verifying_key()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId(doc_id.verifying_key()),
        authorization: CgkaAuthorization::Delegation([0u8; 32]),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(result.unwrap_err().is_missing_dependency());
    Ok(())
}

#[tokio::test]
async fn an_add_through_a_delegation_to_ourselves_for_someone_else_is_denied() -> TestResult {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;
    learn(&alice, &mallory).await;

    let mut op = creators_own_add(&alice, doc_id).await.payload().clone();
    if let CgkaOperation::Add {
        added_id,
        pk,
        predecessors,
        ..
    } = &mut op
    {
        *added_id = MemberId(mallory.id().verifying_key());
        *pk = own_prekey(&mallory, doc_id).await;
        *predecessors = cgka_heads(&alice, doc_id).await;
    }
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!result.unwrap_err().is_missing_dependency());
    Ok(())
}
