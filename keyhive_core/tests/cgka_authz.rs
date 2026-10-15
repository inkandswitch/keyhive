use beekem::{
    id::{MemberId, TreeId},
    operation::{CgkaAuthorization, CgkaOperation},
    tree::PathChange,
};
use ed25519_dalek::VerifyingKey;
use future_form::Sendable;
use keyhive_core::{
    content::heads::ContentHeads,
    crypto::digest::Digest,
    event::Event,
    keyhive::ReceiveCgkaOpError,
    principal::{
        document::id::DocumentId,
        group::id::GroupId,
        identifier::Identifier,
        individual::{id::IndividualId, op::KeyOp, IndividualState},
    },
    test_utils::Hive,
};
use keyhive_crypto::{id::Id, share_key::ShareKey, signed::Signed, verifiable::Verifiable};
use keyline::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    contract::Keyline,
    delegation::Delegation,
    power::Power,
    revocation::Revocation,
};
use nonempty::nonempty;
use std::{collections::HashSet, convert::Infallible};
use testresult::TestResult;

/// `who` as a Beekem member.
fn member(who: IndividualId) -> MemberId {
    MemberId::try_from(who).expect("a generated individual's key is a valid id")
}

/// `doc` as a Beekem tree.
fn tree(doc: DocumentId) -> TreeId {
    TreeId::try_from(doc).expect("a generated document's key is a valid id")
}

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Hive, doc: DocumentId) -> Vec<Digest<Signed<CgkaOperation>>> {
    let ops = observer
        .cgka_ops_for_doc(&doc)
        .await
        .expect("the observer holds the document");
    let referenced: HashSet<_> = ops
        .iter()
        .flat_map(|op| op.payload.predecessors())
        .collect();
    ops.iter()
        .map(|op| Digest::hash(op.as_ref()))
        .filter(|d| !referenced.contains(d))
        .collect()
}

/// Whether `observer`'s tree contains a CGKA op signed by `issuer`.
async fn contains_op_from(observer: &Hive, doc: DocumentId, issuer: VerifyingKey) -> bool {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap_or_default();
    ops.iter().any(|op| op.issuer == issuer)
}

/// Whether `observer`'s tree contains `op`.
async fn contains_op(observer: &Hive, doc: DocumentId, op: &Signed<CgkaOperation>) -> bool {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap_or_default();
    ops.iter().any(|known| known.as_ref() == op)
}

/// One of `kh`'s own prekeys it would use to join `doc`.
async fn own_prekey(kh: &Hive, doc: DocumentId) -> ShareKey {
    kh.get_individual(kh.id())
        .await
        .expect("an instance holds its own prekeys")
        .pick_prekey(doc)
        .await
        .expect("an individual has a prekey")
}

/// Register `who`'s identity with `observer` so it can be added.
async fn learn(observer: &Hive, who: &Hive) -> IndividualId {
    let prekey = who.expand_prekeys().await.expect("prekeys expand");
    let indie = IndividualState::new(KeyOp::Add(prekey));
    let id = indie.id();
    observer.register_individual(indie).await;
    id
}

/// Alice creates a document and adds Bob as a reader.
async fn doc_with_alice_and_bob() -> TestResult<(Hive, Hive, DocumentId)> {
    let alice = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob = keyhive_core::test_utils::make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Read).await?;
    Ok((alice, bob, doc_id))
}

/// A legitimate `PathChange` from a document of `who`'s, for retargeting elsewhere.
async fn intercepted_path(who: &Hive) -> Box<PathChange> {
    let doc_id = who
        .generate_doc(vec![], nonempty![[7u8; 32]])
        .await
        .expect("a document");
    who.try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"warm up".as_ref())
        .await
        .expect("content encrypts");
    who.cgka_ops_for_doc(&doc_id)
        .await
        .expect("the writer holds the document")
        .iter()
        .find_map(|op| match op.payload() {
            CgkaOperation::Update { new_path, .. } => Some(new_path.clone()),
            _ => None,
        })
        .expect("an update op was produced")
}

/// The individuals seated in `observer`'s CGKA tree for `doc`.
async fn tree_members(observer: &Hive, doc: DocumentId) -> Vec<IndividualId> {
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
    observer: &Hive,
    doc: DocumentId,
    pick: impl Fn(&CgkaOperation) -> bool,
) -> Signed<CgkaOperation> {
    observer
        .cgka_ops_for_doc(&doc)
        .await
        .expect("the observer holds the document")
        .iter()
        .find(|op| pick(op.payload()))
        .map(|op| op.as_ref().clone())
        .expect("the operation was produced")
}

/// `group`'s key admitting `member` to itself at `Read`, as a Keyline
/// certificate.
async fn keyline_twin(
    group: &Hive,
    group_id: IndividualId,
    member: IndividualId,
) -> TestResult<Certificate<ContentHeads<[u8; 32]>>> {
    let id = |i: IndividualId| Id::try_from(Identifier::from(i)).expect("a valid id");
    let delegation = Delegation::new(id(member), id(group_id), Power::Read);
    let signed = group.sign_certificate(&delegation).await?;
    Ok(VerifiedCertificate::from(signed).into_certificate())
}

/// The Keyline delegation from `subject` to `audience` that `kh` holds, as
/// the authorization a CGKA add cites. A grant someone issued is preferred
/// over the subject's own root edge, which only a creator cites.
async fn keyline_grant(
    kh: &Hive,
    subject: impl Into<Identifier>,
    audience: impl Into<Identifier>,
) -> CgkaAuthorization {
    let subject = subject.into();
    let subject_id = Id::try_from(subject).expect("a valid id");
    let grants = Keyline::<Sendable>::delegations_to(
        kh.keyline(),
        subject_id,
        Id::try_from(audience.into()).expect("a valid id"),
    )
    .await
    .expect("the memory store does not fail")
    .value;
    let digest = grants
        .iter()
        .find(|(_, (issuer, _))| *issuer != subject_id)
        .or_else(|| grants.iter().next())
        .map(|(digest, _)| *digest)
        .expect("a Keyline delegation");
    CgkaAuthorization::Delegation(digest.into())
}

/// A Keyline revocation of a delegation from `subject` to `audience` that
/// `kh` holds, as the authorization a CGKA remove cites.
async fn keyline_revocation(
    kh: &Hive,
    subject: impl Into<Identifier>,
    audience: impl Into<Identifier>,
) -> CgkaAuthorization {
    for digest in keyline_delegations(kh, subject, audience).await {
        let revocations = Keyline::<Sendable>::revocations_of(kh.keyline(), digest)
            .await
            .expect("the memory store does not fail")
            .value;
        if let Some(revocation) = revocations.first() {
            return CgkaAuthorization::Revocation((*revocation).into());
        }
    }
    panic!("no Keyline revocation of a delegation to that audience")
}

async fn keyline_delegations(
    kh: &Hive,
    subject: impl Into<Identifier>,
    audience: impl Into<Identifier>,
) -> Vec<Digest<Delegation>> {
    let id = |i: Identifier| Id::try_from(i).expect("a valid id");
    Keyline::<Sendable>::delegations_to(kh.keyline(), id(subject.into()), id(audience.into()))
        .await
        .expect("the memory store does not fail")
        .value
        .into_keys()
        .collect()
}

fn is_denied(result: &Result<(), ReceiveCgkaOpError<Infallible>>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(_)))
}

fn is_pending(result: &Result<(), ReceiveCgkaOpError<Infallible>>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::PendingCgkaAuthorization(_)))
}

#[tokio::test]
async fn a_non_member_cannot_add_themselves() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    // Mallory cites a real delegation, but Alice issued it, not Mallory.
    let bob_delegation = keyline_grant(&alice, doc_id, bob.id()).await;
    let op = CgkaOperation::Add {
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    alice
        .revoke_member(Identifier::from(bob.id()), true, doc_id)
        .await?;
    let bob_revocation = keyline_revocation(&alice, doc_id, bob.id()).await;
    let op = CgkaOperation::Remove {
        id: member(bob.id()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    path.leaf_id = member(bob.id());
    let op = CgkaOperation::Update {
        id: member(bob.id()),
        new_path: path,
        predecessor_secrets: Vec::new(),
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn an_add_cannot_target_the_wrong_subject() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = keyhive_core::test_utils::make_simple_keyhive().await?;

    let bob_delegation = keyline_grant(&alice, doc_id, bob.id()).await;

    let op = CgkaOperation::Add {
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
        alice.add_member(id, doc_id, Power::Read).await?;
    }

    alice
        .revoke_member(Identifier::from(bob.id()), true, doc_id)
        .await?;
    let bob_revocation = alice
        .cgka_ops_for_doc(&doc_id)
        .await
        .unwrap_or_default()
        .iter()
        .find_map(|op| match op.payload() {
            CgkaOperation::Remove { authorization, .. } => Some(*authorization),
            _ => None,
        })
        .expect("a remove op for bob");

    let op = CgkaOperation::Remove {
        id: member(carol.id()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    mallory: &Hive,
    subject: Identifier,
) -> TestResult<(GroupId, CgkaAuthorization)> {
    let group_id = mallory.generate_group(vec![]).await?;
    let update = mallory.add_member(subject, group_id, Power::Admin).await?;
    let _ = update;
    Ok((group_id, keyline_grant(mallory, group_id, subject).await))
}

/// Deliver `from`'s own history to `to` as a relay would.
async fn leak_to(from: &Hive, to: &Hive) {
    let events = from
        .static_events_for_agent(from.id())
        .await
        .expect("selects events");
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
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    mallory.revoke_member(bob_id, false, group_id).await?;
    let rev_hash = keyline_revocation(&mallory, group_id, bob_id).await;
    leak_to(&mallory, &alice).await;

    let op = CgkaOperation::Remove {
        id: member(bob.id()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    path.leaf_id = member(bob.id());
    let op = CgkaOperation::Update {
        id: member(bob.id()),
        new_path: path,
        predecessor_secrets: Vec::new(),
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    alice.add_member(carol_id, doc_id, Power::Relay).await?;
    let authorization = keyline_grant(&alice, doc_id, carol_id).await;

    let op = CgkaOperation::Add {
        added_id: member(carol.id()),
        pk: own_prekey(&carol, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    alice.add_member(group_id, doc_id, Power::Relay).await?;
    alice.add_member(mallory_id, group_id, Power::Admin).await?;

    let op = CgkaOperation::Add {
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
        authorization: keyline_grant(&alice, group_id, mallory_id).await,
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

    // The root edge to Alice, signed by the document's own key.
    let founding = keyline_grant(&alice, doc_id, alice.id()).await;
    let op = CgkaOperation::Add {
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
        authorization: founding,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    // Pending, not denied: in Keyline an individual can have members, so
    // Mallory could still gain a route through Alice. She is not seated.
    assert!(is_pending(&result), "{result:?}");
    let seated = doc
        .cgka_members()
        .await
        .is_some_and(|members| members.contains(&mallory.id()));
    assert!(!seated, "mallory must not be in the tree");
    Ok(())
}

/// The causal root of `doc`'s operations, which is its creator's add of themselves.
async fn creators_own_add(observer: &Hive, doc: DocumentId) -> Signed<CgkaOperation> {
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
    alice.add_member(alice.id(), doc_id, Power::Admin).await?;

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
    alice.add_member(bob_id, doc_id, Power::Admin).await?;

    let reissued = creators_own_add(&alice, doc_id).await.payload().clone();
    let result = alice.receive_cgka_op(bob.try_sign(reissued).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(!contains_op_from(&alice, doc_id, bob.id().verifying_key()).await);
    Ok(())
}

/// A revocation that covers nothing cannot evict anyone. A relay can sign a
/// revocation of any delegation; it is inert in Keyline because the relay
/// neither signed nor is named by it, and holds no Admin over its subject.
#[tokio::test]
async fn a_remove_citing_a_revocation_that_covers_nothing_is_pending() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let bob_id = bob.id();
    let relay = keyhive_core::test_utils::make_simple_keyhive().await?;
    let relay_id = learn(&alice, &relay).await;
    alice.add_member(relay_id, doc_id, Power::Relay).await?;

    let root_edge = keyline_delegations(&alice, doc_id, alice.id())
        .await
        .into_iter()
        .next()
        .expect("alice's root edge");
    let inert: Revocation<ContentHeads<[u8; 32]>> = Revocation::new(root_edge);
    let signed = relay.sign_certificate(&inert).await?;
    let inert_digest = signed.digest();
    alice
        .receive_certificate(VerifiedCertificate::from(signed).into_certificate())
        .await?;

    let leaf_idx = tree_members(&alice, doc_id)
        .await
        .iter()
        .position(|id| *id == bob_id)
        .expect("bob seated") as u32;
    let op = CgkaOperation::Remove {
        id: member(bob_id),
        leaf_idx,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
        authorization: CgkaAuthorization::Revocation(inert_digest.into()),
    };
    let result = alice.receive_cgka_op(relay.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(tree_members(&alice, doc_id).await.contains(&bob_id));
    assert_eq!(
        alice
            .access_for_doc(Identifier::from(bob_id), doc_id)
            .await?,
        Some(Power::Read)
    );
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
    alice.add_member(carol_id, doc_id, Power::Read).await?;
    carol
        .ingest_event_table(alice.events_for_agent(carol_id).await?)
        .await?;

    let group_id = alice.generate_group(vec![]).await?;
    alice.add_member(bob_id, group_id, Power::Read).await?;
    alice.add_member(group_id, doc_id, Power::Read).await?;
    let add_of_bob = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Add { added_id, .. }
            if *added_id == member(bob.id()))
    })
    .await;
    alice.revoke_member(bob_id, true, group_id).await?;

    // Carol receives the revocation before she sees the add it reverses.
    let membership_only = alice
        .events_for_agent(carol_id)
        .await?
        .into_iter()
        .filter(|(_, event)| !matches!(event, Event::CgkaOperation(_)))
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
    alice.add_member(dave_id, doc_id, Power::Read).await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await?)
        .await?;

    // Every peer first learns of `group` as an individual, from its prekeys.
    // Its key then signs a delegation over itself that adds Carol. A peer that
    // receives this delegation promotes `group` from an individual to a group.
    let group_to_carol_cert = keyline_twin(&group, group_id, carol_id).await?;
    alice
        .receive_certificate(group_to_carol_cert.clone())
        .await?;
    alice.add_member(group_id, doc_id, Power::Read).await?;
    let add_of_carol = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Add { added_id, .. }
            if *added_id == member(carol.id()))
    })
    .await;

    // Dave receives Alice's delegation to `group` but not the delegation that
    // promotes it, so `group` is still an individual to Dave.
    // He gets every key agreement operation but the add under test, so its
    // predecessors are in place.
    let without_group_to_carol = alice
        .events_for_agent(dave_id)
        .await?
        .into_iter()
        .filter(|(_, event)| match event {
            Event::CgkaOperation(op) => **op != add_of_carol,
            Event::Delegated(dlg) => CertificateId::from(dlg.digest()) != group_to_carol_cert.id(),
            _ => true,
        })
        .collect();
    dave.ingest_event_table(without_group_to_carol).await?;

    let result = dave.receive_cgka_op(add_of_carol.clone()).await;
    assert!(is_pending(&result), "{result:?}");

    // Dave learns about the group and can now accept the pending CGKA add.
    dave.receive_certificate(group_to_carol_cert.clone())
        .await?;
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
    alice.add_member(dave_id, doc_id, Power::Read).await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await?)
        .await?;
    let group_to_carol_cert = keyline_twin(&group, group_id, carol_id).await?;
    alice
        .receive_certificate(group_to_carol_cert.clone())
        .await?;
    alice.add_member(group_id, doc_id, Power::Read).await?;
    alice.revoke_member(group_id, true, doc_id).await?;
    let remove_of_carol = op_where(&alice, doc_id, |op| {
        matches!(op, CgkaOperation::Remove { id, .. }
            if *id == member(carol.id()))
    })
    .await;

    // Dave receives the revocation of Alice's delegation to `group` while
    // `group` is still an individual to him.
    let without_group_to_carol = alice
        .events_for_agent(dave_id)
        .await?
        .into_iter()
        .filter(|(_, event)| match event {
            Event::CgkaOperation(_) => false,
            Event::Delegated(dlg) => CertificateId::from(dlg.digest()) != group_to_carol_cert.id(),
            _ => true,
        })
        .collect();
    dave.ingest_event_table(without_group_to_carol).await?;
    dave.receive_certificate(group_to_carol_cert.clone())
        .await?;
    dave.ingest_event_table(alice.events_for_agent(dave_id).await?)
        .await?;

    assert!(contains_op(&dave, doc_id, &remove_of_carol).await);
    Ok(())
}

#[tokio::test]
async fn a_rotation_of_another_members_leaf_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = intercepted_path(&alice).await;
    path.leaf_id = member(bob.id());
    let op = CgkaOperation::Update {
        id: member(bob.id()),
        new_path: path,
        predecessor_secrets: Vec::new(),
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
        id: member(alice.id()),
        new_path: intercepted_path(&bob).await,
        predecessor_secrets: Vec::new(),
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
    alice.add_member(bob_id, doc_id, Power::Relay).await?;
    alice
        .revoke_member(Identifier::from(bob_id), true, doc_id)
        .await?;

    let op = CgkaOperation::Remove {
        id: member(bob.id()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
        authorization: keyline_revocation(&alice, doc_id, bob_id).await,
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_remove_citing_a_revocation_not_yet_received_is_pending() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let op = CgkaOperation::Remove {
        id: member(bob.id()),
        leaf_idx: 1,
        removed_keys: vec![],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
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
        added_id: member(mallory.id()),
        pk: own_prekey(&mallory, doc_id).await,
        leaf_index: 0,
        invitation: None,
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: tree(doc_id),
        authorization: CgkaAuthorization::Delegation([0u8; 32]),
    };
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    assert!(result.unwrap_err().is_missing_dependency());
    Ok(())
}

#[tokio::test]
async fn an_add_through_a_delegation_to_ourselves_for_someone_else_is_pending() -> TestResult {
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
        *added_id = member(mallory.id());
        *pk = own_prekey(&mallory, doc_id).await;
        *predecessors = cgka_heads(&alice, doc_id).await;
    }
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    // Pending, not denied: in Keyline an individual can have members, so
    // Mallory could still gain a route through Alice. She is not seated.
    assert!(is_pending(&result), "{result:?}");
    assert!(!tree_members(&alice, doc_id).await.contains(&mallory.id()));
    Ok(())
}
