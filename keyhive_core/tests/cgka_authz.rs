use beekem::{
    error::CgkaError,
    id::{MemberId, TreeId},
    operation::{CgkaOperation, CitationId, RemovedMember},
    tree::PathChange,
};
use future_form::{FutureForm, Sendable};
use keyhive_codec::traits::Decode;
use keyhive_core::{
    content::heads::ContentHeads,
    crypto::digest::Digest,
    event::Event,
    keyhive::{Keyhive, ReceiveCgkaOpError},
    listener::no_listener::NoListener,
    principal::{
        document::id::DocumentId,
        group::id::GroupId,
        individual::{
            id::IndividualId,
            op::{add_key::AddKeyOp, KeyOp},
            IndividualState,
        },
    },
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::{make_simple_keyhive, Hive, KeylineStore, TestContext},
};
use keyhive_crypto::{
    identifier::Identifier,
    share_key::ShareKey,
    signed::{SerdeSigned, SigningError},
    signer::{async_signer::AsyncSigner, memory::MemorySigner},
    verifiable::Verifiable,
    verified::Signed,
};
use keyline::{
    certificate::VerifiedCertificate, contract::Keyline, delegation::Delegation, power::Power,
    revocation::Revocation,
};
use nonempty::nonempty;
use rand::rngs::OsRng;
use std::{
    collections::HashSet,
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use testresult::TestResult;

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Hive, doc: DocumentId) -> Vec<Digest<SerdeSigned<CgkaOperation>>> {
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

/// Whether `observer` holds `op`.
async fn contains_op(observer: &Hive, doc: DocumentId, op: &SerdeSigned<CgkaOperation>) -> bool {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap_or_default();
    ops.iter().any(|known| known.as_ref() == op)
}

/// Register `who`'s identity with `observer` so it can be added.
async fn learn(observer: &Hive, who: &Hive) -> IndividualId {
    let prekey = who.expand_prekeys().await.expect("prekeys expand");
    let indie = IndividualState::new(KeyOp::Add(prekey));
    let id = indie.id();
    observer.register_individual(indie).await;
    id
}

/// A fresh prekey of `who`'s, and the key proof an add of `who` carries.
async fn proven_prekey(who: &Hive) -> (ShareKey, Vec<u8>) {
    let op = who.expand_prekeys().await.expect("prekeys expand");
    (op.payload().share_key, KeyOp::Add(op).to_key_proof())
}

/// Alice creates a document and adds Bob as a reader.
async fn doc_with_alice_and_bob() -> TestResult<(Hive, Hive, DocumentId)> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
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

/// The members of `observer`'s CGKA group for `doc`.
async fn cgka_members(observer: &Hive, doc: DocumentId) -> Vec<IndividualId> {
    observer
        .cgka_members_for(doc)
        .await
        .expect("knows the document")
        .expect("observer has joined the CGKA group")
        .into_iter()
        .collect()
}

/// The adds of `member` in `observer`'s CGKA graph for `doc`.
async fn adds_of(
    observer: &Hive,
    doc: DocumentId,
    member: IndividualId,
) -> TestResult<Vec<Arc<SerdeSigned<CgkaOperation>>>> {
    Ok(observer
        .cgka_ops_for_doc(&doc)
        .await
        .ok_or("the observer holds the document")?
        .into_iter()
        .filter(|op| match &op.payload {
            CgkaOperation::Add { added_id, .. } => *added_id == MemberId::from(member),
            _ => false,
        })
        .collect())
}

/// The first operation on `doc` that `pick` selects, as `observer` sees it.
async fn op_where(
    observer: &Hive,
    doc: DocumentId,
    pick: impl Fn(&CgkaOperation) -> bool,
) -> SerdeSigned<CgkaOperation> {
    observer
        .cgka_ops_for_doc(&doc)
        .await
        .expect("the observer holds the document")
        .iter()
        .find(|op| pick(op.payload()))
        .map(|op| op.as_ref().clone())
        .expect("the operation was produced")
}

/// The causal root of `doc`'s operations, which is its creator's add of themselves.
async fn creators_own_add(observer: &Hive, doc: DocumentId) -> SerdeSigned<CgkaOperation> {
    op_where(
        observer,
        doc,
        |op| matches!(op, CgkaOperation::Add { predecessors, .. } if predecessors.is_empty()),
    )
    .await
}

fn kl(id: impl Into<Identifier>) -> Identifier {
    id.into()
}

fn citation<W>(cert: &VerifiedCertificate<W>) -> CitationId {
    CitationId(cert.id().to_bytes())
}

/// `signer`'s signature on `delegation`, not yet received by anyone.
async fn signed_delegation(
    signer: &Hive,
    delegation: Delegation,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    Ok(signer.sign_certificate(&delegation).await?.into())
}

/// `signer`'s revocation of a delegation from `subject` to `audience` that
/// `holder` holds, not yet received by anyone.
async fn signed_revocation(
    signer: &Hive,
    holder: &Hive,
    subject: impl Into<Identifier>,
    audience: impl Into<Identifier>,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    let target = *Keyline::<Sendable>::delegations_to(holder.keyline(), kl(subject), kl(audience))
        .await?
        .value
        .keys()
        .next()
        .ok_or("a delegation to revoke")?;
    let revocation: Revocation<ContentHeads<[u8; 32]>> = Revocation::new(target);
    Ok(signer.sign_certificate(&revocation).await?.into())
}

/// The citation of a delegation from `subject` to `audience` that `holder` has.
async fn delegation_citation(
    holder: &Hive,
    subject: Identifier,
    audience: Identifier,
) -> TestResult<CitationId> {
    let delegation = *Keyline::<Sendable>::delegations_to(holder.keyline(), subject, audience)
        .await?
        .value
        .keys()
        .next()
        .ok_or("a delegation")?;
    Ok(CitationId(delegation.into()))
}

/// `issuer`'s grant of `power` over `doc` to `audience`, received by `issuer`.
async fn issue_grant(
    issuer: &Hive,
    audience: impl Into<Identifier>,
    doc: DocumentId,
    power: Power,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    let cert = signed_delegation(issuer, Delegation::new(kl(audience), kl(doc), power)).await?;
    receive(issuer, &cert).await;
    Ok(cert)
}

async fn receive(observer: &Hive, cert: &VerifiedCertificate<ContentHeads<[u8; 32]>>) {
    observer
        .receive_certificate(cert.clone().into_certificate())
        .await
        .expect("a valid certificate is received");
}

fn cites(certs: &[&VerifiedCertificate<ContentHeads<[u8; 32]>>]) -> Vec<CitationId> {
    let mut cited: Vec<CitationId> = certs.iter().map(|c| citation(c)).collect();
    cited.sort_unstable();
    cited.dedup();
    cited
}

/// An add of `added` with key `pk` on `doc`, on top of `observer`'s heads.
async fn add_op(
    observer: &Hive,
    doc: DocumentId,
    added: IndividualId,
    (pk, key_proof): (ShareKey, Option<Vec<u8>>),
    citations: Vec<CitationId>,
) -> CgkaOperation {
    CgkaOperation::Add {
        added_id: MemberId::from(added),
        pk,
        leaf_index: 0,
        invitation: None,
        key_proof,
        predecessors: cgka_heads(observer, doc).await,
        doc_id: TreeId::from(doc),
        citations,
    }
}

/// An update of `id`'s key with `new_path` on `doc`, on top of `observer`'s
/// heads.
async fn update_op(
    observer: &Hive,
    doc: DocumentId,
    id: IndividualId,
    new_path: Box<PathChange>,
) -> CgkaOperation {
    CgkaOperation::Update {
        id: MemberId::from(id),
        new_path,
        predecessor_secrets: Vec::new(),
        predecessors: cgka_heads(observer, doc).await,
        doc_id: TreeId::from(doc),
    }
}

/// An add of `who` on `doc`, on top of `observer`'s heads, with a fresh
/// prekey of `who`'s and the key proof for it.
async fn proven_add(
    observer: &Hive,
    doc: DocumentId,
    who: &Hive,
    citations: Vec<CitationId>,
) -> CgkaOperation {
    let (pk, proof) = proven_prekey(who).await;
    add_op(observer, doc, who.id(), (pk, Some(proof)), citations).await
}

/// A remove that lists no member, on `doc`, on top of `observer`'s heads.
async fn remove_op(observer: &Hive, doc: DocumentId, citations: Vec<CitationId>) -> CgkaOperation {
    CgkaOperation::Remove {
        removed: vec![],
        predecessors: cgka_heads(observer, doc).await,
        doc_id: TreeId::from(doc),
        citations,
    }
}

fn is_denied(result: &Result<(), ReceiveCgkaOpError<Infallible>>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(_)))
}

fn is_pending(result: &Result<(), ReceiveCgkaOpError<Infallible>>) -> bool {
    matches!(result, Err(ReceiveCgkaOpError::PendingCgkaAuthorization(_)))
}

#[tokio::test]
async fn a_signer_without_read_in_its_signing_set_is_denied() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let grant = issue_grant(&alice, carol_id, doc_id, Power::Read).await?;
    let self_granted = signed_delegation(
        &mallory,
        Delegation::new(kl(mallory.id()), kl(doc_id), Power::Admin),
    )
    .await?;
    receive(&alice, &self_granted).await;

    // Everything about the add is valid except who signed it. Mallory's grant
    // to herself is inert, since she has no authority over the document.
    let op = proven_add(&alice, doc_id, &carol, cites(&[&grant, &self_granted])).await;
    let result = alice.receive_cgka_op(mallory.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!cgka_members(&alice, doc_id).await.contains(&carol_id));
    Ok(())
}

#[tokio::test]
async fn an_add_of_someone_whose_route_grants_only_relay_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let relay_grant = issue_grant(&alice, carol_id, doc_id, Power::Relay).await?;

    // A member signs, so only the added member's standing is in question.
    let op = proven_add(&alice, doc_id, &carol, cites(&[&relay_grant])).await;
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!cgka_members(&alice, doc_id).await.contains(&carol_id));
    Ok(())
}

#[tokio::test]
async fn an_add_must_cite_the_route_to_its_member_even_when_the_receiver_has_it() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let group = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    let group_id = learn(&alice, &group).await;
    let carol_id = learn(&alice, &carol).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    let to_group = signed_delegation(
        &alice,
        Delegation::new(kl(group_id), kl(doc_id), Power::Read),
    )
    .await?;
    let carol_in_group = signed_delegation(
        &group,
        Delegation::new(kl(carol_id), kl(group_id), Power::Read),
    )
    .await?;
    receive(&alice, &to_group).await;
    receive(&alice, &carol_in_group).await;

    // Alice has both certificates, but the add cites only the first.
    let op = proven_add(&alice, doc_id, &carol, cites(&[&to_group])).await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(is_denied(&result), "{result:?}");

    let op = proven_add(&alice, doc_id, &carol, cites(&[&to_group, &carol_in_group])).await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn an_add_whose_key_its_member_did_not_publish_is_denied() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let grant = issue_grant(&alice, carol_id, doc_id, Power::Read).await?;

    let (carols_pk, carols_proof) = proven_prekey(&carol).await;
    let (_, carols_other_proof) = proven_prekey(&carol).await;
    let (alices_pk, alices_proof) = proven_prekey(&alice).await;
    let (alices_key, carols_key) = (kl(alice.id()).to_bytes(), kl(carol_id).to_bytes());
    let at = alices_proof
        .windows(alices_key.len())
        .position(|w| w == alices_key)
        .ok_or("the proof contains its issuer")?;
    let mut forged_proof = alices_proof.clone();
    forged_proof[at..at + carols_key.len()].copy_from_slice(&carols_key);
    for (case, key) in [
        ("no proof", (carols_pk, None)),
        (
            "a proof of another key",
            (carols_pk, Some(carols_other_proof)),
        ),
        ("someone else's key", (alices_pk, Some(alices_proof))),
        (
            "someone else's proof claiming her as its issuer",
            (alices_pk, Some(forged_proof)),
        ),
    ] {
        let op = add_op(&alice, doc_id, carol_id, key, cites(&[&grant])).await;
        let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
        assert!(is_denied(&result), "{case}: {result:?}");
    }

    let op = add_op(
        &alice,
        doc_id,
        carol_id,
        (carols_pk, Some(carols_proof)),
        cites(&[&grant]),
    )
    .await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_remove_that_lists_a_specific_member_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let op = CgkaOperation::Remove {
        removed: vec![RemovedMember {
            id: MemberId::from(bob.id()),
            leaf_idx: 1,
        }],
        predecessors: cgka_heads(&alice, doc_id).await,
        doc_id: TreeId::from(doc_id),
        citations: vec![],
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(cgka_members(&alice, doc_id).await.contains(&bob.id()));
    Ok(())
}

#[tokio::test]
async fn citations_must_be_strictly_ascending() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let mut grants = Vec::new();
    for _ in 0..2 {
        let reader = make_simple_keyhive().await?;
        let grant = issue_grant(&alice, reader.id(), doc_id, Power::Read).await?;
        grants.push(citation(&grant));
    }
    grants.sort_unstable();
    let (low, high) = (grants[0], grants[1]);

    for cited in [vec![high, low], vec![low, low]] {
        let op = remove_op(&alice, doc_id, cited.clone()).await;
        let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
        assert!(is_denied(&result), "{cited:?}: {result:?}");
    }
    let op = remove_op(&alice, doc_id, vec![low, high]).await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_member_can_cite_the_revocation_of_their_own_access() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    // Alice revokes Bob in Keyline only. Bob carries the revocation into the
    // key agreement himself.
    let revocation = signed_revocation(&alice, &alice, doc_id, bob.id()).await?;
    receive(&alice, &revocation).await;
    let op = remove_op(&alice, doc_id, cites(&[&revocation])).await;
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(result.is_ok(), "{result:?}");
    assert!(!cgka_members(&alice, doc_id).await.contains(&bob.id()));
    Ok(())
}

#[tokio::test]
async fn a_remove_citing_a_revocation_that_covers_nothing_removes_no_one() -> TestResult {
    // A relay can sign a revocation of any delegation. It doesn't cover anything
    // in Keyline since the relay neither signed the delegation nor is its
    // audience and has no Admin. A remove citing it will not remove anyone.
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let relay = make_simple_keyhive().await?;
    let relay_id = learn(&alice, &relay).await;
    alice.add_member(relay_id, doc_id, Power::Relay).await?;

    let inert = signed_revocation(&relay, &alice, doc_id, alice.id()).await?;
    receive(&alice, &inert).await;
    let op = remove_op(&alice, doc_id, cites(&[&inert])).await;
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(result.is_ok(), "{result:?}");
    let members = cgka_members(&alice, doc_id).await;
    assert!(members.contains(&alice.id()) && members.contains(&bob.id()));
    Ok(())
}

#[tokio::test]
async fn an_operation_citing_a_certificate_not_yet_received_waits_for_it() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let grant = signed_delegation(
        &alice,
        Delegation::new(kl(carol_id), kl(doc_id), Power::Read),
    )
    .await?;
    let op = proven_add(&alice, doc_id, &carol, cites(&[&grant])).await;
    let op = alice.try_sign(op).await?;

    let result = alice.receive_cgka_op(op.clone()).await;
    assert!(is_pending(&result), "{result:?}");

    receive(&alice, &grant).await;
    let result = alice.receive_cgka_op(op).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(cgka_members(&alice, doc_id).await.contains(&carol_id));
    Ok(())
}

#[tokio::test]
async fn an_operation_whose_predecessor_is_missing_is_pending() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let op = CgkaOperation::Update {
        id: MemberId::from(alice.id()),
        new_path: intercepted_path(&alice).await,
        predecessor_secrets: Vec::new(),
        predecessors: vec![Digest::from([9u8; 32])],
        doc_id: TreeId::from(doc_id),
    };
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_pending(&result), "{result:?}");
    Ok(())
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
async fn only_a_root_edges_audience_can_start_a_documents_history() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Admin).await?;

    // Bob cites his Admin grant, so he has standing, but no root edge points
    // to him or to a node he administers.
    let mut reissued = creators_own_add(&alice, doc_id).await.payload().clone();
    let bobs_grant = *Keyline::<Sendable>::delegations_to(alice.keyline(), kl(doc_id), kl(bob_id))
        .await?
        .value
        .keys()
        .next()
        .ok_or("bob's grant")?;
    if let CgkaOperation::Add {
        citations: cited, ..
    } = &mut reissued
    {
        cited.push(CitationId(bobs_grant.into()));
        cited.sort_unstable();
    }
    let signed = bob.try_sign(reissued).await?;
    let result = alice.receive_cgka_op(signed.clone()).await;

    assert!(is_denied(&result), "{result:?}");
    assert!(!contains_op(&alice, doc_id, &signed).await);
    Ok(())
}

/// Alice creates a group in which each of `members` has its power, and a
/// document whose root edge is to that group.
async fn doc_rooted_at_a_group(
    members: &[(&Hive, Power)],
) -> TestResult<(Hive, GroupId, DocumentId)> {
    let alice = make_simple_keyhive().await?;
    let group_id = alice.generate_group(vec![]).await?;
    for (member, power) in members {
        let id = learn(&alice, member).await;
        alice.add_member(id, group_id, *power).await?;
    }
    let doc_id = alice
        .generate_doc(vec![group_id.into()], nonempty![[0u8; 32]])
        .await?;
    Ok((alice, group_id, doc_id))
}

/// An add of `signer` with no predecessors, citing the document's root edge
/// to `group_id`, the group's own root edge and `signer`'s membership of the
/// group, as Alice has them.
async fn root_add_of(
    alice: &Hive,
    group_id: GroupId,
    doc_id: DocumentId,
    signer: &Hive,
) -> TestResult<SerdeSigned<CgkaOperation>> {
    let mut citations = vec![
        delegation_citation(alice, kl(doc_id), kl(group_id)).await?,
        delegation_citation(alice, kl(group_id), kl(alice.id())).await?,
        delegation_citation(alice, kl(group_id), kl(signer.id())).await?,
    ];
    citations.sort_unstable();
    let mut op = proven_add(alice, doc_id, signer, citations).await;
    if let CgkaOperation::Add { predecessors, .. } = &mut op {
        predecessors.clear();
    }
    Ok(signer.try_sign(op).await?)
}

#[tokio::test]
async fn a_root_op_may_be_signed_by_an_admin_of_a_root_audience_but_not_a_reader() -> TestResult {
    let dave = make_simple_keyhive().await?;
    let eve = make_simple_keyhive().await?;
    let (alice, group_id, doc_id) =
        doc_rooted_at_a_group(&[(&dave, Power::Admin), (&eve, Power::Read)]).await?;

    let by_dave = root_add_of(&alice, group_id, doc_id, &dave).await?;
    let result = alice.receive_cgka_op(by_dave).await;
    assert!(result.is_ok(), "{result:?}");
    let by_eve = root_add_of(&alice, group_id, doc_id, &eve).await?;
    let result = alice.receive_cgka_op(by_eve).await;
    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_root_add_by_a_revoked_root_admin_is_removed_when_it_merges() -> TestResult {
    let dave = make_simple_keyhive().await?;
    let (alice, group_id, doc_id) = doc_rooted_at_a_group(&[(&dave, Power::Admin)]).await?;
    let late = root_add_of(&alice, group_id, doc_id, &dave).await?;
    alice.revoke_member(dave.id(), false, group_id).await?;

    // A root op is evaluated over its own citations, so leaving out the
    // revocation lets Dave start a history after he was revoked. Merging it
    // with Alice's history, which cites the revocation, removes him.
    let result = alice.receive_cgka_op(late).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(!cgka_members(&alice, doc_id).await.contains(&dave.id()));
    Ok(())
}

#[tokio::test]
async fn an_add_through_a_group_is_still_applied_to_cgka_graph_after_member_revoked_from_group(
) -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
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
            if *added_id == MemberId::from(bob.id()))
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
async fn a_rotation_of_another_members_key_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let mut path = intercepted_path(&alice).await;
    path.leaf_id = MemberId::from(bob.id());
    let op = update_op(&alice, doc_id, bob.id(), path).await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_rotation_whose_id_differs_from_its_paths_member_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;

    let op = update_op(&alice, doc_id, alice.id(), intercepted_path(&bob).await).await;
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;

    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

/// Everything `from` would send `to`, delivered.
async fn send(from: &Hive, to: &Hive) {
    let events = from
        .static_events_for_agent(to.id())
        .await
        .expect("selects events");
    to.ingest_unsorted_static_events(events.into_values().collect())
        .await;
}

#[tokio::test]
async fn a_revoked_writer_adds_no_reader() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let carol_id = learn(&bob, &carol).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Edit).await?;
    send(&alice, &bob).await;
    let grant = issue_grant(&alice, carol_id, doc_id, Power::Read).await?;
    let revocation = signed_revocation(&alice, &alice, doc_id, bob_id).await?;
    receive(&alice, &revocation).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after")
        .await?;
    for cert in [&grant, &revocation] {
        receive(&bob, cert).await;
    }
    for op in alice.cgka_ops_for_doc(&doc_id).await.unwrap_or_default() {
        let _ = bob.receive_cgka_op(op.as_ref().clone()).await;
    }
    assert!(!cgka_members(&bob, doc_id).await.contains(&bob_id));

    // Only Bob holds Carol's prekeys, but his revocation is in the history
    // an add of her would build on, so every receiver would deny it.
    let _ = bob
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"by bob")
        .await;
    let ops = bob.cgka_ops_for_doc(&doc_id).await.unwrap_or_default();
    let carol_member = MemberId::from(carol_id);
    assert!(!ops.iter().any(
        |op| matches!(op.payload, CgkaOperation::Add { added_id, .. } if added_id == carol_member)
    ));
    Ok(())
}

#[tokio::test]
async fn a_reader_no_writer_can_add_adds_itself() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    // Alice grants Bob Read without having any of his prekeys, so no writer
    // can add him.
    issue_grant(&alice, bob.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    assert!(!cgka_members(&alice, doc_id).await.contains(&bob.id()));

    send(&alice, &bob).await;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;
    assert!(cgka_members(&alice, doc_id).await.contains(&bob.id()));

    let ct = alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"for bob")
        .await?;
    send(&alice, &bob).await;
    assert_eq!(
        bob.try_decrypt_content(doc_id, ct.encrypted_content())
            .await?,
        b"for bob".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn a_member_added_under_a_key_it_rotated_away_rotates_before_writing() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let grant = issue_grant(&alice, carol_id, doc_id, Power::Read).await?;
    // Carol published this prekey and then rotated it away, perhaps because
    // it leaked. Her key proof for it is still valid, so a member can add
    // her under it.
    let (retired, proof) = proven_prekey(&carol).await;
    carol.rotate_prekey(retired).await?;
    let add = add_op(
        &alice,
        doc_id,
        carol_id,
        (retired, Some(proof)),
        cites(&[&grant]),
    )
    .await;
    alice.receive_cgka_op(alice.try_sign(add).await?).await?;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"from alice")
        .await?;
    send(&alice, &carol).await;

    carol
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"from carol")
        .await?;

    let rotated = carol
        .cgka_ops_for_doc(&doc_id)
        .await
        .ok_or("carol holds the document")?
        .iter()
        .any(|op| {
            matches!(op.payload(), CgkaOperation::Update { id, new_path, .. }
                if *id == MemberId::from(carol_id)
                    && !new_path.leaf_pk.contains_key(&retired))
        });
    assert!(rotated, "carol still writes under the key she rotated away");
    Ok(())
}

#[tokio::test]
async fn a_reader_whose_prekeys_arrive_after_a_write_is_added_at_the_next_write() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    issue_grant(&alice, carol.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before her prekeys")
        .await?;

    learn(&alice, &carol).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after her prekeys")
        .await?;

    assert!(cgka_members(&alice, doc_id).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn an_add_of_a_reader_revoked_before_being_added_is_removed_at_the_next_write() -> TestResult
{
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let grant = issue_grant(&alice, bob.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    let revocation = signed_revocation(&alice, &alice, doc_id, bob.id()).await?;
    receive(&alice, &revocation).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after")
        .await?;

    // Bob was never added, so no remove cited the revocation. An add citing
    // only his grant is evaluated over its own certificate set, which grants
    // him Read, so it is accepted. The next write removes him.
    let op = proven_add(&alice, doc_id, &bob, cites(&[&grant])).await;
    alice.receive_cgka_op(alice.try_sign(op).await?).await?;
    assert!(cgka_members(&alice, doc_id).await.contains(&bob.id()));
    alice
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"after the add")
        .await?;
    assert!(!cgka_members(&alice, doc_id).await.contains(&bob.id()));
    Ok(())
}

#[tokio::test]
async fn an_operation_built_on_a_denied_one_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let mallory = make_simple_keyhive().await?;
    let denied = remove_op(&alice, doc_id, vec![]).await;
    let denied = mallory.try_sign(denied).await?;
    let result = alice.receive_cgka_op(denied.clone()).await;
    assert!(is_denied(&result), "{result:?}");

    let child = CgkaOperation::Remove {
        removed: vec![],
        predecessors: vec![Digest::hash(&denied)],
        doc_id: TreeId::from(doc_id),
        citations: vec![],
    };
    let result = alice.receive_cgka_op(bob.try_sign(child).await?).await;
    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

/// A remove by the document's creator with no predecessors, citing what the
/// creator's own add cites: authorized, but the CGKA accepts only an add
/// with no predecessors.
async fn a_remove_the_cgka_refuses(
    alice: &Hive,
    doc_id: DocumentId,
) -> TestResult<SerdeSigned<CgkaOperation>> {
    let op = CgkaOperation::Remove {
        removed: vec![],
        predecessors: vec![],
        doc_id: TreeId::from(doc_id),
        citations: creators_own_add(alice, doc_id)
            .await
            .payload()
            .citations()
            .to_vec(),
    };
    Ok(alice.try_sign(op).await?)
}

#[tokio::test]
async fn an_authorized_op_the_cgka_refuses_reports_the_cgka_error() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let refused = a_remove_the_cgka_refuses(&alice, doc_id).await?;
    let result = alice.receive_cgka_op(refused).await;
    assert!(
        matches!(
            result,
            Err(ReceiveCgkaOpError::CgkaError(CgkaError::InvalidOperation))
        ),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn an_operation_built_on_one_that_failed_to_merge_is_denied() -> TestResult {
    let (alice, bob, doc_id) = doc_with_alice_and_bob().await?;
    let refused = a_remove_the_cgka_refuses(&alice, doc_id).await?;
    let _ = alice.receive_cgka_op(refused.clone()).await;

    let child = CgkaOperation::Remove {
        removed: vec![],
        predecessors: vec![Digest::hash(&refused)],
        doc_id: TreeId::from(doc_id),
        citations: vec![],
    };
    let result = alice.receive_cgka_op(bob.try_sign(child).await?).await;
    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

/// Alice, her document, and Bob, who added himself to it, was removed when
/// Alice revoked his `Read`, and was then granted `Edit`.
async fn removed_and_granted_again() -> TestResult<(Hive, Hive, DocumentId)> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    issue_grant(&alice, bob.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    send(&alice, &bob).await;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;

    let revocation = signed_revocation(&alice, &alice, doc_id, bob.id()).await?;
    receive(&alice, &revocation).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"revoked")
        .await?;
    issue_grant(&alice, bob.id(), doc_id, Power::Edit).await?;
    send(&alice, &bob).await;
    assert!(!cgka_members(&bob, doc_id).await.contains(&bob.id()));
    Ok((alice, bob, doc_id))
}

#[tokio::test]
async fn a_reader_removed_and_granted_again_can_add_itself_again() -> TestResult {
    let (alice, bob, doc_id) = removed_and_granted_again().await?;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;
    let ct = alice
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"for bob again")
        .await?;
    send(&alice, &bob).await;
    assert_eq!(
        bob.try_decrypt_content(doc_id, ct.encrypted_content())
            .await?,
        b"for bob again".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn a_reader_removed_and_granted_again_adds_itself_when_it_writes() -> TestResult {
    let (_alice, bob, doc_id) = removed_and_granted_again().await?;

    bob.try_encrypt_content(doc_id, &[3u8; 32], &vec![], b"back again")
        .await?;

    assert!(cgka_members(&bob, doc_id).await.contains(&bob.id()));
    Ok(())
}

#[tokio::test]
async fn a_replica_stops_adding_once_its_add_cites_its_own_revocation() -> TestResult {
    let (alice, bob, doc) = removed_and_granted_again().await?;
    let mut readers = Vec::new();
    for _ in 0..2 {
        let reader = learn(&bob, &make_simple_keyhive().await?).await;
        receive(&bob, &issue_grant(&alice, reader, doc, Power::Read).await?).await;
        readers.push(reader);
    }
    let (edit, _) = Keyline::<Sendable>::delegations_to(bob.keyline(), kl(doc), kl(bob.id()))
        .await?
        .value
        .into_iter()
        .find(|(_, (_, delegation))| delegation.power == Power::Edit)
        .ok_or("bob's Edit grant")?;
    let revocation: Revocation<ContentHeads<[u8; 32]>> = Revocation::new(edit);
    receive(&bob, &alice.sign_certificate(&revocation).await?.into()).await;

    // Bob is not a member, so the write fails. What matters is what it
    // issues before that.
    let _ = bob
        .try_encrypt_content(doc, &[3u8; 32], &vec![], b"revoked again")
        .await;

    let mut adds = 0;
    for reader in readers {
        adds += adds_of(&bob, doc, reader).await?.len();
    }
    assert_eq!(adds, 1);
    Ok(())
}

/// A signer that signs as many payloads as it is allowed, then refuses, as a
/// remote or hardware signer can.
#[derive(Debug, Clone)]
struct RationedSigner {
    inner: MemorySigner,
    allowed: Arc<AtomicUsize>,
}

impl RationedSigner {
    fn new() -> Self {
        RationedSigner {
            inner: MemorySigner::generate(&mut OsRng),
            allowed: Arc::new(AtomicUsize::new(usize::MAX)),
        }
    }

    fn allow(&self, signatures: usize) {
        self.allowed.store(signatures, Ordering::SeqCst);
    }
}

impl Verifiable for RationedSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl AsyncSigner<Sendable> for RationedSigner {
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> <Sendable as FutureForm>::Future<'a, Result<ed25519_dalek::Signature, SigningError>> {
        let allowed = self
            .allowed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        Sendable::ready(match allowed {
            Ok(_) => self.inner.try_sign_bytes_sync(payload_bytes),
            Err(_) => Err(SigningError::SigningFailed(
                ed25519_dalek::SignatureError::new(),
            )),
        })
    }
}

#[tokio::test]
async fn a_reader_whose_remove_failed_to_sign_is_removed_at_the_next_write() -> TestResult {
    let signer = RationedSigner::new();
    let alice = Keyhive::generate(
        signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        NoListener,
        KeylineStore::new(),
        OsRng,
    )
    .await?;
    let bob = make_simple_keyhive().await?;
    let bob_id = bob.id();
    alice
        .register_individual(IndividualState::new(KeyOp::Add(
            bob.expand_prekeys().await?,
        )))
        .await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Read).await?;

    // The revocation is signed. The remove it calls for is not.
    signer.allow(1);
    alice.revoke_member(bob_id, false, doc_id).await?;
    let members = alice
        .cgka_members_for(doc_id)
        .await?
        .ok_or("alice has not joined the CGKA group")?;
    assert!(members.contains(&bob_id), "the failed remove removed bob");
    let readers = Keyline::<Sendable>::members(alice.keyline(), kl(doc_id))
        .await?
        .value;
    assert!(!readers.into_iter().any(|(id, _)| id == kl(bob_id)));

    signer.allow(usize::MAX);
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after the revocation")
        .await?;
    let members = alice
        .cgka_members_for(doc_id)
        .await?
        .ok_or("alice has not joined the CGKA group")?;
    assert!(!members.contains(&bob_id));
    Ok(())
}

#[tokio::test]
async fn an_add_contains_the_prekey_operation_that_published_its_key() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let prekey = bob.expand_prekeys().await?;
    let published = prekey.signed().as_ref().clone();
    let bob = IndividualState::new(KeyOp::Add(prekey));
    let bob_id = bob.id();
    alice.register_individual(bob).await;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc, Power::Read).await?;

    let proofs: Vec<_> = adds_of(&alice, doc, bob_id)
        .await?
        .iter()
        .filter_map(|op| match &op.payload {
            CgkaOperation::Add { key_proof, .. } => key_proof.clone(),
            _ => None,
        })
        .map(|proof| Signed::<AddKeyOp>::decode(&proof))
        .collect::<Result<_, _>>()?;
    assert_eq!(proofs, vec![published]);
    Ok(())
}

/// Alice grants Bob Read, adds him to the CGKA group and revokes him. Bob then
/// grants Read to a fresh key of his own and Alice receives that grant.
/// Returns Alice, Bob, the fresh key's keyhive, the document, Bob's grant and
/// the fresh key's grant.
async fn bob_revoked_with_a_fresh_key() -> TestResult<(
    Hive,
    Hive,
    Hive,
    DocumentId,
    VerifiedCertificate<ContentHeads<[u8; 32]>>,
    VerifiedCertificate<ContentHeads<[u8; 32]>>,
)> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let fresh = make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let grant = issue_grant(&alice, bob_id, doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    assert!(cgka_members(&alice, doc_id).await.contains(&bob_id));
    let revocation = signed_revocation(&alice, &alice, doc_id, bob_id).await?;
    receive(&alice, &revocation).await;
    let to_fresh = signed_delegation(
        &bob,
        Delegation::new(kl(fresh.id()), kl(doc_id), Power::Read),
    )
    .await?;
    receive(&alice, &to_fresh).await;
    Ok((alice, bob, fresh, doc_id, grant, to_fresh))
}

#[tokio::test]
async fn a_revoked_reader_cannot_sign_after_the_remove() -> TestResult {
    let (alice, bob, fresh, doc_id, _, _) = bob_revoked_with_a_fresh_key().await?;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after")
        .await?;
    let from_alice = issue_grant(&alice, fresh.id(), doc_id, Power::Read).await?;
    let op = proven_add(&alice, doc_id, &fresh, cites(&[&from_alice])).await;
    let result = alice.receive_cgka_op(bob.try_sign(op.clone()).await?).await;
    assert!(is_denied(&result), "{result:?}");
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn an_operation_on_a_document_the_replica_cannot_read_is_refused() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    for cert in Keyline::<Sendable>::closure(alice.keyline(), kl(doc))
        .await?
        .value
    {
        carol.receive_certificate(cert).await?;
    }
    let root = alice
        .cgka_ops_for_doc(&doc)
        .await
        .ok_or("alice holds the document")?
        .into_iter()
        .find(|op| op.payload.predecessors().is_empty())
        .ok_or("the CGKA graph has a root")?;

    let received = carol.receive_cgka_op(root.as_ref().clone()).await;
    assert!(
        matches!(received, Err(ReceiveCgkaOpError::UnknownDocument(_))),
        "{received:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_member_cannot_add_a_key_a_revoked_reader_granted_after_the_remove() -> TestResult {
    let (alice, _bob, fresh, doc_id, _, to_fresh) = bob_revoked_with_a_fresh_key().await?;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after")
        .await?;
    let op = proven_add(&alice, doc_id, &fresh, cites(&[&to_fresh])).await;
    let result = alice.receive_cgka_op(alice.try_sign(op).await?).await;
    assert!(is_denied(&result), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_key_a_revoked_reader_added_before_the_remove_is_removed_by_it() -> TestResult {
    let (alice, bob, fresh, doc_id, grant, to_fresh) = bob_revoked_with_a_fresh_key().await?;
    let op = proven_add(&alice, doc_id, &fresh, cites(&[&grant, &to_fresh])).await;
    let result = alice.receive_cgka_op(bob.try_sign(op).await?).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(cgka_members(&alice, doc_id).await.contains(&fresh.id()));
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after")
        .await?;
    let members = cgka_members(&alice, doc_id).await;
    assert!(
        !members.contains(&fresh.id()) && !members.contains(&bob.id()),
        "{members:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_replica_whose_read_was_revoked_adds_no_new_reader() -> TestResult {
    let (alice, bob, doc) = doc_with_alice_and_bob().await?;
    let dave = make_simple_keyhive().await?;
    send(&alice, &bob).await;
    let revocation = signed_revocation(&alice, &alice, doc, bob.id()).await?;
    receive(&alice, &revocation).await;
    send(&alice, &bob).await;
    learn(&alice, &dave).await;
    let dave_id = learn(&bob, &dave).await;
    let grant = issue_grant(&alice, dave_id, doc, Power::Read).await?;
    receive(&bob, &grant).await;

    // Bob removes himself first, which his signing set allows. The write then
    // fails because he is no longer a member.
    let _ = bob
        .try_encrypt_content(doc, &[1u8; 32], &vec![], b"after his revocation")
        .await;

    assert!(adds_of(&bob, doc, dave_id).await?.is_empty());
    Ok(())
}

/// Alice, who granted Carol `Read` on `doc` and wrote since, and a replica of
/// Alice rebuilt from her archive from before the grant, over a Keyline store
/// that holds the grant.
async fn restored_from_before_a_grant() -> TestResult<(Hive, Hive, Hive, DocumentId)> {
    let signer = MemorySigner::generate(&mut OsRng);
    let alice = Keyhive::generate(
        signer.clone(),
        MemoryCiphertextStore::new(),
        NoListener,
        KeylineStore::new(),
        OsRng,
    )
    .await?;
    let carol = make_simple_keyhive().await?;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let archive = alice.into_archive().await?;
    issue_grant(&alice, carol.id(), doc, Power::Read).await?;
    learn(&alice, &carol).await;
    alice
        .try_encrypt_content(doc, &[0u8; 32], &vec![], b"for carol")
        .await?;

    let store = KeylineStore::new();
    let certs = Keyline::<Sendable>::closure(alice.keyline(), kl(doc))
        .await?
        .value
        .into_iter()
        .map(|cert| cert.verify())
        .collect::<Result<_, _>>()?;
    Keyline::<Sendable>::insert(&store, certs).await?;
    let restored = Keyhive::try_from_archive(
        &archive,
        signer,
        MemoryCiphertextStore::new(),
        NoListener,
        store,
        Arc::new(futures::lock::Mutex::new(OsRng)),
    )
    .await?;
    Ok((alice, restored, carol, doc))
}

#[tokio::test]
async fn a_rebuilt_replica_merges_an_operation_citing_what_only_its_store_has() -> TestResult {
    let (alice, restored, carol, doc) = restored_from_before_a_grant().await?;
    let add_of_carol = adds_of(&alice, doc, carol.id())
        .await?
        .pop()
        .ok_or("alice added carol")?;

    restored
        .receive_cgka_op(add_of_carol.as_ref().clone())
        .await?;

    assert!(cgka_members(&restored, doc).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn a_reader_can_remove_whom_they_admitted() -> TestResult {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let doc = ctx.doc(&alice, "doc").await?;
    alice.add_member(bob.id(), doc, Power::Read).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(carol.id(), doc, Power::Read).await?;
    ctx.sync_all_unsent().await?;
    assert!(cgka_members(&alice, doc).await.contains(&carol.id()));

    bob.revoke_member(carol.id(), false, doc).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(alice.access_for_doc(carol.id(), doc).await?, None);
    assert!(
        !cgka_members(&alice, doc).await.contains(&carol.id()),
        "carol is still in alice's CGKA group after bob's remove"
    );
    Ok(())
}

#[tokio::test]
async fn a_rebuilt_replica_cites_what_only_its_store_has() -> TestResult {
    let (_alice, restored, carol, doc) = restored_from_before_a_grant().await?;
    learn(&restored, &carol).await;

    restored
        .try_encrypt_content(doc, &[1u8; 32], &vec![], b"for carol")
        .await?;

    assert!(cgka_members(&restored, doc).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn a_group_admin_can_remove_a_member_from_the_groups_documents() -> TestResult {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let dave = ctx.individual("dave").await?;
    let frank = ctx.individual("frank").await?;
    let eve = ctx.individual("eve").await?;
    let group = ctx.group(&dave, "group").await?;
    dave.add_member(frank.id(), group, Power::Admin).await?;
    // So that alice hears of the group.
    dave.add_member(alice.id(), group, Power::Read).await?;
    ctx.sync_all_unsent().await?;
    frank.add_member(eve.id(), group, Power::Read).await?;
    ctx.sync_all_unsent().await?;
    let doc = ctx.doc(&alice, "doc").await?;
    alice.add_member(group, doc, Power::Read).await?;
    ctx.sync_all_unsent().await?;
    assert!(cgka_members(&alice, doc).await.contains(&eve.id()));
    assert_eq!(
        alice.access_for_doc(dave.id(), doc).await?,
        Some(Power::Read)
    );

    dave.revoke_member(eve.id(), false, group).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(alice.access_for_doc(eve.id(), doc).await?, None);
    assert!(
        !cgka_members(&alice, doc).await.contains(&eve.id()),
        "eve is still in alice's CGKA group after dave's remove"
    );
    Ok(())
}
