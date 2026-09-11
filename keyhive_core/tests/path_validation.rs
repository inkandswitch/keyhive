//! Merging a `PathChange` a peer should not have sent.

use beekem::{
    id::{MemberId, TreeId},
    keys::NodeKey,
    operation::CgkaOperation,
    secret_store::SecretStore,
    tree::PathChange,
};
use keyhive_core::{
    access::Access::Read,
    crypto::digest::Digest,
    principal::{document::id::DocumentId, individual::id::IndividualId},
    test_utils::{Instance, TestContext},
};
use keyhive_crypto::{share_key::ShareKey, signed::Signed, verifiable::Verifiable};
use std::collections::BTreeMap;
use testresult::TestResult;

/// One of `who`'s own prekeys it would use to join `doc`.
async fn own_prekey(who: &Instance, doc: DocumentId) -> ShareKey {
    let indie = who.get_individual(who.id()).await.unwrap();
    let guard = indie.lock().await;
    *guard.pick_prekey(doc)
}

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Instance, doc: DocumentId) -> Vec<Digest<Signed<CgkaOperation>>> {
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

/// The individuals seated in `observer`'s tree for `doc`.
async fn seated(observer: &Instance, doc: DocumentId) -> Vec<IndividualId> {
    let doc = observer
        .get_document(doc)
        .await
        .expect("knows the document");
    let guard = doc.lock().await;
    guard
        .cgka()
        .expect("an initialized tree")
        .member_ids()
        .collect()
}

/// The first update `who` produced for `doc`.
async fn an_update(who: &Instance, doc: DocumentId) -> (MemberId, Box<PathChange>) {
    who.cgka_ops_for_doc(&doc)
        .await
        .unwrap()
        .unwrap()
        .iter()
        .find_map(|op| match op.payload() {
            CgkaOperation::Update { id, new_path, .. } => Some((*id, new_path.clone())),
            _ => None,
        })
        .expect("an update was produced")
}

/// Alice's document, with Bob reading it and one update in its history.
async fn doc_shared_with_bob(
    ctx: &mut TestContext,
) -> TestResult<(Instance, Instance, DocumentId)> {
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.encrypt(&alice, design_doc, b"warm up").await?;
    ctx.sync_all_unsent().await?;
    Ok((alice, bob, design_doc))
}

#[tokio::test]
async fn an_update_whose_path_is_not_its_direct_path_is_not_applied() -> TestResult {
    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let (id, mut new_path) = an_update(&alice, design_doc).await;

    let junk = own_prekey(&alice, design_doc).await;
    new_path.path = vec![7u32, 9]
        .into_iter()
        .map(|i| (i, SecretStore::new(junk, junk, BTreeMap::new())))
        .collect();
    let before = seated(&bob, design_doc).await;
    let op = CgkaOperation::Update {
        id,
        new_path,
        predecessors: cgka_heads(&bob, design_doc).await,
        doc_id: TreeId(design_doc.verifying_key()),
    };
    bob.receive_cgka_op(alice.try_sign(op).await?).await?;

    assert_eq!(seated(&bob, design_doc).await, before);
    Ok(())
}

#[tokio::test]
async fn an_update_that_conflicts_a_leaf_does_not_stop_the_receiver() -> TestResult {
    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let (id, mut new_path) = an_update(&alice, design_doc).await;

    new_path.leaf_pk = NodeKey::ShareKey(own_prekey(&bob, design_doc).await);
    new_path.removed_keys = vec![];
    let op = CgkaOperation::Update {
        id,
        new_path,
        predecessors: cgka_heads(&bob, design_doc).await,
        doc_id: TreeId(design_doc.verifying_key()),
    };
    bob.receive_cgka_op(alice.try_sign(op).await?).await?;

    let result = ctx.encrypt(&bob, design_doc, b"after").await;

    assert!(result.is_err(), "{result:?}");
    Ok(())
}
