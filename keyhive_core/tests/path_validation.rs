//! Validating a CGKA update path.

use beekem::{
    id::TreeId,
    operation::{CgkaChange, CgkaOperation},
    secret_store::SecretStore,
    tree::PathChange,
};
use keyhive_core::{
    crypto::digest::Digest,
    principal::document::id::DocumentId,
    test_utils::{Instance, TestContext},
};
use keyhive_crypto::share_key::ShareKey;
use keyline::power::Power::Read;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use testresult::TestResult;

/// One of `who`'s own prekeys it would use to join `doc`.
async fn own_prekey(who: &Instance, doc: DocumentId) -> ShareKey {
    who.get_individual(who.id())
        .await
        .expect("an instance holds its own prekeys")
        .pick_prekey(doc)
        .await
        .expect("an individual has a prekey")
}

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Instance, doc: DocumentId) -> BTreeSet<Digest<CgkaOperation>> {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap();
    let referenced: HashSet<_> = ops
        .iter()
        .flat_map(|op| op.payload().predecessors.iter().copied())
        .collect();
    ops.iter()
        .map(|op| op.digest())
        .filter(|d| !referenced.contains(d))
        .collect()
}

/// The first update `who` produced for `doc`.
async fn an_update(who: &Instance, doc: DocumentId) -> PathChange {
    who.cgka_ops_for_doc(&doc)
        .await
        .unwrap()
        .iter()
        .find_map(|op| match &op.payload().change {
            CgkaChange::Update { new_path, .. } => Some(new_path.clone()),
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
    alice.add_member(bob.id(), design_doc, Read).await?;
    ctx.encrypt(&alice, design_doc, b"warm up").await?;
    ctx.sync_all_unsent().await?;
    Ok((alice, bob, design_doc))
}

#[tokio::test]
async fn an_update_whose_path_is_not_its_direct_path_is_ignored() -> TestResult {
    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let mut new_path = an_update(&alice, design_doc).await;

    let junk = own_prekey(&alice, design_doc).await;
    new_path.path = vec![7u32, 9]
        .into_iter()
        .map(|i| (i, SecretStore::new(junk, junk, BTreeMap::new())))
        .collect();
    let op = CgkaOperation {
        doc_id: TreeId::from(design_doc),
        predecessors: cgka_heads(&bob, design_doc).await,
        change: CgkaChange::Update {
            new_path,
            predecessor_secrets: Vec::new(),
        },
    };

    // We should ignore the forged path and not panic.
    let signed = alice.sign(&op).await?;
    bob.receive_cgka_op(signed.signed().as_ref().clone())
        .await?;

    Ok(())
}
