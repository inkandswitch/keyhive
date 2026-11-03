//! Validating a CGKA update path.

use beekem::{
    id::TreeId,
    operation::{CgkaChange, CgkaOperation},
    tree::PathChange,
};
use keyhive_core::{
    crypto::digest::Digest,
    principal::document::id::DocumentId,
    test_utils::{Instance, TestContext},
};
use keyline::power::Power::Read;
use std::collections::{BTreeSet, HashSet};
use testresult::TestResult;

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Instance, doc: DocumentId) -> BTreeSet<Digest<CgkaOperation>> {
    let ops = observer.cgka_ops_for_doc(&doc).await.unwrap();
    let referenced: HashSet<_> = ops
        .iter()
        .flat_map(|op| op.payload().predecessors())
        .collect();
    ops.iter()
        .map(|op| op.digest())
        .filter(|d| !referenced.contains(d))
        .collect()
}

/// The first update `who` produced for `doc`.
async fn an_update(who: &Instance, doc: DocumentId) -> Box<PathChange> {
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
async fn an_update_whose_path_ends_at_an_older_root_is_accepted() -> TestResult {
    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let new_path = an_update(&alice, design_doc).await;
    assert_eq!(
        new_path.path.len(),
        1,
        "written while the tree had two leaves"
    );

    // Carol's add grows the tree, so the path stops below the root, as the path
    // of any update concurrent with an add can.
    let carol = ctx.individual("carol").await?;
    alice.add_member(carol.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;
    let op = CgkaOperation {
        doc_id: TreeId::from(design_doc),
        predecessors: cgka_heads(&bob, design_doc).await,
        change: CgkaChange::Update {
            new_path,
            predecessor_secrets: Vec::new(),
        },
    };

    bob.receive_cgka_op(alice.sign_cgka_op(op).await?).await?;

    Ok(())
}
