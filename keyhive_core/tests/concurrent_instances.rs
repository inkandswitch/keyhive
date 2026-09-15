//! Two instances of one keyhive identity.

use beekem::{
    id::{MemberId, TreeId},
    keys::NodeKey,
    operation::CgkaOperation,
    tree::PathChange,
};
use keyhive_core::{
    access::Access::Read,
    crypto::digest::Digest,
    principal::document::id::DocumentId,
    test_utils::{Instance, TestContext, TestResult as Result},
};
use keyhive_crypto::{share_key::ShareKey, signed::Signed, verifiable::Verifiable};

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
async fn doc_shared_with_bob(ctx: &mut TestContext) -> Result<(Instance, Instance, DocumentId)> {
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.encrypt(&alice, design_doc, b"warm up").await?;
    ctx.sync_all_unsent().await?;
    Ok((alice, bob, design_doc))
}

/// The same document with a second instance of alice that holds her secrets.
async fn doc_with_a_second_instance(
    ctx: &mut TestContext,
) -> Result<(Instance, Instance, Instance, DocumentId)> {
    let (alice, bob, design_doc) = doc_shared_with_bob(ctx).await?;
    let alice_replica = ctx
        .new_keyhive_instance_for(&alice, "alice-replica")
        .await?;
    ctx.share_prekey_secrets(&alice, &alice_replica).await?;
    ctx.sync_all_unsent().await?;
    Ok((alice, alice_replica, bob, design_doc))
}

#[tokio::test]
async fn a_forged_leaf_key_still_leaves_one_key_at_the_leaf() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let (id, mut new_path) = an_update(&alice, design_doc).await;

    // A peer can put whatever it likes in a signed `PathChange`, including a key that
    // does not displace the one already at the leaf.
    new_path.leaf_pk = NodeKey::ShareKey(own_prekey(&bob, design_doc).await);
    new_path.removed_keys = vec![];
    let op = CgkaOperation::Update {
        id,
        new_path,
        predecessors: cgka_heads(&bob, design_doc).await,
        doc_id: TreeId(design_doc.verifying_key()),
    };
    let signed = alice.try_sign(op).await.map_err(|e| e.to_string())?;
    bob.receive_cgka_op(signed)
        .await
        .map_err(|e| e.to_string())?;

    // Alice's leaf comes out of the merge holding one key whatever was put in `leaf_pk`,
    // so bob still has a single key to encrypt to.
    ctx.encrypt(&bob, design_doc, b"after").await?;
    Ok(())
}

#[tokio::test]
async fn the_instance_that_lost_the_leaf_reads_again_once_it_has_the_winning_secret() -> Result<()>
{
    let mut ctx = TestContext::new().await;
    let (alice, alice_replica, bob, design_doc) = doc_with_a_second_instance(&mut ctx).await?;

    // Neither rotation has seen the other, so both land on the shared leaf and only one
    // of the two keys survives the merge.
    let (_, from_original_alice) = alice.force_pcs_update(design_doc).await?;
    let (_, from_alice_replica) = alice_replica.force_pcs_update(design_doc).await?;
    assert!(
        from_original_alice.is_some() && from_alice_replica.is_some(),
        "this test needs both instances to have rotated a key of their own"
    );

    // Bob merges both and writes, so his path encrypts to whichever key survived.
    ctx.sync(&alice, &bob).await?;
    ctx.sync(&alice_replica, &bob).await?;
    let after = ctx.encrypt(&bob, design_doc, b"after").await?;
    ctx.sync(&bob, &alice).await?;
    ctx.sync(&bob, &alice_replica).await?;

    let alice_can_decrypt = alice.try_decrypt_content(design_doc, &after).await.is_ok();
    let alice_replica_can_decrypt = alice_replica
        .try_decrypt_content(design_doc, &after)
        .await
        .is_ok();
    // The merge keeps the lower of the two keys, so the instance that sampled it is the
    // one holding the secret bob's path encrypted to.
    let (alice_key, _) = from_original_alice.expect("asserted above");
    let (replica_key, _) = from_alice_replica.expect("asserted above");
    assert_eq!(
        alice_can_decrypt,
        alice_key < replica_key,
        "whichever instance's key sorts lower is the one that can derive the root"
    );
    assert_ne!(
        alice_can_decrypt, alice_replica_can_decrypt,
        "and only one of the two can, until they exchange secrets"
    );

    // The one that lost cannot derive that key until secrets are shared and ops are
    // synced between replicas.
    ctx.share_prekey_secrets(&alice, &alice_replica).await?;
    ctx.share_prekey_secrets(&alice_replica, &alice).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        alice.try_decrypt_content(design_doc, &after).await?,
        b"after".to_vec(),
        "both instances should be able to decrypt after sharing secrets and syncing ops"
    );
    assert_eq!(
        alice_replica
            .try_decrypt_content(design_doc, &after)
            .await?,
        b"after".to_vec(),
        "both instances should be able to decrypt after sharing secrets and syncing ops"
    );
    Ok(())
}

#[tokio::test]
async fn writes_made_during_a_partition_survive_the_merge() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let (alice, alice_replica, bob, doc) = doc_with_a_second_instance(&mut ctx).await?;

    // Each instance rotates without seeing the other and writes under the key it just
    // rotated. One of those two keys is about to lose the merge.
    alice.force_pcs_update(doc).await?;
    let from_alice = ctx.encrypt(&alice, doc, b"written in the partition").await?;
    alice_replica.force_pcs_update(doc).await?;
    let from_replica = ctx
        .encrypt(&alice_replica, doc, b"also written in the partition")
        .await?;

    // Heal completely by exchanging secrets and syncing operations.
    ctx.share_prekey_secrets(&alice, &alice_replica).await?;
    ctx.share_prekey_secrets(&alice_replica, &alice).await?;
    ctx.sync_all_unsent().await?;

    for (name, who) in [("alice", &alice), ("her replica", &alice_replica), ("bob", &bob)] {
        assert_eq!(
            who.try_decrypt_content(doc, &from_alice).await?,
            b"written in the partition".to_vec(),
            "{name} reads what alice wrote during the partition"
        );
        assert_eq!(
            who.try_decrypt_content(doc, &from_replica).await?,
            b"also written in the partition".to_vec(),
            "{name} reads what her replica wrote during the partition"
        );
    }
    Ok(())
}
