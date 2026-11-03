//! Two instances of one keyhive identity.

use beekem::{
    id::TreeId,
    operation::{CgkaChange, CgkaOperation},
    tree::PathChange,
};
use keyhive_core::{
    crypto::digest::Digest,
    principal::document::id::DocumentId,
    test_utils::{Instance, TestContext, TestResult as Result},
};
use keyhive_crypto::share_key::ShareKey;
use keyline::power::Power::Read;
use std::collections::{BTreeSet, HashSet};

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
        .flat_map(|op| op.payload().predecessors())
        .collect();
    ops.iter()
        .map(|op| op.digest())
        .filter(|d| !referenced.contains(d))
        .collect()
}

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
async fn doc_shared_with_bob(ctx: &mut TestContext) -> Result<(Instance, Instance, DocumentId)> {
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
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
    let mut new_path = an_update(&alice, design_doc).await;

    // A peer can put whatever it likes in a signed `PathChange`, including a key that
    // does not displace the one already at the leaf.
    new_path.leaf_pk = own_prekey(&bob, design_doc).await;
    let op = CgkaOperation {
        doc_id: TreeId::from(design_doc),
        predecessors: cgka_heads(&bob, design_doc).await,
        change: CgkaChange::Update {
            new_path,
            predecessor_secrets: Vec::new(),
        },
    };
    let signed = alice.sign_cgka_op(op).await.map_err(|e| e.to_string())?;
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
    let (_, (alice_key, _)) = alice.force_pcs_update(design_doc).await?;
    let (_, (replica_key, _)) = alice_replica.force_pcs_update(design_doc).await?;

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
        alice
            .try_decrypt_content(design_doc, &after)
            .await?
            .plaintext,
        b"after".to_vec(),
        "both instances should be able to decrypt after sharing secrets and syncing ops"
    );
    assert_eq!(
        alice_replica
            .try_decrypt_content(design_doc, &after)
            .await?
            .plaintext,
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
    let from_alice = ctx
        .encrypt(&alice, doc, b"written in the partition")
        .await?;
    alice_replica.force_pcs_update(doc).await?;
    let from_alice_replica = ctx
        .encrypt(&alice_replica, doc, b"also written in the partition")
        .await?;

    // Heal completely by exchanging secrets and syncing operations.
    ctx.share_prekey_secrets(&alice, &alice_replica).await?;
    ctx.share_prekey_secrets(&alice_replica, &alice).await?;
    ctx.sync_all_unsent().await?;

    for (name, who) in [
        ("the first", &alice),
        ("the second", &alice_replica),
        ("bob", &bob),
    ] {
        assert_eq!(
            who.try_decrypt_content(doc, &from_alice).await?.plaintext,
            b"written in the partition".to_vec(),
            "{name} reads what the first instance wrote during the partition"
        );
        assert_eq!(
            who.try_decrypt_content(doc, &from_alice_replica)
                .await?
                .plaintext,
            b"also written in the partition".to_vec(),
            "{name} reads what the second instance wrote during the partition"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_resealed_twin_of_a_covered_update_leaves_live_state_matching_a_rebuild() -> Result<()> {
    use beekem::secret_store::SecretStore;
    use keyhive_codec::traits::{Decode, Encode};

    let mut ctx = TestContext::new().await;
    let (alice, bob, design_doc) = doc_shared_with_bob(&mut ctx).await?;
    let (by_bob, _) = bob.force_pcs_update(design_doc).await?;
    ctx.sync_all_unsent().await?;

    // The same update signed again with one sealed byte changed: the same keys, a new digest.
    let mut twin = by_bob.payload().clone();
    let CgkaChange::Update { new_path, .. } = &mut twin.change else {
        unreachable!("a rotation is an update")
    };
    let bytes = new_path.path[0].1.encode().as_bytes().to_vec();
    let resealed = (0..bytes.len())
        .find_map(|i| {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1;
            let node = SecretStore::decode(&flipped).ok()?;
            (node != new_path.path[0].1 && node.node_key() == new_path.path[0].1.node_key())
                .then_some(node)
        })
        .expect("some sealed byte can change without changing the node's keys");
    new_path.path[0].1 = resealed;
    let twin = bob.sign_cgka_op(twin).await?;

    // Alice's update covers Bob's, so it removes the keys the twin also contains.
    alice.force_pcs_update(design_doc).await?;
    ctx.sync_all_unsent().await?;
    for who in [&alice, &bob] {
        who.receive_cgka_op(twin.clone())
            .await
            .map_err(|e| e.to_string())?;
    }

    let restored = ctx
        .rebuild_from_archive(&alice.into_archive().await?, "alice-restored")
        .await?;
    assert_eq!(
        alice.try_pcs_key_hash(design_doc).await,
        restored.try_pcs_key_hash(design_doc).await,
        "alice, live, is in the same state as a rebuild of her history"
    );

    alice.force_pcs_update(design_doc).await?;
    ctx.sync_all_unsent().await?;
    let key = alice.try_pcs_key_hash(design_doc).await;
    assert!(
        key.is_some(),
        "an update that has the twin in its past gives alice the root key"
    );
    assert_eq!(
        bob.try_pcs_key_hash(design_doc).await,
        key,
        "bob derives the same root key as alice"
    );
    Ok(())
}
