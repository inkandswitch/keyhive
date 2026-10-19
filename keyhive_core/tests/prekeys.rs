//! Expanding and rotating prekeys.

use keyhive_core::test_utils::{PrekeyOp, TestContext, TestResult as Result};
use keyline::power::Power::Read;

#[tokio::test]
async fn expanding_prekeys_adds_a_distinct_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let before = ctx.prekey_ops_of(&alice, alice.id()).await?;
    let added = alice.expand_prekeys().await?.payload().share_key;
    let after = ctx.prekey_ops_of(&alice, alice.id()).await?;

    assert_eq!(after.len(), before.len() + 1, "exactly one op was recorded");
    assert!(
        !before.iter().any(|op| op.new_key() == added),
        "the key is new"
    );
    assert!(
        after.contains(&PrekeyOp::Added { new: added }),
        "and it was recorded as an addition"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_records_what_it_replaced() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    let new = alice.rotate_prekey(old).await?.payload().new;

    assert_ne!(new, old, "a rotation produces a different key");
    let ops = ctx.prekey_ops_of(&alice, alice.id()).await?;
    assert!(
        ops.contains(&PrekeyOp::Rotated { old, new }),
        "the rotation records the key it replaced and its replacement"
    );
    assert!(
        ops.contains(&PrekeyOp::Added { new: old }),
        "and the op that introduced the old key is still in the log"
    );
    Ok(())
}

#[tokio::test]
async fn a_prekey_rotation_reaches_a_peer() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    let new = alice.rotate_prekey(old).await?.payload().new;
    assert!(
        !ctx.prekey_ops_of(&bob, alice.id())
            .await?
            .contains(&PrekeyOp::Rotated { old, new }),
        "bob hasn't seen alice's rotation yet"
    );

    ctx.sync_all_unsent().await?;

    assert!(
        ctx.prekey_ops_of(&bob, alice.id())
            .await?
            .contains(&PrekeyOp::Rotated { old, new }),
        "bob sees alice's rotation"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_replaces_the_old_one() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    assert!(ctx.prekeys_of(&alice, alice.id()).await?.contains(&old));

    let new = alice.rotate_prekey(old).await?.payload().new;
    let live = ctx.prekeys_of(&alice, alice.id()).await?;

    assert!(live.contains(&new), "the replacement is live");
    assert!(!live.contains(&old), "the replaced key is not");
    Ok(())
}

#[tokio::test]
async fn a_rotated_away_intermediate_prekey_does_not_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let k1 = alice.expand_prekeys().await?.payload().share_key;
    let k2 = alice.rotate_prekey(k1).await?.payload().new;
    let k3 = alice.rotate_prekey(k2).await?.payload().new;

    let live = ctx.prekeys_of(&alice, alice.id()).await?;
    assert!(live.contains(&k3), "the last key is live");
    assert!(!live.contains(&k2), "the intermediate is not");
    assert!(!live.contains(&k1), "and neither is the original");
    Ok(())
}

#[tokio::test]
async fn two_concurrent_rotations_of_one_key_both_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_replica = ctx
        .new_keyhive_instance_for(&alice, "alice-replica")
        .await?;

    let k1 = alice.expand_prekeys().await?.payload().share_key;
    ctx.sync_all_unsent().await?;
    assert!(
        ctx.prekeys_of(&alice_replica, alice.id())
            .await?
            .contains(&k1),
        "both instances start from the same key"
    );

    // Neither rotation has heard of the other.
    let from_first = alice.rotate_prekey(k1).await?.payload().new;
    let from_replica = alice_replica.rotate_prekey(k1).await?.payload().new;
    assert_ne!(from_first, from_replica);

    ctx.sync_all_unsent().await?;

    for observer in [&alice, &alice_replica] {
        let live = ctx.prekeys_of(observer, alice.id()).await?;
        assert!(
            live.contains(&from_first) && live.contains(&from_replica),
            "{} lost one of the two concurrent replacements",
            observer.name()
        );
        assert!(
            !live.contains(&k1),
            "{} kept the key both rotations replaced",
            observer.name()
        );
    }
    Ok(())
}

/// Sixteen prekeys (seven at creation, nine more) used to pick an index one
/// past the end for about half of all documents, and panic.
#[tokio::test]
async fn a_member_with_sixteen_prekeys_can_be_added_to_any_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    for _ in 0..9 {
        bob.expand_prekeys().await?;
    }
    ctx.sync_all_unsent().await?;
    assert_eq!(ctx.prekeys_of(&alice, bob.id()).await?.len(), 16);

    for i in 0..24 {
        let doc = ctx.doc(&alice, &format!("doc-{i}")).await?;
        alice.add_member(bob.id(), doc, Read).await?;
    }
    Ok(())
}

/// Rotations that retire each other's keys leave an individual with no live
/// prekey. Adding them still delegates to them, but they are not added to the
/// CGKA tree.
#[tokio::test]
async fn a_member_with_no_live_prekeys_is_delegated_but_not_added_to_cgka_tree() -> Result<()> {
    use keyhive_core::principal::individual::op::{
        add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp,
    };
    use keyhive_crypto::{
        identifier::Identifier, share_key::ShareSecretKey, signer::memory::MemorySigner,
        verifiable::Verifiable, verified::Verified,
    };

    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = MemorySigner::generate(&mut rand::rngs::OsRng);
    let key = || ShareSecretKey::generate(&mut rand::rngs::OsRng).share_key();
    let (a, b) = (key(), key());
    for op in [
        KeyOp::Add(Verified::sign_sync(&AddKeyOp { share_key: a }, &carol)?),
        KeyOp::Rotate(Verified::sign_sync(
            &RotateKeyOp { old: a, new: b },
            &carol,
        )?),
        KeyOp::Rotate(Verified::sign_sync(
            &RotateKeyOp { old: b, new: a },
            &carol,
        )?),
    ] {
        alice.receive_prekey_op(&op).await?;
    }
    let carol_id = Identifier::try_from(carol.verifying_key())?;
    assert!(ctx.prekeys_of(&alice, carol_id.into()).await?.is_empty());

    let doc = ctx.doc(&alice, "doc").await?;
    let update = alice.add_member(carol_id, doc, Read).await?;
    assert_eq!(
        alice.access_for_doc(carol_id, doc).await?,
        Some(Read),
        "the delegation stands"
    );
    assert!(update.cgka_ops.is_empty(), "no live prekeys to add with");
    assert!(
        !alice
            .cgka_members_for(doc)
            .await?
            .expect("alice holds the tree")
            .contains(&carol_id.into()),
        "no live prekeys"
    );
    Ok(())
}
