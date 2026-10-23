//! The transient handles read what `Keyhive`'s own queries read: what an id
//! names, and who its members are.

use keyhive_codec::traits::Decode;
use keyhive_core::test_utils::{TestContext, TestResult as Result};
use keyhive_crypto::identifier::Identifier;
use keyline::power::Power::{Admin, Edit, Read};
use std::collections::{BTreeSet, HashSet};

/// The audiences of a principal's direct members.
fn audiences<D: AsRef<keyhive_crypto::verified::Signed<keyline::delegation::Delegation>>>(
    members: &[D],
) -> BTreeSet<Identifier> {
    members
        .iter()
        .map(|d| {
            keyline::delegation::Delegation::decode(d.as_ref().encoded().as_bytes())
                .expect("stored delegations decode")
                .audience
        })
        .collect()
}

#[tokio::test]
async fn a_principal_handle_tells_what_its_id_names() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), engineering, Read).await?;
    alice.add_member(engineering, design_doc, Edit).await?;

    let me = alice.get_principal(Identifier::from(alice.id()));
    assert!(me.is_active());
    assert!(me.as_individual().await.is_some());
    assert!(me.as_document().await.is_none());

    let them = alice.get_principal(Identifier::from(bob.id()));
    assert!(!them.is_active());
    assert!(them.as_individual().await.is_some());

    let doc = alice.get_principal(Identifier::from(design_doc));
    assert!(doc.as_document().await.is_some());
    assert!(doc.as_group().await?.is_none());
    assert_eq!(
        audiences(&doc.members().await?),
        BTreeSet::from([Identifier::from(alice.id()), Identifier::from(engineering)])
    );

    let group = alice.get_principal(Identifier::from(engineering));
    assert!(group.as_group().await?.is_some());
    assert!(group.as_document().await.is_none());
    assert_eq!(
        audiences(&group.members().await?),
        BTreeSet::from([Identifier::from(alice.id()), Identifier::from(bob.id())])
    );
    let transitive = group.transitive_members().await?;
    assert_eq!(transitive.get(&Identifier::from(alice.id())), Some(&Admin));
    assert_eq!(transitive.get(&Identifier::from(bob.id())), Some(&Read));
    Ok(())
}

/// An individual's handle picks the prekey that individual is seated with,
/// whether it is the active identity or someone else.
#[tokio::test]
async fn an_individual_handle_picks_its_own_prekey() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;

    for who in [&alice, &bob] {
        let picked = alice
            .get_individual(who.id())
            .await
            .ok_or("alice holds both individuals")?
            .pick_prekey(design_doc)
            .await
            .ok_or("an individual has a prekey")?;
        assert!(
            ctx.prekeys_of(&alice, who.id()).await?.contains(&picked),
            "{}'s handle picked a prekey that is not theirs",
            who.name()
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_document_handle_reads_its_members_tree_and_heads() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), engineering, Read).await?;
    alice.add_member(engineering, design_doc, Edit).await?;

    let doc = alice
        .get_document(design_doc)
        .await
        .ok_or("alice holds her document")?;
    assert_eq!(
        audiences(&doc.members().await?),
        BTreeSet::from([Identifier::from(alice.id()), Identifier::from(engineering)])
    );
    let transitive = doc.transitive_members().await?;
    assert_eq!(transitive.get(&Identifier::from(alice.id())), Some(&Admin));
    assert_eq!(transitive.get(&Identifier::from(engineering)), Some(&Edit));
    assert_eq!(transitive.get(&Identifier::from(bob.id())), Some(&Read));

    let held = alice
        .cgka_ops_for_doc(&design_doc)
        .await
        .ok_or("alice holds operations for her document")?
        .len();
    assert!(
        held > 1,
        "the document's creation and bob's seat made operations"
    );
    assert_eq!(doc.cgka_ops_count().await, Some(held));
    assert_eq!(doc.content_heads().await, Some(HashSet::from([[0u8; 32]])));
    Ok(())
}

#[tokio::test]
async fn a_group_handle_reads_its_members() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(bob.id(), engineering, Edit).await?;

    let group = alice
        .get_group(engineering)
        .await?
        .ok_or("alice holds her group")?;
    assert_eq!(
        audiences(&group.members().await?),
        BTreeSet::from([Identifier::from(alice.id()), Identifier::from(bob.id())])
    );
    let transitive = group.transitive_members().await?;
    assert_eq!(transitive.get(&Identifier::from(bob.id())), Some(&Edit));
    Ok(())
}
