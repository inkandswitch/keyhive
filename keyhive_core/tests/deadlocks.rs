use keyhive_core::{
    access::Access::Read,
    crypto::digest::Digest,
    principal::{
        document::AddMemberError,
        group::{delegation::StaticDelegation, revocation::StaticRevocation},
        public::Public,
    },
    test_utils::TestContext,
};
use std::{future::IntoFuture, time::Duration};
use testresult::TestResult;
use tokio::time::{timeout, Timeout};

fn check_deadlock<F>(future: F) -> Timeout<F::IntoFuture>
where
    F: IntoFuture,
{
    timeout(Duration::from_secs(10), future)
}

#[tokio::test]
async fn a_revocation_issued_by_public_does_not_deadlock_the_receiver() -> TestResult {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;

    let dlg = Public
        .signer()
        .try_sign_sync(StaticDelegation::<[u8; 32]> {
            can: Read,
            proof: None,
            delegate: bob.id().into(),
            after_revocations: vec![],
            after_content: Default::default(),
        })?;
    alice.receive_delegation(&dlg).await?;
    let rev = Public
        .signer()
        .try_sign_sync(StaticRevocation::<[u8; 32]> {
            revoke: Digest::hash(&dlg),
            proof: None,
            after_content: Default::default(),
        })?;

    check_deadlock(alice.receive_revocation(&rev)).await??;
    Ok(())
}

#[tokio::test]
async fn naming_the_resource_among_the_other_relevant_docs_is_refused() -> TestResult {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let result =
        check_deadlock(alice.add_member(bob.id(), design_doc, Read, &[design_doc])).await?;
    assert!(matches!(
        result,
        Err(AddMemberError::ResourceIncludedInRelevantDocs(id)) if id == design_doc
    ));
    assert_eq!(alice.access_for_doc(bob.id(), design_doc).await, None);
    Ok(())
}
