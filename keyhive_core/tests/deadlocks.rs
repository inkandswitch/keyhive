use keyhive_core::{
    access::Access::Read,
    crypto::digest::Digest,
    principal::{
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
