use keyhive_core::{
    content::heads::ContentHeads,
    event::{static_event::StaticEvent, Event},
    principal::{identifier::Identifier, public::Public},
    test_utils::TestContext,
};
use keyhive_crypto::{id::Id, verified::Verified};
use keyline::{
    certificate::Certificate, delegation::Delegation, power::Power::Read, revocation::Revocation,
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
    alice.add_member(bob.id(), design_doc, Read).await?;

    let public = Id::try_from(Public.id())?;
    let dlg = Verified::sign_sync(
        &Delegation::new(
            public,
            Id::try_from(Identifier::from(bob.id()))?,
            Id::try_from(Identifier::from(design_doc))?,
            Read,
        ),
        &Public.signer(),
    )?;
    let rev: Verified<Revocation<ContentHeads<[u8; 32]>>> =
        Verified::sign_sync(&Revocation::new(public, dlg.digest()), &Public.signer())?;

    let event = |cert: Certificate<ContentHeads<[u8; 32]>>| StaticEvent::from(Event::from(cert));
    alice
        .receive_static_event(event(Certificate::Delegation(dlg.signed().clone())))
        .await?;
    check_deadlock(
        alice.receive_static_event(event(Certificate::Revocation(rev.signed().clone()))),
    )
    .await??;
    Ok(())
}
