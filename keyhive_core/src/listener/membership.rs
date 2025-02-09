use super::prekey::PrekeyListener;
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    principal::group::{delegation::Delegation, revocation::Revocation},
};
use std::rc::Rc;

// NOTE: we assume single-threaded async, so this can be ignored for now
#[allow(async_fn_in_trait)]
pub trait MembershipListener<S: AsyncSigner, T: ContentRef>: PrekeyListener {
    async fn on_delegation(&self, data: &Rc<Signed<Delegation<S, T, Self>>>);
    async fn on_revocation(&self, data: &Rc<Signed<Revocation<S, T, Self>>>);
}
