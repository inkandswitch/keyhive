//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::principal::group::{delegation::Delegation, revocation::Revocation};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::sync::Arc;

/// Trait for listening to [`Group`] or [`Document`] membership change events.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener:
/// [`NoListener`][super::no_listener::NoListener].
///
/// [`Group`]: crate::principal::group::Group
/// [`Document`]: crate::principal::document::Document
pub trait MembershipListener<F: FutureForm, S: AsyncSigner<F>, T: ContentRef>:
    PrekeyListener<F> + CgkaListener<F>
{
    /// React to new [`Delegation`]s.
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<F, S, T, Self>>>,
    ) -> F::Future<'a, ()>;

    /// React to new [`Revocation`]s.
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<F, S, T, Self>>>,
    ) -> F::Future<'a, ()>;
}
