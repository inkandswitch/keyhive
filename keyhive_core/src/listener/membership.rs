//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    principal::group::{delegation::Delegation, revocation::Revocation},
};
use std::sync::Arc;

/// Trait for listening to [`Group`] or [`Document`] membership change events.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// <div class="warning">
///
/// Note that we assume single-threaded async.
///
/// </div>
///
/// [`Group`]: crate::principal::group::Group
/// [`Document`]: crate::principal::document::Document
#[allow(async_fn_in_trait)]
pub trait MembershipListener<S: AsyncSigner, T: ContentRef>: PrekeyListener + CgkaListener {
    /// React to new [`Delegation`]s.
    async fn on_delegation(&self, data: &Arc<Signed<Delegation<S, T, Self>>>);

    /// React to new [`Revocation`]s.
    async fn on_revocation(&self, data: &Arc<Signed<Revocation<S, T, Self>>>);
}
