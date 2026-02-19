//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    principal::group::{delegation::Delegation, revocation::Revocation},
};
use future_form::FutureForm;
use std::sync::Arc;

/// Trait for listening to [`Group`] or [`Document`] membership change events.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// The `K` type parameter controls whether futures are `Send` (`Sendable`) or not (`Local`).
/// Use `Sendable` for multi-threaded runtimes (e.g., Tokio) and `Local` for single-threaded
/// contexts (e.g., Wasm).
///
/// [`Group`]: crate::principal::group::Group
/// [`Document`]: crate::principal::document::Document
pub trait MembershipListener<K: FutureForm + ?Sized, S: AsyncSigner, T: ContentRef>:
    PrekeyListener<K> + CgkaListener<K> + Sized
{
    /// React to new [`Delegation`]s.
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<K, S, T, Self>>>,
    ) -> K::Future<'a, ()>;

    /// React to new [`Revocation`]s.
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<K, S, T, Self>>>,
    ) -> K::Future<'a, ()>;
}
