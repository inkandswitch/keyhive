//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    principal::group::{delegation::Delegation, revocation::Revocation},
};
use future_form::{FutureForm, Local};
use std::sync::Arc;

/// Trait for listening to [`Group`] or [`Document`] membership change events.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// The `K` type parameter controls whether futures are `Send` (`Sendable`) or not (`Local`).
/// Use `Sendable` for multi-threaded runtimes (e.g., Tokio) and `Local` for single-threaded
/// contexts (e.g., Wasm). Defaults to `Local`.
///
/// [`Group`]: crate::principal::group::Group
/// [`Document`]: crate::principal::document::Document
pub trait MembershipListener<S: AsyncSigner, T: ContentRef, K: FutureForm + ?Sized = Local>:
    PrekeyListener<K> + CgkaListener<K> + Sized
{
    /// React to new [`Delegation`]s.
    ///
    /// The `DL` type parameter allows the delegation to carry any listener type,
    /// avoiding recursive type constraints while still accepting delegations from
    /// any context.
    fn on_delegation<'a, DL: MembershipListener<S, T>>(
        &'a self,
        data: &'a Arc<Signed<Delegation<S, T, DL>>>,
    ) -> K::Future<'a, ()>;

    /// React to new [`Revocation`]s.
    ///
    /// The `DL` type parameter allows the revocation to carry any listener type,
    /// avoiding recursive type constraints while still accepting revocations from
    /// any context.
    fn on_revocation<'a, DL: MembershipListener<S, T>>(
        &'a self,
        data: &'a Arc<Signed<Revocation<S, T, DL>>>,
    ) -> K::Future<'a, ()>;
}
