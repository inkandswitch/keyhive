//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, verifiable::Verifiable},
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
/// The `K` parameter determines whether futures must be `Send` ([`Sendable`]) or not ([`Local`]).
///
/// [`Group`]: crate::principal::group::Group
/// [`Document`]: crate::principal::document::Document
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
pub trait MembershipListener<K: FutureForm, S: Verifiable, T: ContentRef>:
    PrekeyListener<K> + CgkaListener<K>
{
    /// React to new [`Delegation`]s.
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<S, T, Self>>>,
    ) -> K::Future<'a, ()>;

    /// React to new [`Revocation`]s.
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<S, T, Self>>>,
    ) -> K::Future<'a, ()>;
}
