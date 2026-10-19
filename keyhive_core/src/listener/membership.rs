//! Trait for listening to membership change events.

use super::{cgka::CgkaListener, prekey::PrekeyListener};
use crate::content::heads::ContentHeads;
use future_form::FutureForm;
use keyhive_crypto::{content::reference::ContentRef, verified::Verified};
use keyline::{delegation::Delegation, revocation::Revocation};
use std::sync::Arc;

/// Trait for listening to membership changes: the Keyline certificates a
/// replica writes or receives for the first time.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener:
/// [`NoListener`][super::no_listener::NoListener].
pub trait MembershipListener<F: FutureForm, T: ContentRef>:
    PrekeyListener<F> + CgkaListener<F>
{
    /// React to a Keyline delegation this replica signed or received for
    /// the first time.
    fn on_delegation<'a>(&'a self, data: &'a Arc<Verified<Delegation>>) -> F::Future<'a, ()>;

    /// React to a Keyline revocation this replica signed or received for
    /// the first time.
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Verified<Revocation<ContentHeads<T>>>>,
    ) -> F::Future<'a, ()>;
}
