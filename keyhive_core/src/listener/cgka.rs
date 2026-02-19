//! Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.

use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use future_form::FutureForm;
use std::sync::Arc;

/// Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// The `K` parameter determines whether futures must be `Send` ([`Sendable`]) or not ([`Local`]).
///
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
pub trait CgkaListener<K: FutureForm> {
    /// React to CGKA operations.
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> K::Future<'a, ()>;
}
