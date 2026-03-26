//! Trait for listening to [`Cgka`](crate::cgka::Cgka) changes.

use beekem::operation::CgkaOperation;
use future_form::FutureForm;
use keyhive_crypto::signed::Signed;
use std::sync::Arc;

/// Trait for listening to [`Cgka`](crate::cgka::Cgka) changes.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener:
/// [`NoListener`][super::no_listener::NoListener].
pub trait CgkaListener<F: FutureForm> {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()>;
}
