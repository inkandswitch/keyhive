//! Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.

use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use std::{future::Future, sync::Arc};

/// Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.
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
pub trait CgkaListener {
    #[cfg(not(feature = "sendable"))]
    fn on_cgka_op(&self, data: &Arc<Signed<CgkaOperation>>) -> impl Future<Output = ()>;

    #[cfg(feature = "sendable")]
    fn on_cgka_op(&self, data: &Arc<Signed<CgkaOperation>>) -> impl Future<Output = ()> + Send;
}
