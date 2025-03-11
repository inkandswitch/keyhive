//! Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.

use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use std::rc::Rc;

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
#[allow(async_fn_in_trait)]
pub trait CgkaListener {
    async fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>);
}
