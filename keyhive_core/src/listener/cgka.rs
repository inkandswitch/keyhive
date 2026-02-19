//! Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.

use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use future_form::{FutureForm, Local};
use std::sync::Arc;

/// Trait for listening to [`Cgka`][crate::cgka::Cgka] changes.
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// The `K` type parameter controls whether futures are `Send` (`Sendable`) or not (`Local`).
/// Use `Sendable` for multi-threaded runtimes (e.g., Tokio) and `Local` for single-threaded
/// contexts (e.g., Wasm). Defaults to `Local`.
pub trait CgkaListener<K: FutureForm + ?Sized = Local> {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> K::Future<'a, ()>;
}
