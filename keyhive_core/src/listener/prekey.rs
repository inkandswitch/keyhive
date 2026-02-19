//! Listener for changes to sharing prekeys.

use crate::{
    crypto::signed::Signed,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use future_form::{FutureForm, Local};
use std::sync::Arc;

/// Trait for listening to changes to [prekeys][crate::crypto::share_key::ShareKey].
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener: [`NoListener`][super::no_listener::NoListener].
///
/// The `K` type parameter controls whether futures are `Send` (`Sendable`) or not (`Local`).
/// Use `Sendable` for multi-threaded runtimes (e.g., Tokio) and `Local` for single-threaded
/// contexts (e.g., Wasm). Defaults to `Local`.
pub trait PrekeyListener<K: FutureForm + ?Sized = Local>: Sized + Clone {
    /// React to new prekeys.
    fn on_prekeys_expanded<'a>(&'a self, new_prekey: &'a Arc<Signed<AddKeyOp>>) -> K::Future<'a, ()>;

    /// React to rotated prekeys.
    fn on_prekey_rotated<'a>(&'a self, rotate_key: &'a Arc<Signed<RotateKeyOp>>) -> K::Future<'a, ()>;
}
