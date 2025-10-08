//! Listener for changes to sharing prekeys.

use crate::{
    crypto::signed::Signed,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use std::sync::Arc;

/// Trait for listening to changes to [prekeys][crate::crypto::share_key::ShareKey].
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
pub trait PrekeyListener: Sized + Clone {
    /// React to new prekeys.
    async fn on_prekeys_expanded(&self, new_prekey: &Arc<Signed<AddKeyOp>>);

    /// React to rotated prekeys.
    async fn on_prekey_rotated(&self, rotate_key: &Arc<Signed<RotateKeyOp>>);
}
