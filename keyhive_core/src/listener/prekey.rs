//! Listener for changes to sharing prekeys.

use crate::principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use future_form::FutureForm;
use keyhive_crypto::signed::Signed;
use std::sync::Arc;

/// Trait for listening to changes to [prekeys][keyhive_crypto::share_key::ShareKey].
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener:
/// [`NoListener`][super::no_listener::NoListener].
pub trait PrekeyListener<F: FutureForm>: Sized + Clone {
    /// React to new prekeys.
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> F::Future<'a, ()>;

    /// React to rotated prekeys.
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> F::Future<'a, ()>;
}
