//! Listener for changes to sharing prekeys.

use crate::principal::{
    active::LocalPrekeySecret,
    individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use future_form::FutureForm;
use keyhive_crypto::verified::Signed;
use std::sync::Arc;

/// Trait for listening to changes to [prekeys][keyhive_crypto::share_key::ShareKey].
///
/// This can be helpful for logging, live streaming of changes, gossip, and so on.
///
/// If you don't want this feature, you can use the default listener:
/// [`NoListener`][super::no_listener::NoListener].
///
/// Each operation is passed in its signed form, already verified, so it can
/// be forwarded as received.
///
/// An operation this replica generated comes with the secret half of the key it
/// publishes, as a [`LocalPrekeySecret`]. A listener that persists operations
/// incrementally must make that secret durable before returning: the public
/// operation is observable by peers once the callback returns, and a key
/// whose secret was lost cannot open what is sealed to it. An operation
/// received from a peer has no secret here, so the argument is `None`.
pub trait PrekeyListener<F: FutureForm>: Sized + Clone {
    /// React to new prekeys.
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
        local_secret: Option<&'a LocalPrekeySecret>,
    ) -> F::Future<'a, ()>;

    /// React to rotated prekeys.
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
        local_secret: Option<&'a LocalPrekeySecret>,
    ) -> F::Future<'a, ()>;
}
