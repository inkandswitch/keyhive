//! Listener for changes to sharing prekeys.

use crate::{
    crypto::signed::Signed,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};

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
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>);

    /// React to rotated prekeys.
    async fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>);
}

#[derive(Debug, Clone, Dupe, Default)]
pub struct PrekeyLog(Rc<RefCell<Vec<KeyOp>>>);

impl PrekeyListener for PrekeyLog {
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>) {
        self.0.borrow_mut().push(new_prekey.dupe().into());
    }

    async fn on_prekey_rotated(&self, rotate_prekey: &Rc<Signed<RotateKeyOp>>) {
        self.0.borrow_mut().push(rotate_prekey.dupe().into());
    }
}
