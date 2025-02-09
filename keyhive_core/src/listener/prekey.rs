use crate::{
    crypto::signed::Signed,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use std::rc::Rc;

// NOTE: we assume single-threaded async, so this can be ignored for now
#[allow(async_fn_in_trait)]
pub trait PrekeyListener: Sized + Clone {
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>);
    async fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>);
}
