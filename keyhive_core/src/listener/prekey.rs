use crate::{
    crypto::signed::Signed,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use std::rc::Rc;

pub trait PrekeyListener: Sized + Clone {
    fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>);
    fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>);
}
