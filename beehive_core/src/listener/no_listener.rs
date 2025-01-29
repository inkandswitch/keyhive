use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::derive::Debug;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

impl PrekeyListener for NoListener {
    fn on_prekeys_expanded(&self, _e: &Rc<Signed<AddKeyOp>>) {}
    fn on_prekey_rotated(&self, _e: &Rc<Signed<RotateKeyOp>>) {}
}

impl<T: ContentRef> MembershipListener<T> for NoListener {
    fn on_delegation(&self, _data: &Rc<Signed<Delegation<T, NoListener>>>) {}
    fn on_revocation(&self, _data: &Rc<Signed<Revocation<T, NoListener>>>) {}
}

impl CgkaListener for NoListener {
    fn on_cgka_op(&self, _data: &Rc<Signed<CgkaOperation>>) {}
}
