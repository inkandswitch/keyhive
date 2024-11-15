use super::prekey::PrekeyListener;
use crate::{
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::group::operation::{delegation::Delegation, revocation::Revocation},
};
use std::rc::Rc;

// TODO make async
pub trait MembershipListener<T: ContentRef>: PrekeyListener {
    fn on_delegation(&self, data: &Rc<Signed<Delegation<T, Self>>>);
    fn on_revocation(&self, data: &Rc<Signed<Revocation<T, Self>>>);
}
