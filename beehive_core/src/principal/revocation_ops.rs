use crate::{
    cgka::operation::CgkaOperation, content::reference::ContentRef, crypto::signed::Signed,
    principal::group::operation::revocation::Revocation,
};
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationOps<T: ContentRef> {
    pub(crate) revocations: Vec<Rc<Signed<Revocation<T>>>>,
    pub(crate) cgka_operations: Vec<CgkaOperation>,
}

impl<T: ContentRef> RevocationOps<T> {
    pub fn revocations(&self) -> &[Rc<Signed<Revocation<T>>>] {
        self.revocations.as_slice()
    }

    pub fn cgka_operations(&self) -> &[CgkaOperation] {
        self.cgka_operations.as_slice()
    }
}
