use crate::{
    access::Access,
    content::reference::ContentRef,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::Document,
};
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub struct Ability<'a, T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) doc: &'a Rc<RefCell<Document<T, L>>>,
    pub(crate) can: Access,
}

impl<T: ContentRef, L: MembershipListener<T>> Ability<'_, T, L> {
    pub fn doc(&self) -> &Rc<RefCell<Document<T, L>>> {
        self.doc
    }

    pub fn can(&self) -> Access {
        self.can
    }
}
