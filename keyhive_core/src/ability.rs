use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signer::async_signer::AsyncSigner,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::Document,
};
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub struct Ability<
    'a,
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) doc: &'a Rc<RefCell<Document<S, T, L>>>,
    pub(crate) can: Access,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Ability<'_, S, T, L> {
    pub fn doc(&self) -> &Rc<RefCell<Document<S, T, L>>> {
        self.doc
    }

    pub fn can(&self) -> Access {
        self.can
    }
}
