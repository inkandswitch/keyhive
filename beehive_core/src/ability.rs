use crate::{access::Access, content::reference::ContentRef, principal::document::Document};
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub struct Ability<'a, T: ContentRef> {
    pub(crate) doc: &'a Rc<RefCell<Document<T>>>,
    pub(crate) can: Access,
}

impl<T: ContentRef> Ability<'_, T> {
    pub fn doc(&self) -> &Rc<RefCell<Document<T>>> {
        self.doc
    }

    pub fn can(&self) -> Access {
        self.can
    }
}
