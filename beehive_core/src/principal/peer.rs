use crate::{
    content::reference::ContentRef,
    principal::{document::Document, group::Group, individual::Individual},
};
use derive_more::From;
use std::{cell::RefCell, rc::Rc};

/// An [`Agent`] minus the current user.
#[derive(Debug, Clone, PartialEq, Eq, From)]
pub enum Peer<T: ContentRef> {
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<T>>>),
    Document(Rc<RefCell<Document<T>>>),
}
